package cli

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/Tchirek/blanc/internal/audit"
	"github.com/Tchirek/blanc/internal/doctor"
	"github.com/Tchirek/blanc/internal/engine"
	"github.com/Tchirek/blanc/internal/policy"
	"github.com/Tchirek/blanc/internal/render"
	"github.com/Tchirek/blanc/internal/version"
)

const tagline = "a modern anti-telescreen tool to block telemetry and data exfiltration URLs."

func Run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		printHelp(stdout)
		return 0
	}
	switch args[0] {
	case "help", "-h", "--help":
		printHelp(stdout)
		return 0
	case "version":
		fmt.Fprintln(stdout, version.Full())
		return 0
	case "init":
		return runInit(args[1:], stdout, stderr)
	case "scan":
		return runScan(args[1:], stdout, stderr)
	case "compile":
		return runCompile(args[1:], stdout, stderr)
	case "explain":
		return runExplain(args[1:], stdout, stderr)
	case "doctor":
		return runDoctor(args[1:], stdout, stderr)
	default:
		fmt.Fprintf(stderr, "blanc: unknown command %q\n\n", args[0])
		printHelp(stderr)
		return 2
	}
}

func printHelp(w io.Writer) {
	fmt.Fprintf(w, "BLANC\n%s\n\n", tagline)
	fmt.Fprintln(w, "電波絶ち")
	fmt.Fprintln(w, "紙の白さよ")
	fmt.Fprintln(w, "冴返る")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "usage:")
	fmt.Fprintln(w, "  blanc scan    [--serial <id>] [--policy blanc.yaml] [--out blanc-out] [-- <noir scan args>]")
	fmt.Fprintln(w, "  blanc compile [--noir noir-out] [--policy blanc.yaml] [--out blanc-out]")
	fmt.Fprintln(w, "  blanc doctor  --config <mihomo config.yaml | sing-box config.json> [--out blanc-out]")
	fmt.Fprintln(w, "  blanc explain <host|url> [--app <package>] [--noir noir-out] [--policy blanc.yaml]")
	fmt.Fprintln(w, "  blanc init    [--out blanc.yaml] [--force]")
	fmt.Fprintln(w, "  blanc version")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "BLANC turns a NOIR scan into Mihomo and sing-box reject rules. Every NOIR")
	fmt.Fprintln(w, "tracker is rejected for every app; blanc.yaml adds global or per-app")
	fmt.Fprintln(w, "exceptions and extra blocks. If an app breaks, run blanc explain.")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "A blocked URL is not privacy. NOIR cannot see vendor-preinstalled services,")
	fmt.Fprintln(w, "lower-level frameworks or system processes.")
}

// 旗と名を
// 混ぜて渡せど
// 選り分ける
func parseInterleaved(fs *flag.FlagSet, args []string) ([]string, error) {
	positional := make([]string, 0)
	for {
		if err := fs.Parse(args); err != nil {
			return nil, err
		}
		rest := fs.Args()
		if len(rest) == 0 {
			return positional, nil
		}
		if rest[0] == "--" {
			return append(positional, rest[1:]...), nil
		}
		positional = append(positional, rest[0])
		args = rest[1:]
	}
}

func runInit(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("init", flag.ContinueOnError)
	fs.SetOutput(stderr)
	path := fs.String("out", "blanc.yaml", "policy path")
	force := fs.Bool("force", false, "overwrite an existing file")
	fs.Usage = func() {
		fmt.Fprintln(stderr, "usage: blanc init [--out blanc.yaml] [--force]")
	}
	if err := fs.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return 0
		}
		return 2
	}
	if *path == "" {
		fmt.Fprintln(stderr, "blanc init: --out cannot be empty")
		return 2
	}
	if !*force {
		if _, err := os.Stat(*path); err == nil {
			fmt.Fprintf(stderr, "blanc init: %s exists; use --force to overwrite\n", *path)
			return 1
		}
	}
	if err := os.WriteFile(*path, policy.DefaultYAML(), 0o644); err != nil {
		fmt.Fprintf(stderr, "blanc init: %v\n", err)
		return 1
	}
	fmt.Fprintf(stdout, "wrote %s\n\n", *path)
	fmt.Fprintln(stdout, "Every NOIR tracker is blocked for every app without any edits. Add entries only")
	fmt.Fprintln(stdout, "when something breaks or you want more blocked (entries cover subdomains):")
	fmt.Fprintln(stdout)
	fmt.Fprintln(stdout, "  allow: [umeng.com]                never block these, for any app")
	fmt.Fprintln(stdout, "  block: [api.example.cn]           block these for every app")
	fmt.Fprintln(stdout, "  apps:")
	fmt.Fprintln(stdout, "    com.example.bank: allow         exempt one app from every block")
	fmt.Fprintln(stdout, "    com.example.shop:")
	fmt.Fprintln(stdout, "      allow: [login.example.cn]     exempt hosts for one app")
	fmt.Fprintln(stdout, "      block: [ads.example.cn]       extra blocks for one app")
	fmt.Fprintln(stdout)
	fmt.Fprintln(stdout, "next: blanc compile")
	return 0
}

type inputFlags struct {
	noir    *string
	report  *string
	domains *string
	policy  *string
}

func addInputFlags(fs *flag.FlagSet) inputFlags {
	return inputFlags{
		noir:    fs.String("noir", "noir-out", "NOIR scan output directory (report.json + domains-*.txt)"),
		report:  fs.String("report", "", "NOIR report.json (default: <noir>/report.json if present)"),
		domains: fs.String("domains", "", "directory with domains-*.txt (default: <noir>, or the --report directory)"),
		policy:  fs.String("policy", "", "policy file (default: ./blanc.yaml if present, else built-in)"),
	}
}

type inputs struct {
	report     *audit.Report
	reportPath string
	domains    *audit.DomainSet
	policy     *policy.Policy
	policyPath string
}

// 帳と札
// 在るもの拾い
// 無きは告ぐ
func loadInputs(f inputFlags, offerScan bool, stdout, stderr io.Writer) (*inputs, error) {
	in := &inputs{}
	domainDir := *f.domains
	switch {
	case domainDir != "":
	case *f.report != "":
		domainDir = filepath.Dir(*f.report)
	default:
		domainDir = *f.noir
	}
	if _, err := os.Stat(domainDir); errors.Is(err, os.ErrNotExist) {
		scanned := false
		if offerScan && *f.domains == "" && *f.report == "" {
			if scanned, err = offerNoirScan(domainDir, stdout, stderr); err != nil {
				return nil, err
			}
		}
		if !scanned {
			return nil, missingNoirError(domainDir)
		}
	}

	reportPath := *f.report
	if reportPath == "" {
		candidate := filepath.Join(*f.noir, "report.json")
		if _, err := os.Stat(candidate); err == nil {
			reportPath = candidate
		}
	}
	if reportPath != "" {
		report, err := audit.Load(reportPath)
		if err != nil {
			return nil, err
		}
		if len(report.Apps) == 0 {
			return nil, fmt.Errorf("%s lists 0 apps; NOIR may have failed or its schema changed", reportPath)
		}
		in.report, in.reportPath = report, reportPath
	}

	domains, err := audit.LoadDomains(domainDir)
	if err != nil {
		return nil, err
	}
	in.domains = domains

	policyPath := *f.policy
	if policyPath == "" {
		if _, err := os.Stat("blanc.yaml"); err == nil {
			policyPath = "blanc.yaml"
		}
	}
	pol, err := policy.Load(policyPath)
	if err != nil {
		return nil, err
	}
	in.policy, in.policyPath = pol, policyPath
	return in, nil
}

func runCompile(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("compile", flag.ContinueOnError)
	fs.SetOutput(stderr)
	in := addInputFlags(fs)
	outPath := fs.String("out", "blanc-out", "output directory")
	fs.Usage = func() {
		fmt.Fprintln(stderr, "usage: blanc compile [--noir noir-out] [--policy blanc.yaml] [--out blanc-out] [--report <file>] [--domains <dir>]")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return 0
		}
		return 2
	}
	if fs.NArg() > 0 {
		fmt.Fprintf(stderr, "blanc compile: unexpected argument %q (use --noir <dir>)\n", fs.Arg(0))
		return 2
	}
	if *outPath == "" {
		fmt.Fprintln(stderr, "blanc compile: --out cannot be empty")
		return 2
	}
	return compileAndWrite(in, *outPath, stdout, stderr)
}

// 帳を読み
// 網を編みては
// 紙に置く
func compileAndWrite(in inputFlags, outPath string, stdout, stderr io.Writer) int {
	loaded, err := loadInputs(in, true, stdout, stderr)
	if err != nil {
		fmt.Fprintf(stderr, "blanc compile: %v\n", err)
		return 1
	}
	plan, err := engine.Compile(loaded.report, loaded.domains, loaded.policy)
	if err != nil {
		fmt.Fprintf(stderr, "blanc compile: %v\n", err)
		return 1
	}
	files, err := render.All(plan, render.Options{
		Version:     version.Version,
		Commit:      version.Commit,
		GeneratedAt: time.Now().UTC(),
		RuleSetPath: singboxRuleSetPath(outPath),
	})
	if err != nil {
		fmt.Fprintf(stderr, "blanc compile: %v\n", err)
		return 1
	}
	if err := writeFiles(outPath, files); err != nil {
		fmt.Fprintf(stderr, "blanc compile: %v\n", err)
		return 1
	}

	printSummary(stdout, plan, loaded, outPath)
	for _, note := range plan.Notes {
		if note.Level == engine.LevelWarn {
			fmt.Fprintf(stderr, "warning: %s: %s\n", note.Subject, note.Message)
		}
	}
	if len(plan.Rules) == 0 {
		fmt.Fprintln(stderr, "warning: no rules were emitted; the NOIR export has no tracker hosts and the policy blocks nothing")
	}
	return 0
}

func printSummary(w io.Writer, plan *engine.Plan, in *inputs, outPath string) {
	stats := plan.Stats
	fmt.Fprintf(w, "BLANC %s\n", version.Version)
	fmt.Fprintln(w, "────────────────────────────────────────")
	if plan.HasReport {
		fmt.Fprintf(w, "device    %s (%s)\n", plan.Device.Model, plan.Device.Serial)
		fmt.Fprintf(w, "report    %s · %d apps · %d endpoints\n", in.reportPath, stats.Apps, stats.Endpoints)
	} else {
		fmt.Fprintln(w, "report    none (shared-UID packages cannot be detected; evidence omitted)")
	}
	if in.policyPath == "" {
		fmt.Fprintln(w, "policy    built-in (block every NOIR tracker for every app)")
	} else {
		fmt.Fprintf(w, "policy    %s\n", in.policyPath)
	}
	fmt.Fprintf(w, "noir      %s · tracker %d · functional %d · review %d", plan.DomainsDir, stats.Trackers, stats.Functional, stats.Review)
	if stats.SkippedDomainRows > 0 {
		fmt.Fprintf(w, " · %d junk rows skipped", stats.SkippedDomainRows)
	}
	fmt.Fprintln(w)
	fmt.Fprintf(w, "rules     %d for every app · %d app-only · %d exceptions\n", stats.GlobalRules, stats.AppRules, stats.Exceptions)
	if len(plan.Notes) > 0 {
		fmt.Fprintf(w, "notes     %d (see %s)\n", len(plan.Notes), filepath.Join(outPath, render.FileSummary))
	}
	fmt.Fprintf(w, "wrote     %s\n", strings.Join(outputNames(outPath), " · "))
	fmt.Fprintf(w, "next      paste %s at the top of rules:, then blanc doctor --config <config>\n", filepath.Join(outPath, render.FileMihomo))
	fmt.Fprintln(w, "safety    a blocked URL is not privacy; NOIR cannot see vendor services, frameworks or system processes.")
}

func outputNames(outPath string) []string {
	return []string{
		filepath.Join(outPath, render.FileMihomo),
		render.FileSingbox,
		render.FileSingboxRoute,
		render.FileSummary,
		render.FileManifest,
	}
}

// 何故閉ざす
// 問えば札の名
// 指し示す
func runExplain(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("explain", flag.ContinueOnError)
	fs.SetOutput(stderr)
	in := addInputFlags(fs)
	app := fs.String("app", "", "Android package name (default: an app with no blanc.yaml entry)")
	fs.Usage = func() {
		fmt.Fprintln(stderr, "usage: blanc explain <host|url> [--app <package>] [--noir noir-out] [--policy blanc.yaml]")
		fs.PrintDefaults()
	}
	positional, err := parseInterleaved(fs, args)
	if err != nil {
		if err == flag.ErrHelp {
			return 0
		}
		return 2
	}
	if len(positional) != 1 {
		fs.Usage()
		return 2
	}
	ep, err := audit.ParseEndpoint(positional[0])
	if err != nil {
		fmt.Fprintf(stderr, "blanc explain: %q is not a hostname or URL\n", positional[0])
		return 2
	}
	if *app != "" && !audit.ValidPackage(*app) {
		fmt.Fprintf(stderr, "blanc explain: invalid package %q\n", *app)
		return 2
	}
	loaded, err := loadInputs(in, false, stdout, stderr)
	if err != nil {
		fmt.Fprintf(stderr, "blanc explain: %v\n", err)
		return 1
	}
	plan, err := engine.Compile(loaded.report, loaded.domains, loaded.policy)
	if err != nil {
		fmt.Fprintf(stderr, "blanc explain: %v\n", err)
		return 1
	}

	host := ep.Host
	decision := plan.Explain(*app, host)
	who := "any app without a blanc.yaml entry"
	if *app != "" {
		who = *app
	}
	fmt.Fprintf(stdout, "host      %s\n", host)
	fmt.Fprintf(stdout, "app       %s\n", who)
	fmt.Fprintf(stdout, "class     %s\n", decision.Class)
	fmt.Fprintf(stdout, "verdict   %s\n", decision.Verdict)
	fmt.Fprintf(stdout, "because   %s\n", decision.Reason)
	if reason, skipped := plan.Skipped[*app]; skipped {
		fmt.Fprintf(stdout, "note      apps.%s is ignored: %s\n", *app, reason)
	}
	for _, rule := range plan.Rules {
		if rule.Matches(*app, host) {
			fmt.Fprintf(stdout, "rule      %s\n", render.MihomoRule(rule))
		}
	}
	if plan.HasReport {
		if users := referencedBy(plan, host); len(users) > 0 {
			fmt.Fprintf(stdout, "seen in   %s\n", strings.Join(users, ", "))
		}
	}
	fmt.Fprintln(stdout)
	printFix(stdout, *app, host, decision)
	return 0
}

func referencedBy(plan *engine.Plan, host string) []string {
	set := make(map[string]struct{})
	for _, finding := range plan.Findings {
		if audit.Covers(host, finding.Domain) || audit.Covers(finding.Domain, host) {
			set[finding.Package] = struct{}{}
		}
	}
	out := make([]string, 0, len(set))
	for pkg := range set {
		out = append(out, pkg)
	}
	sort.Strings(out)
	return out
}

// 直す道
// 書き足す行を
// 添えて出す
func printFix(w io.Writer, app, host string, decision engine.Decision) {
	target := host
	if decision.Match != "" && decision.Tier != engine.TierApp {
		target = decision.Match
	}
	pkg := app
	if pkg == "" {
		pkg = "<package>"
	}
	if decision.Blocked() {
		fmt.Fprintln(w, "to unblock it, edit blanc.yaml and run blanc compile:")
		switch decision.Tier {
		case engine.TierApp:
			fmt.Fprintf(w, "  remove %s from apps.%s.block\n", decision.Match, pkg)
		case engine.TierGlobal:
			fmt.Fprintf(w, "  for this app only:\n    apps:\n      %s:\n        allow: [%s]\n", pkg, target)
			fmt.Fprintf(w, "  for every app: remove %s from block:\n", decision.Match)
		default:
			fmt.Fprintf(w, "  for this app only:\n    apps:\n      %s:\n        allow: [%s]\n", pkg, target)
			fmt.Fprintf(w, "  for every app:\n    allow: [%s]\n", target)
		}
		return
	}
	fmt.Fprintln(w, "to block it, edit blanc.yaml and run blanc compile:")
	switch {
	case decision.Tier == engine.TierApp && decision.Match != "":
		fmt.Fprintf(w, "  remove %s from apps.%s.allow\n", decision.Match, pkg)
	case decision.Tier == engine.TierGlobal && decision.Match == host:
		fmt.Fprintf(w, "  for this app only:\n    apps:\n      %s:\n        block: [%s]\n", pkg, host)
		fmt.Fprintf(w, "  for every app: remove %s from allow:\n", host)
	default:
		fmt.Fprintf(w, "  for this app only:\n    apps:\n      %s:\n        block: [%s]\n", pkg, host)
		fmt.Fprintf(w, "  for every app:\n    block: [%s]\n", host)
	}
	if decision.Class == audit.ClassFunctional {
		fmt.Fprintln(w, "  careful: NOIR marks this host functional (push/login/update/payment)")
	}
}

func runDoctor(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("doctor", flag.ContinueOnError)
	fs.SetOutput(stderr)
	configPath := fs.String("config", "", "Mihomo config.yaml or sing-box config.json")
	rulesPath := fs.String("rules", "", "generated rules (default: <out>/mihomo.rules.yaml or <out>/singbox.json)")
	outPath := fs.String("out", "blanc-out", "blanc compile output directory")
	fs.Usage = func() {
		fmt.Fprintln(stderr, "usage: blanc doctor --config <config.yaml|config.json> [--out blanc-out] [--rules <file>]")
	}
	positional, err := parseInterleaved(fs, args)
	if err != nil {
		if err == flag.ErrHelp {
			return 0
		}
		return 2
	}
	if *configPath == "" && len(positional) == 1 {
		*configPath = positional[0]
		positional = nil
	}
	if *configPath == "" || len(positional) > 0 {
		fs.Usage()
		return 2
	}
	report, err := doctor.Run(*configPath, *rulesPath, *outPath)
	if err != nil {
		fmt.Fprintf(stderr, "blanc doctor: %v\n", err)
		return 1
	}

	fmt.Fprintf(stdout, "BLANC doctor (%s)\n", report.Kind)
	fmt.Fprintf(stdout, "config  %s\n", report.ConfigPath)
	fmt.Fprintf(stdout, "rules   %s\n", report.RulesPath)
	for _, check := range report.Checks {
		line := ""
		if check.Line > 0 {
			line = fmt.Sprintf(" (line %d)", check.Line)
		}
		fmt.Fprintf(stdout, "%-5s  %-13s %s%s\n", check.Status, check.Name, check.Message, line)
	}
	fmt.Fprintf(stdout, "result  %d fail, %d warn\n", report.Fails(), report.Warnings())
	if report.Fails() > 0 {
		return 1
	}
	return 0
}

func singboxRuleSetPath(outPath string) string {
	cleaned := filepath.Clean(outPath)
	if cleaned == "." {
		return "./" + render.FileSingbox
	}
	joined := filepath.ToSlash(filepath.Join(cleaned, render.FileSingbox))
	if filepath.IsAbs(cleaned) {
		return joined
	}
	return "./" + joined
}

func writeFiles(outPath string, files map[string][]byte) error {
	if err := os.MkdirAll(outPath, 0o755); err != nil {
		return err
	}
	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		path := filepath.Join(outPath, name)
		if err := os.WriteFile(path, files[name], 0o644); err != nil {
			return err
		}
	}
	return nil
}
