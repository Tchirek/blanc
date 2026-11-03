package cli

import (
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/blanc-sh/blanc/internal/audit"
	"github.com/blanc-sh/blanc/internal/doctor"
	"github.com/blanc-sh/blanc/internal/engine"
	"github.com/blanc-sh/blanc/internal/policy"
	"github.com/blanc-sh/blanc/internal/render"
	"github.com/blanc-sh/blanc/internal/version"
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
	case "compile":
		return runCompile(args[1:], stdout, stderr)
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
	fmt.Fprintln(w, "  blanc init [--out blanc.yaml] [--force]")
	fmt.Fprintln(w, "  blanc compile --report noir-out/report.json [--domains noir-out] [--policy blanc.yaml] [--out blanc-out]")
	fmt.Fprintln(w, "  blanc doctor --config <mihomo.yaml> [--rules blanc-out/mihomo.rules.yaml]")
	fmt.Fprintln(w, "  blanc version")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "BLANC is the app-scoped rule compiler for NOIR.")
	fmt.Fprintln(w, "If you only need a flat DNS list, use NOIR's domains-*.txt directly.")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "A blocked URL is not privacy. NOIR cannot see vendor-preinstalled services,")
	fmt.Fprintln(w, "lower-level frameworks or system processes.")
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
	fmt.Fprintf(stdout, "wrote %s\n", *path)
	fmt.Fprintln(stdout, "next: blanc compile --report noir-out/report.json")
	return 0
}

func runCompile(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("compile", flag.ContinueOnError)
	fs.SetOutput(stderr)
	reportPath := fs.String("report", "", "NOIR report.json")
	domainsPath := fs.String("domains", "", "NOIR domain export directory (default: report directory)")
	policyPath := fs.String("policy", "", "BLANC policy (built-in when omitted)")
	outPath := fs.String("out", "blanc-out", "output directory")
	fs.Usage = func() {
		fmt.Fprintln(stderr, "usage: blanc compile --report <report.json> [--domains <dir>] [--policy <blanc.yaml>] [--out <dir>]")
	}
	if err := fs.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return 0
		}
		return 2
	}
	if *reportPath == "" {
		fs.Usage()
		return 2
	}
	if *outPath == "" {
		fmt.Fprintln(stderr, "blanc compile: --out cannot be empty")
		return 2
	}

	report, err := audit.Load(*reportPath)
	if err != nil {
		fmt.Fprintf(stderr, "blanc compile: %v\n", err)
		return 1
	}
	if len(report.Apps) == 0 {
		fmt.Fprintln(stderr, "blanc compile: report contains 0 apps; NOIR may have failed or the schema changed")
		return 1
	}
	domainDir := *domainsPath
	if domainDir == "" {
		domainDir = filepath.Dir(*reportPath)
	}
	domains, err := audit.LoadDomains(domainDir)
	if err != nil {
		fmt.Fprintf(stderr, "blanc compile: %v\n", err)
		return 1
	}
	pol, err := policy.Load(*policyPath)
	if err != nil {
		fmt.Fprintf(stderr, "blanc compile: %v\n", err)
		return 1
	}
	plan, err := engine.Compile(report, domains, pol)
	if err != nil {
		fmt.Fprintf(stderr, "blanc compile: %v\n", err)
		return 1
	}
	if plan.Stats.Endpoints == 0 {
		fmt.Fprintln(stderr, "blanc compile: report contains 0 endpoints; NOIR may have failed or the schema changed")
		return 1
	}

	files, err := render.All(plan, render.Options{
		Version:     version.Version,
		Commit:      version.Commit,
		GeneratedAt: time.Now().UTC(),
	})
	if err != nil {
		fmt.Fprintf(stderr, "blanc compile: %v\n", err)
		return 1
	}
	if err := writeFiles(*outPath, files); err != nil {
		fmt.Fprintf(stderr, "blanc compile: %v\n", err)
		return 1
	}

	printSummary(stdout, plan, domains, *policyPath, *reportPath, *outPath)
	if plan.Stats.Blocked == 0 {
		fmt.Fprintln(stderr, "blanc compile: no BLANC rules were emitted; inspect SUMMARY.md and manifest.json")
	}
	return 0
}

func runDoctor(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("doctor", flag.ContinueOnError)
	fs.SetOutput(stderr)
	configPath := fs.String("config", "", "Mihomo config.yaml")
	rulesPath := fs.String("rules", filepath.Join("blanc-out", render.FileMihomo), "generated BLANC rules")
	fs.Usage = func() {
		fmt.Fprintln(stderr, "usage: blanc doctor --config <mihomo.yaml> [--rules <mihomo.rules.yaml>]")
	}
	if err := fs.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return 0
		}
		return 2
	}
	if *configPath == "" {
		fs.Usage()
		return 2
	}
	report, err := doctor.Run(*configPath, *rulesPath)
	if err != nil {
		fmt.Fprintf(stderr, "blanc doctor: %v\n", err)
		return 1
	}

	fmt.Fprintln(stdout, "BLANC doctor")
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

func printSummary(w io.Writer, plan *engine.Plan, domains *audit.DomainSet, policyPath, reportPath, outPath string) {
	fmt.Fprintf(w, "BLANC %s\n", version.Version)
	fmt.Fprintln(w, "────────────────────────────────────────")
	fmt.Fprintf(w, "device    %s (%s)\n", plan.Device.Model, plan.Device.Serial)
	fmt.Fprintf(w, "report    %s\n", reportPath)
	if policyPath == "" {
		fmt.Fprintln(w, "policy    built-in")
	} else {
		fmt.Fprintf(w, "policy    %s\n", policyPath)
	}
	fmt.Fprintf(w, "inputs    %d apps · %d endpoints\n", plan.Stats.Apps, plan.Stats.Endpoints)
	fmt.Fprintf(w, "classify  noir · tracker %d · functional %d · review %d\n",
		domains.Count(audit.ClassTracker), domains.Count(audit.ClassFunctional), domains.Count(audit.ClassReview))
	fmt.Fprintf(w, "findings  %d · blocked %d · review %d · allowed %d\n",
		plan.Stats.Findings, plan.Stats.Blocked, plan.Stats.Review, plan.Stats.Allowed)
	if plan.Stats.Blocked > 0 {
		fmt.Fprintf(w, "rules     %s\n", filepath.Join(outPath, render.FileMihomo))
		fmt.Fprintf(w, "singbox   %s\n", filepath.Join(outPath, render.FileSingbox))
	} else {
		fmt.Fprintln(w, "rules     none")
	}
	fmt.Fprintf(w, "next      paste rules before GEOSITE,cn / MATCH; run blanc doctor --config <mihomo.yaml>\n")
	fmt.Fprintln(w, "safety    a blocked URL is not privacy; NOIR cannot see vendor services, frameworks or system processes.")
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
