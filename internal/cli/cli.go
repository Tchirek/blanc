package cli

import (
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/blanc-sh/blanc/internal/audit"
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
	default:
		fmt.Fprintf(stderr, "blanc: unknown command %q\n\n", args[0])
		printHelp(stderr)
		return 2
	}
}

func printHelp(w io.Writer) {
	fmt.Fprintf(w, "BLANC\n%s\n\n", tagline)
	fmt.Fprintln(w, "白き紙")
	fmt.Fprintln(w, "闇の通信を")
	fmt.Fprintln(w, "断ち切る")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "usage:")
	fmt.Fprintln(w, "  blanc init [--out blanc.yaml] [--force]")
	fmt.Fprintln(w, "  blanc compile --report noir-out/report.json [--policy blanc.yaml] [--out blanc-out] [--decisions decisions.json]")
	fmt.Fprintln(w, "  blanc version")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "BLANC is a small companion to NOIR. NOIR finds; BLANC compiles.")
	fmt.Fprintln(w, "It does not scan, run in the background, or touch the device.")
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
	policyPath := fs.String("policy", "", "BLANC policy (built-in when omitted)")
	outPath := fs.String("out", "blanc-out", "output directory")
	decisionsPath := fs.String("decisions", "", "optional decisions.json")
	fs.Usage = func() {
		fmt.Fprintln(stderr, "usage: blanc compile --report <report.json> [--policy <blanc.yaml>] [--out <dir>] [--decisions <file>]")
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
	pol, err := policy.Load(*policyPath)
	if err != nil {
		fmt.Fprintf(stderr, "blanc compile: %v\n", err)
		return 1
	}
	decisions := map[string]engine.Verdict(nil)
	if *decisionsPath != "" {
		decisions, err = engine.LoadDecisions(*decisionsPath)
		if err != nil {
			fmt.Fprintf(stderr, "blanc compile: %v\n", err)
			return 1
		}
	}
	plan, err := engine.Compile(report, pol, engine.Options{Overrides: decisions})
	if err != nil {
		fmt.Fprintf(stderr, "blanc compile: %v\n", err)
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

	printSummary(stdout, report, pol, plan, *policyPath, *reportPath, *outPath, len(files))
	return 0
}

func printSummary(w io.Writer, report *audit.Report, pol *policy.Policy, plan *engine.Plan, policyPath, reportPath, outPath string, files int) {
	fmt.Fprintf(w, "BLANC %s\n", version.Version)
	fmt.Fprintln(w, "────────────────────────────────────────")
	fmt.Fprintf(w, "report    %s\n", reportPath)
	if policyPath == "" {
		fmt.Fprintln(w, "policy    built-in")
	} else {
		fmt.Fprintf(w, "policy    %s (%s)\n", policyPath, shortHash(pol.Hash))
	}
	fmt.Fprintf(w, "device    %s (%s)\n", report.Device.Model, report.Device.Serial)
	fmt.Fprintf(w, "apps      %d\n", plan.Stats.Apps)
	fmt.Fprintf(w, "findings  %d · blocked %d · review %d · allowed %d\n",
		plan.Stats.Findings, plan.Stats.Blocked, plan.Stats.Review, plan.Stats.Allowed)
	if blocked := uniqueBlocked(plan); len(blocked) > 0 {
		fmt.Fprintf(w, "blocked   %s\n", summarizeList(blocked, 5))
	}
	if len(plan.Quarantine) > 0 {
		fmt.Fprintf(w, "optional  %d quarantine target(s); review %s\n",
			len(plan.Quarantine), filepath.Join(outPath, render.FileQuarantineScript))
	}
	if plan.Stats.Blocked > 0 && plan.Stats.GlobalDomains == 0 {
		fmt.Fprintln(w, "dns       global lists are empty by default; set compile.globalize: trackers to fill them")
	}
	fmt.Fprintf(w, "wrote     %d files → %s\n", files, outPath)
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
		if err := os.WriteFile(path, files[name], render.Mode(name)); err != nil {
			return err
		}
	}
	return nil
}

func uniqueBlocked(plan *engine.Plan) []string {
	set := make(map[string]struct{})
	for _, finding := range plan.Findings {
		if finding.Blocked() {
			set[finding.Domain] = struct{}{}
		}
	}
	out := make([]string, 0, len(set))
	for domain := range set {
		out = append(out, domain)
	}
	sort.Strings(out)
	return out
}

func summarizeList(values []string, limit int) string {
	if len(values) <= limit {
		return strings.Join(values, ", ")
	}
	return strings.Join(values[:limit], ", ") + fmt.Sprintf(" +%d more", len(values)-limit)
}

func shortHash(hash string) string {
	if len(hash) <= 12 {
		return hash
	}
	return hash[:12]
}
