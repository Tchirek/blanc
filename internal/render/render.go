package render

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/blanc-sh/blanc/internal/audit"
	"github.com/blanc-sh/blanc/internal/engine"
	"github.com/blanc-sh/blanc/internal/version"
)

const (
	FileMihomo       = "mihomo.rules.yaml"
	FileSingbox      = "singbox.json"
	FileSingboxRoute = "singbox-route.json"
	FileManifest     = "manifest.json"
	FileSummary      = "SUMMARY.md"
)

type Options struct {
	Version     string
	Commit      string
	GeneratedAt time.Time
}

type manifest struct {
	Tool                 toolInfo          `json:"tool"`
	GeneratedAt          string            `json:"generated_at"`
	Device               audit.Device      `json:"device"`
	Inputs               inputs            `json:"inputs"`
	ClassificationSource string            `json:"classification_source"`
	Stats                engine.Stats      `json:"stats"`
	Findings             []engine.Finding  `json:"findings"`
	Ignored              []engine.Ignored  `json:"ignored"`
	Files                map[string]string `json:"files_sha256"`
	Warnings             []string          `json:"warnings"`
}

type toolInfo struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Commit  string `json:"commit,omitempty"`
}

type inputs struct {
	ReportSHA256 string            `json:"report_sha256"`
	PolicySHA256 string            `json:"policy_sha256"`
	ReportSource string            `json:"report_source,omitempty"`
	PolicySource string            `json:"policy_source,omitempty"`
	ReportKeys   []string          `json:"report_keys"`
	DomainsDir   string            `json:"domains_dir"`
	DomainSHA256 map[string]string `json:"domain_sha256"`
}

// 朝の門
// ルールの束を
// 編み上げる
func All(plan *engine.Plan, opts Options) (map[string][]byte, error) {
	if plan == nil {
		return nil, fmt.Errorf("render: nil plan")
	}
	opts = withDefaults(opts)
	files := make(map[string][]byte)

	files[FileMihomo] = mihomoRules(plan)
	files[FileSingbox] = marshalJSON(sourceRuleSetFor(plan))
	files[FileSingboxRoute] = marshalJSON(singboxRoute())
	files[FileSummary] = summary(plan, opts)

	fileHashes := make(map[string]string, len(files))
	for name, data := range files {
		sum := sha256.Sum256(data)
		fileHashes[name] = hex.EncodeToString(sum[:])
	}

	m := manifest{
		Tool: toolInfo{
			Name:    "BLANC",
			Version: opts.Version,
			Commit:  opts.Commit,
		},
		GeneratedAt: opts.GeneratedAt.Format(time.RFC3339),
		Device:      plan.Device,
		Inputs: inputs{
			ReportSHA256: plan.ReportHash,
			PolicySHA256: plan.PolicyHash,
			ReportSource: plan.ReportSource,
			PolicySource: plan.PolicySource,
			ReportKeys:   plan.ReportKeys,
			DomainsDir:   plan.DomainsDir,
			DomainSHA256: plan.DomainHashes,
		},
		ClassificationSource: plan.ClassificationSource,
		Stats:                plan.Stats,
		Findings:             plan.Findings,
		Ignored:              plan.Ignored,
		Files:                fileHashes,
		Warnings:             warnings(plan),
	}
	files[FileManifest] = marshalJSON(m)
	return files, nil
}

func withDefaults(opts Options) Options {
	if opts.Version == "" {
		opts.Version = version.Version
	}
	if opts.Commit == "" {
		opts.Commit = version.Commit
	}
	if opts.GeneratedAt.IsZero() {
		opts.GeneratedAt = time.Now().UTC()
	}
	return opts
}

func marshalJSON(value any) []byte {
	raw, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		panic(err)
	}
	return append(raw, '\n')
}

func warnings(plan *engine.Plan) []string {
	out := []string{
		"A blocked URL is not privacy. NOIR sees APK endpoints only; vendor-preinstalled services, lower-level frameworks and system processes can still report data.",
		"Move to a trusted device and operating system if you need real assurance.",
		"BLANC rules only match Android apps when TUN and process matching are enabled; run blanc doctor.",
		"Place BLANC rules before GEOSITE,cn, DOMAIN-SUFFIX,cn and MATCH; the doctor checks obvious shadowing.",
		"Doctor rule-order checks are heuristic, not a proof.",
	}
	if plan.Stats.Apps == 0 {
		out = append(out, "Report contains 0 apps; NOIR may have failed or the schema changed.")
	}
	if plan.Stats.Endpoints == 0 {
		out = append(out, "Report contains 0 endpoints; NOIR may have failed or the schema changed.")
	}
	if plan.Stats.Blocked == 0 {
		out = append(out, "No BLANC rules were emitted; this may be a clean device or a classification mismatch.")
	}
	return out
}

func summary(plan *engine.Plan, opts Options) []byte {
	var b strings.Builder
	fmt.Fprintf(&b, "# BLANC\n\n")
	fmt.Fprintf(&b, "`%s` · `%s` · %s\n\n", plan.Device.Model, plan.Device.Serial, opts.GeneratedAt.Format(time.RFC3339))
	fmt.Fprintf(&b, "%d apps · %d endpoints · %d blocked · %d review · %d allowed\n\n",
		plan.Stats.Apps, plan.Stats.Endpoints, plan.Stats.Blocked, plan.Stats.Review, plan.Stats.Allowed)

	if plan.Stats.Blocked == 0 {
		fmt.Fprintf(&b, "No rules were emitted. This may be a clean device or a classification mismatch.\n\n")
	}

	fmt.Fprintf(&b, "## Blocked\n\n")
	fmt.Fprintf(&b, "| app | domain | class | data | reason |\n")
	fmt.Fprintf(&b, "|---|---|---|---|---|\n")
	for _, finding := range plan.Findings {
		if !finding.Blocked() {
			continue
		}
		fmt.Fprintf(&b, "| `%s` | `%s` | %s | %s | %s |\n",
			finding.Package, finding.Domain, finding.Class,
			dataCell(finding.DataTypes), finding.Reason)
	}

	fmt.Fprintf(&b, "\n## Review\n\n")
	fmt.Fprintf(&b, "| app | domain | class | reason |\n")
	fmt.Fprintf(&b, "|---|---|---|---|\n")
	for _, finding := range plan.Findings {
		if finding.Verdict != engine.VerdictReview {
			continue
		}
		fmt.Fprintf(&b, "| `%s` | `%s` | %s | %s |\n",
			finding.Package, finding.Domain, finding.Class, finding.Reason)
	}

	fmt.Fprintf(&b, "\n## Make it take effect\n\n")
	fmt.Fprintf(&b, "1. Paste `mihomo.rules.yaml` under `rules:` before `GEOSITE,cn`, `DOMAIN-SUFFIX,cn` and `MATCH`.\n")
	fmt.Fprintf(&b, "2. On Android, enable TUN and process matching (`find-process-mode: always`).\n")
	fmt.Fprintf(&b, "3. Run `blanc doctor --config <mihomo.yaml>`.\n")
	fmt.Fprintf(&b, "4. sing-box 1.11+: insert `singbox-route.json` into your `route` section.\n\n")

	fmt.Fprintf(&b, "> A blocked URL is not privacy. NOIR cannot see vendor-preinstalled services, lower-level frameworks or system processes. Move to a trusted device and OS if you need real assurance.\n\n")
	fmt.Fprintf(&b, "## Files\n\n")
	fmt.Fprintf(&b, "`mihomo.rules.yaml` · `singbox.json` · `singbox-route.json` · `SUMMARY.md` · `manifest.json`\n")
	return []byte(b.String())
}

func dataCell(dataTypes []string) string {
	if len(dataTypes) == 0 {
		return "—"
	}
	return strings.Join(dataTypes, ", ")
}

func sortedSet(set map[string]struct{}) []string {
	out := make([]string, 0, len(set))
	for value := range set {
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}
