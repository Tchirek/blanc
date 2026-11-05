package render

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/Tchirek/blanc/internal/audit"
	"github.com/Tchirek/blanc/internal/engine"
	"github.com/Tchirek/blanc/internal/version"
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
	RuleSetPath string
}

type Manifest struct {
	Tool        ToolInfo            `json:"tool"`
	GeneratedAt string              `json:"generated_at"`
	Device      audit.Device        `json:"device"`
	Inputs      Inputs              `json:"inputs"`
	Stats       engine.Stats        `json:"stats"`
	Rules       []ManifestRule      `json:"rules"`
	Findings    []engine.Finding    `json:"findings"`
	Skipped     map[string]string   `json:"skipped_packages,omitempty"`
	Domain      engine.DomainIssues `json:"domain_export"`
	Notes       []engine.Note       `json:"notes"`
	Files       map[string]string   `json:"files_sha256"`
}

type ManifestRule struct {
	engine.Rule
	Mihomo string `json:"mihomo"`
}

type ToolInfo struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Commit  string `json:"commit,omitempty"`
}

type Inputs struct {
	ReportSHA256 string            `json:"report_sha256,omitempty"`
	PolicySHA256 string            `json:"policy_sha256"`
	ReportSource string            `json:"report_source,omitempty"`
	PolicySource string            `json:"policy_source,omitempty"`
	ReportKeys   []string          `json:"report_keys,omitempty"`
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
	files[FileSingbox] = marshalJSON(SingboxRuleSet(plan.Rules))
	files[FileSingboxRoute] = marshalJSON(SingboxRoute(opts.RuleSetPath))
	files[FileSummary] = summary(plan, opts)

	fileHashes := make(map[string]string, len(files))
	for name, data := range files {
		sum := sha256.Sum256(data)
		fileHashes[name] = hex.EncodeToString(sum[:])
	}

	rules := make([]ManifestRule, 0, len(plan.Rules))
	for _, rule := range plan.Rules {
		rules = append(rules, ManifestRule{Rule: rule, Mihomo: MihomoRule(rule)})
	}
	findings := plan.Findings
	if findings == nil {
		findings = []engine.Finding{}
	}
	m := Manifest{
		Tool:        ToolInfo{Name: "BLANC", Version: opts.Version, Commit: opts.Commit},
		GeneratedAt: opts.GeneratedAt.Format(time.RFC3339),
		Device:      plan.Device,
		Inputs: Inputs{
			ReportSHA256: plan.ReportHash,
			PolicySHA256: plan.PolicyHash,
			ReportSource: plan.ReportSource,
			PolicySource: plan.PolicySource,
			ReportKeys:   plan.ReportKeys,
			DomainsDir:   plan.DomainsDir,
			DomainSHA256: plan.DomainHashes,
		},
		Stats:    plan.Stats,
		Rules:    rules,
		Findings: findings,
		Skipped:  plan.Skipped,
		Domain:   plan.DomainIssues,
		Notes:    plan.Notes,
		Files:    fileHashes,
	}
	if m.Notes == nil {
		m.Notes = []engine.Note{}
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
	if opts.RuleSetPath == "" {
		opts.RuleSetPath = "./blanc-out/singbox.json"
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

// 紙一枚
// 何を塞ぐか
// 書き記す
func summary(plan *engine.Plan, opts Options) []byte {
	var b strings.Builder
	s := plan.Stats
	fmt.Fprintf(&b, "# BLANC\n\n")
	if plan.HasReport {
		fmt.Fprintf(&b, "`%s` · `%s` · %s\n\n", plan.Device.Model, plan.Device.Serial, opts.GeneratedAt.Format(time.RFC3339))
	} else {
		fmt.Fprintf(&b, "no NOIR report · %s\n\n", opts.GeneratedAt.Format(time.RFC3339))
	}
	fmt.Fprintf(&b, "%d rules (%d for every app, %d app-only) · %d exceptions · NOIR: %d tracker, %d functional, %d review hosts\n\n",
		s.Rules, s.GlobalRules, s.AppRules, s.Exceptions, s.Trackers, s.Functional, s.Review)

	if len(plan.Notes) > 0 {
		fmt.Fprintf(&b, "## Notes\n\n")
		for _, note := range plan.Notes {
			fmt.Fprintf(&b, "- **%s** `%s`: %s\n", note.Level, note.Subject, note.Message)
		}
		b.WriteString("\n")
	}

	fmt.Fprintf(&b, "## Rules\n\n")
	if len(plan.Rules) == 0 {
		fmt.Fprintf(&b, "No rules. The NOIR export has no tracker hosts and the policy blocks nothing.\n\n")
	} else {
		fmt.Fprintf(&b, "| domain (+ subdomains) | apps | except | source |\n|---|---|---|---|\n")
		for _, rule := range plan.Rules {
			apps := "every app"
			if rule.Package != "" {
				apps = "`" + rule.Package + "`"
			}
			fmt.Fprintf(&b, "| `%s` | %s | %s | %s |\n", rule.Domain, apps, exceptCell(rule.Except), rule.Source)
		}
		b.WriteString("\n")
	}

	if plan.HasReport {
		writeEvidence(&b, plan)
	}

	fmt.Fprintf(&b, "## Make it take effect\n\n")
	fmt.Fprintf(&b, "Mihomo (Clash Meta for Android, FlClash, desktop):\n\n")
	fmt.Fprintf(&b, "1. Paste `mihomo.rules.yaml` at the top of `rules:`, before `GEOSITE,cn`, `DOMAIN-SUFFIX,cn`, `GEOIP` and `MATCH`.\n")
	fmt.Fprintf(&b, "2. Let the core see domain names: `sniffer: {enable: true, parse-pure-ip: true}` with TLS/HTTP/QUIC sniffing, and `dns.enhanced-mode: fake-ip`. Apps that use HTTPDNS or hard-coded IPs bypass domain rules without the sniffer.\n")
	if hasScoped(plan.Rules) {
		fmt.Fprintf(&b, "3. Some rules name apps: on Android turn on the client's VPN/TUN mode; keep `find-process-mode` at `strict` or `always`, never `off`.\n")
	}
	fmt.Fprintf(&b, "\nRun `blanc doctor --config <config.yaml>`.\n\n")
	fmt.Fprintf(&b, "sing-box 1.11+: merge `singbox-route.json` into `route`. The `reject` rule must come after a `{\"action\": \"sniff\"}` rule (keep only one sniff rule) and before any rule that routes the same traffic. Run `blanc doctor --config <config.json>`.\n\n")
	fmt.Fprintf(&b, "If an app breaks: `blanc explain <host> --app <package>` shows which entry blocks it, then add an `allow` for that app in `blanc.yaml` and compile again.\n\n")
	fmt.Fprintf(&b, "> A blocked URL is not privacy. NOIR cannot see vendor-preinstalled services, lower-level frameworks or system processes. Move to a trusted device and OS if you need real assurance.\n")
	return []byte(b.String())
}

func writeEvidence(b *strings.Builder, plan *engine.Plan) {
	blocked := make(map[string][]string)
	review := make(map[string][]string)
	for _, finding := range plan.Findings {
		switch {
		case finding.Blocked():
			blocked[finding.Domain] = append(blocked[finding.Domain], finding.Package)
		case finding.Class == audit.ClassReview:
			review[finding.Domain] = append(review[finding.Domain], finding.Package)
		}
	}
	fmt.Fprintf(b, "## Seen in scanned apps\n\n")
	fmt.Fprintf(b, "%d endpoints in %d apps · %d blocked, %d allowed host/app pairs · %d endpoints are outside the NOIR export (normal: NOIR exports upload URLs only)\n\n",
		plan.Stats.Endpoints, plan.Stats.Apps, plan.Stats.BlockedFindings, plan.Stats.AllowedFindings, plan.Stats.EndpointsOutside)
	if len(blocked) > 0 {
		fmt.Fprintf(b, "| blocked host | referenced by |\n|---|---|\n")
		for _, host := range sortedKeys(blocked) {
			fmt.Fprintf(b, "| `%s` | %s |\n", host, codeList(blocked[host]))
		}
		b.WriteString("\n")
	}
	if len(review) > 0 {
		fmt.Fprintf(b, "### Review hosts (not blocked)\n\nNOIR could not tell what these do. To block one, add it to `block:` (every app) or `apps.<package>.block:`.\n\n")
		fmt.Fprintf(b, "| host | referenced by |\n|---|---|\n")
		for _, host := range sortedKeys(review) {
			fmt.Fprintf(b, "| `%s` | %s |\n", host, codeList(review[host]))
		}
		b.WriteString("\n")
	}
}

func exceptCell(conds []engine.Cond) string {
	if len(conds) == 0 {
		return "—"
	}
	parts := make([]string, 0, len(conds))
	for _, cond := range conds {
		switch {
		case cond.Package != "" && cond.Domain != "":
			parts = append(parts, fmt.Sprintf("`%s` on `%s`", cond.Package, cond.Domain))
		case cond.Package != "":
			parts = append(parts, fmt.Sprintf("`%s`", cond.Package))
		default:
			parts = append(parts, fmt.Sprintf("`%s`", cond.Domain))
		}
	}
	return strings.Join(parts, ", ")
}

func hasScoped(rules []engine.Rule) bool {
	for _, rule := range rules {
		if rule.Scoped() {
			return true
		}
	}
	return false
}

func codeList(values []string) string {
	sort.Strings(values)
	parts := make([]string, len(values))
	for i, value := range values {
		parts[i] = "`" + value + "`"
	}
	return strings.Join(parts, ", ")
}

func sortedKeys(m map[string][]string) []string {
	out := make([]string, 0, len(m))
	for key := range m {
		out = append(out, key)
	}
	sort.Strings(out)
	return out
}
