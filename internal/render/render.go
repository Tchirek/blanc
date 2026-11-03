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
	FileSingbox        = "singbox.json"
	FileSingboxRoute   = "singbox-route.json"
	FileMihomoRules    = "mihomo.rules.yaml"
	FileMihomoProvider = "mihomo-provider.yaml"
	FileAdGuard        = "adguard.txt"
	FileHosts          = "hosts.txt"
	FileGlobalDomains  = "global-domains.txt"
	FileBlockedDomains = "blocked-domains.txt"
	FileReviewDomains  = "review-domains.txt"
	FileSummary        = "SUMMARY.md"
	FileManifest       = "manifest.json"
	FileArmPlan        = "arm-plan.json"
	FileDecisions      = "decisions.json"
)

type Options struct {
	Version     string
	Commit      string
	GeneratedAt time.Time
}

type manifest struct {
	Tool        toolInfo                  `json:"tool"`
	GeneratedAt string                    `json:"generated_at"`
	Device      audit.Device              `json:"device"`
	Inputs      inputs                    `json:"inputs"`
	Globalize   string                    `json:"globalize"`
	Stats       engine.Stats              `json:"stats"`
	Findings    []engine.Finding          `json:"findings"`
	Ignored     []engine.Ignored          `json:"ignored"`
	Quarantine  []engine.QuarantineTarget `json:"quarantine"`
	Skipped     []engine.Skipped          `json:"quarantine_skipped"`
	Files       map[string]string         `json:"files_sha256"`
	Warnings    []string                  `json:"warnings"`
}

type toolInfo struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Commit  string `json:"commit,omitempty"`
}

type inputs struct {
	ReportSHA256 string `json:"report_sha256"`
	PolicySHA256 string `json:"policy_sha256"`
	ReportSource string `json:"report_source,omitempty"`
	PolicySource string `json:"policy_source,omitempty"`
}

type armPlan struct {
	Version int              `json:"version"`
	Device  audit.Device     `json:"device"`
	Targets []armTarget      `json:"targets"`
	Skipped []engine.Skipped `json:"skipped,omitempty"`
	Notes   []string         `json:"notes"`
}

type armTarget struct {
	Package        string   `json:"package"`
	UID            string   `json:"uid"`
	System         bool     `json:"system"`
	SharedUID      string   `json:"shared_uid,omitempty"`
	Score          int      `json:"score"`
	DataTypes      []string `json:"data_types,omitempty"`
	BlockedDomains []string `json:"blocked_domains"`
	Commands       []string `json:"commands"`
	Rollback       []string `json:"rollback"`
}

type decisionsFile struct {
	Version   int                       `json:"version"`
	Decisions map[string]engine.Verdict `json:"decisions"`
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

	files[FileSingbox] = marshalJSON(sourceRuleSetFor(plan))
	files[FileSingboxRoute] = marshalJSON(singboxRoute())
	files[FileMihomoRules] = mihomoRules(plan)
	files[FileMihomoProvider] = mihomoProvider(plan)
	files[FileAdGuard] = adguard(plan)
	files[FileHosts] = hosts(plan)
	files[FileGlobalDomains] = globalDomains(plan)
	files[FileBlockedDomains] = blockedDomains(plan)
	files[FileReviewDomains] = reviewDomains(plan)
	files[FileSummary] = summary(plan, opts)
	files[FileArmPlan] = marshalJSON(buildArmPlan(plan))
	decisions := plan.Decisions
	if decisions == nil {
		decisions = map[string]engine.Verdict{}
	}
	files[FileDecisions] = marshalJSON(decisionsFile{
		Version:   1,
		Decisions: decisions,
	})

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
		},
		Globalize:  plan.Globalize,
		Stats:      plan.Stats,
		Findings:   plan.Findings,
		Ignored:    plan.Ignored,
		Quarantine: plan.Quarantine,
		Skipped:    plan.Skipped,
		Files:      fileHashes,
		Warnings:   warnings(plan),
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

func uniqueBlockedDomains(plan *engine.Plan) []string {
	set := make(map[string]struct{})
	for _, finding := range plan.Findings {
		if finding.Blocked() {
			set[finding.Domain] = struct{}{}
		}
	}
	return sortedSet(set)
}

func globalBlockedDomains(plan *engine.Plan) []string {
	set := make(map[string]struct{})
	for _, finding := range plan.Findings {
		if finding.Blocked() && finding.Global() {
			set[finding.Domain] = struct{}{}
		}
	}
	return sortedSet(set)
}

func sortedSet(set map[string]struct{}) []string {
	out := make([]string, 0, len(set))
	for value := range set {
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

func warnings(plan *engine.Plan) []string {
	out := []string{
		"NOIR and BLANC only see APK endpoints; vendor-preinstalled services, lower-level frameworks and system processes can still report data.",
		"A blocked URL is not privacy. Move to a trusted device and operating system if you need real assurance.",
	}
	if plan.Stats.GlobalDomains > 0 {
		out = append(out, "Global rules and DNS lists apply to every app; app scope is lost for those domains.")
	}
	if plan.Stats.Quarantine > 0 {
		out = append(out, "netpolicy restricts metered background traffic only; it is not a firewall.")
	}
	if plan.Stats.QuarantineSkipped > 0 {
		out = append(out, "Some quarantine candidates were skipped; see quarantine_skipped.")
	}
	return out
}

func summary(plan *engine.Plan, opts Options) []byte {
	var b strings.Builder
	fmt.Fprintf(&b, "# BLANC summary\n\n")
	fmt.Fprintf(&b, "`%s` · `%s` · %s\n\n", plan.Device.Model, plan.Device.Serial, opts.GeneratedAt.Format(time.RFC3339))
	fmt.Fprintf(&b, "> A blocked URL is not privacy. NOIR sees APK endpoints only; vendor services, lower-level frameworks and system processes are outside its view. Move to a trusted device and OS if you need real assurance.\n\n")

	fmt.Fprintf(&b, "## Numbers\n\n")
	fmt.Fprintf(&b, "| apps | findings | blocked | review | allowed | quarantine |\n")
	fmt.Fprintf(&b, "|---:|---:|---:|---:|---:|---:|\n")
	fmt.Fprintf(&b, "| %d | %d | %d | %d | %d | %d |\n\n",
		plan.Stats.Apps, plan.Stats.Findings, plan.Stats.Blocked,
		plan.Stats.Review, plan.Stats.Allowed, plan.Stats.Quarantine)

	fmt.Fprintf(&b, "## Blocked\n\n")
	fmt.Fprintf(&b, "| app | uid | domain | class | signal | data | reason | scope |\n")
	fmt.Fprintf(&b, "|---|---|---|---|---|---|---|---|\n")
	for _, finding := range plan.Findings {
		if !finding.Blocked() {
			continue
		}
		fmt.Fprintf(&b, "| `%s` | %s | `%s` | %s | %s | %s | %s | %s |\n",
			finding.Package, finding.UID, finding.Domain, finding.Class, finding.Signal,
			strings.Join(finding.DataTypes, ", "), finding.Reason, finding.Scope)
	}

	reviewed := 0
	for _, finding := range plan.Findings {
		if finding.Verdict == engine.VerdictReview && finding.Class == audit.ClassTracker {
			reviewed++
		}
	}
	if reviewed > 0 {
		fmt.Fprintf(&b, "\n## Review\n\n")
		fmt.Fprintf(&b, "| app | domain | signal | reason |\n")
		fmt.Fprintf(&b, "|---|---|---|---|\n")
		for _, finding := range plan.Findings {
			if finding.Verdict != engine.VerdictReview || finding.Class != audit.ClassTracker {
				continue
			}
			fmt.Fprintf(&b, "| `%s` | `%s` | %s | %s |\n",
				finding.Package, finding.Domain, finding.Signal, finding.Reason)
		}
	}

	if len(plan.Quarantine) > 0 {
		fmt.Fprintf(&b, "\n## Quarantine candidates\n\n")
		fmt.Fprintf(&b, "| app | uid | score | blocked domains |\n")
		fmt.Fprintf(&b, "|---|---|---:|---|\n")
		for _, target := range plan.Quarantine {
			fmt.Fprintf(&b, "| `%s` | %s | %d | %s |\n",
				target.Package, target.UID, target.Score, strings.Join(target.BlockedDomains, ", "))
		}
	}

	if len(plan.Skipped) > 0 {
		fmt.Fprintf(&b, "\n## Skipped quarantine\n\n")
		for _, skipped := range plan.Skipped {
			fmt.Fprintf(&b, "- `%s` — %s\n", skipped.Package, skipped.Reason)
		}
	}

	fmt.Fprintf(&b, "\n## Files\n\n")
	fmt.Fprintf(&b, "Rules: `singbox.json`, `mihomo.rules.yaml`, `mihomo-provider.yaml`.\n\n")
	fmt.Fprintf(&b, "DNS fallback: `adguard.txt`, `hosts.txt`, `global-domains.txt`.\n\n")
	fmt.Fprintf(&b, "Audit: `manifest.json`, `blocked-domains.txt`, `review-domains.txt`.\n\n")
	fmt.Fprintf(&b, "Reversible arm: `arm-plan.json`.\n")
	return []byte(b.String())
}

func buildArmPlan(plan *engine.Plan) armPlan {
	arm := armPlan{
		Version: 1,
		Device:  plan.Device,
		Targets: make([]armTarget, 0, len(plan.Quarantine)),
		Skipped: plan.Skipped,
		Notes: []string{
			"netpolicy restricts metered background traffic; it is not a firewall.",
			"force-stop closes the current process; the app can be reopened.",
			"appops background restriction is opt-in and may break notifications.",
			"Use blanc disarm to reverse netpolicy and appops changes.",
		},
	}
	var backgroundRestrict, appOpsBackground, forceStop bool
	if plan.Policy != nil {
		backgroundRestrict = plan.Policy.Quarantine.BackgroundRestrict
		appOpsBackground = plan.Policy.Quarantine.AppOpsBackground
		forceStop = plan.Policy.Quarantine.ForceStop
	}
	for _, target := range plan.Quarantine {
		entry := armTarget{
			Package:        target.Package,
			UID:            target.UID,
			System:         target.System,
			SharedUID:      target.SharedUID,
			Score:          target.Score,
			DataTypes:      target.DataTypes,
			BlockedDomains: target.BlockedDomains,
			Commands:       []string{},
			Rollback:       []string{},
		}
		if backgroundRestrict {
			entry.Commands = append(entry.Commands,
				fmt.Sprintf("cmd netpolicy add restrict-background-blacklist %s", target.UID))
			entry.Rollback = append(entry.Rollback,
				fmt.Sprintf("cmd netpolicy remove restrict-background-blacklist %s", target.UID))
		}
		if appOpsBackground {
			entry.Commands = append(entry.Commands,
				fmt.Sprintf("cmd appops set %s RUN_IN_BACKGROUND ignore", target.Package))
			entry.Rollback = append(entry.Rollback,
				fmt.Sprintf("cmd appops set %s RUN_IN_BACKGROUND default", target.Package))
		}
		if forceStop {
			entry.Commands = append(entry.Commands,
				fmt.Sprintf("am force-stop %s", target.Package))
		}
		arm.Targets = append(arm.Targets, entry)
	}
	return arm
}
