package engine

import (
	"fmt"
	"sort"
	"strconv"

	"github.com/blanc-sh/blanc/internal/audit"
	"github.com/blanc-sh/blanc/internal/policy"
)

type Verdict string

const (
	VerdictBlock  Verdict = "block"
	VerdictReview Verdict = "review"
	VerdictAllow  Verdict = "allow"
)

type Scope string

const (
	ScopeApp    Scope = "app"
	ScopeGlobal Scope = "global"
)

type Finding struct {
	ID              string      `json:"id"`
	Package         string      `json:"package"`
	UID             string      `json:"uid"`
	System          bool        `json:"system"`
	SharedUID       string      `json:"shared_uid,omitempty"`
	Category        string      `json:"category"`
	Score           int         `json:"score"`
	DataTypes       []string    `json:"data_types,omitempty"`
	Sensitive       bool        `json:"sensitive"`
	SensitiveReason string      `json:"sensitive_reason,omitempty"`
	Domain          string      `json:"domain"`
	Class           audit.Class `json:"class"`
	Signal          string      `json:"signal"`
	Verdict         Verdict     `json:"verdict"`
	AutoVerdict     Verdict     `json:"auto_verdict"`
	Scope           Scope       `json:"scope"`
	Reason          string      `json:"reason"`
	Evidence        []string    `json:"evidence,omitempty"`
	UploadPaths     []string    `json:"upload_paths,omitempty"`
}

type Ignored struct {
	Package string `json:"package"`
	Raw     string `json:"raw"`
	Reason  string `json:"reason"`
}

type QuarantineTarget struct {
	Package        string   `json:"package"`
	UID            string   `json:"uid"`
	System         bool     `json:"system"`
	SharedUID      string   `json:"shared_uid,omitempty"`
	Score          int      `json:"score"`
	DataTypes      []string `json:"data_types,omitempty"`
	BlockedDomains []string `json:"blocked_domains"`
}

type Skipped struct {
	Package string `json:"package"`
	UID     string `json:"uid,omitempty"`
	Reason  string `json:"reason"`
}

type Stats struct {
	Apps              int `json:"apps"`
	Findings          int `json:"findings"`
	Blocked           int `json:"blocked"`
	Scoped            int `json:"scoped"`
	Global            int `json:"global"`
	Review            int `json:"review"`
	Allowed           int `json:"allowed"`
	AppsWithBlocks    int `json:"apps_with_blocks"`
	UniqueDomains     int `json:"unique_domains"`
	BlockedDomains    int `json:"blocked_domains"`
	GlobalDomains     int `json:"global_domains"`
	Ignored           int `json:"ignored"`
	Quarantine        int `json:"quarantine"`
	QuarantineSkipped int `json:"quarantine_skipped"`
}

type Plan struct {
	Device       audit.Device       `json:"device"`
	Globalize    string             `json:"globalize"`
	AppCount     int                `json:"app_count"`
	Findings     []Finding          `json:"findings"`
	Ignored      []Ignored          `json:"ignored"`
	Quarantine   []QuarantineTarget `json:"quarantine"`
	Skipped      []Skipped          `json:"quarantine_skipped"`
	Stats        Stats              `json:"stats"`
	ReportHash   string             `json:"report_hash"`
	PolicyHash   string             `json:"policy_hash"`
	ReportSource string             `json:"report_source,omitempty"`
	PolicySource string             `json:"policy_source,omitempty"`
	Decisions    map[string]Verdict `json:"-"`

	Policy *policy.Policy `json:"-"`
}

type Options struct {
	Overrides map[string]Verdict
}

type sensitivity struct {
	sensitive bool
	reason    string
}

// 暗き夜
// 見えぬ声を
// 星に数え
func Compile(report *audit.Report, pol *policy.Policy, opts Options) (*Plan, error) {
	if report == nil {
		return nil, fmt.Errorf("engine: nil report")
	}
	if pol == nil {
		return nil, fmt.Errorf("engine: nil policy")
	}

	plan := &Plan{
		Device:       report.Device,
		Globalize:    pol.Compile.Globalize,
		AppCount:     len(report.Apps),
		ReportHash:   report.Hash,
		PolicyHash:   pol.Hash,
		ReportSource: report.Source,
		PolicySource: pol.Path,
		Policy:       pol,
		Decisions:    copyDecisions(opts.Overrides),
	}

	types := stringSet(pol.Sensitive.DataTypes)
	categories := stringSet(pol.Sensitive.Categories)

	for _, app := range report.Apps {
		dataTypes := app.DataTypeSlugs()
		sensitivity := appSensitivity(app, dataTypes, types, categories)
		groups, ignored := groupEndpoints(app)
		plan.Ignored = append(plan.Ignored, ignored...)

		hosts := make([]string, 0, len(groups))
		for host := range groups {
			hosts = append(hosts, host)
		}
		sort.Strings(hosts)

		for _, host := range hosts {
			evidence := groups[host]
			classification := audit.ClassifyHost(host)
			if classification.Class == audit.ClassReview && len(evidence.uploads) > 0 {
				classification = audit.ClassifyEndpoint(audit.Endpoint{Host: host, Path: "/" + evidence.uploads[0]})
			}

			verdict, scope, reason := decide(app, host, classification, sensitivity, pol)
			if verdict == VerdictBlock && scope == ScopeApp {
				if pol.Compile.Globalize == "all" ||
					(pol.Compile.Globalize == "trackers" && classification.Class == audit.ClassTracker) {
					scope = ScopeGlobal
					reason += " (globalized)"
				}
			}

			finding := Finding{
				ID:              findingID(app.Package, host),
				Package:         app.Package,
				UID:             app.UID,
				System:          app.System,
				Category:        app.CategorySlug(),
				Score:           app.Score,
				DataTypes:       dataTypes,
				Sensitive:       sensitivity.sensitive,
				SensitiveReason: sensitivity.reason,
				Domain:          host,
				Class:           classification.Class,
				Signal:          classification.Signal,
				Verdict:         verdict,
				AutoVerdict:     verdict,
				Scope:           scope,
				Reason:          reason,
				Evidence:        evidence.urls,
				UploadPaths:     evidence.uploads,
			}
			if app.SharedUID != nil {
				finding.SharedUID = *app.SharedUID
			}

			if decision, ok := opts.Overrides[finding.ID]; ok && finding.Scope != ScopeGlobal {
				applyDecision(&finding, decision)
			}

			plan.Findings = append(plan.Findings, finding)
		}
	}

	sortFindings(plan.Findings)
	sort.Slice(plan.Ignored, func(i, j int) bool {
		if plan.Ignored[i].Package != plan.Ignored[j].Package {
			return plan.Ignored[i].Package < plan.Ignored[j].Package
		}
		return plan.Ignored[i].Raw < plan.Ignored[j].Raw
	})

	recompute(plan)
	return plan, nil
}

func (p *Plan) Find(pkg, domain string) (Finding, bool) {
	id := findingID(pkg, domain)
	for _, finding := range p.Findings {
		if finding.ID == id {
			return finding, true
		}
	}
	return Finding{}, false
}

func (f Finding) Blocked() bool {
	return f.Verdict == VerdictBlock
}

func (f Finding) Global() bool {
	return f.Scope == ScopeGlobal
}

func applyDecision(finding *Finding, verdict Verdict) {
	if finding.Scope == ScopeGlobal {
		return
	}
	finding.Verdict = verdict
	finding.Scope = ScopeApp
	finding.Reason = "manual: " + string(verdict)
}

func appSensitivity(app audit.App, dataTypes []string, types, categories map[string]struct{}) sensitivity {
	for _, dataType := range dataTypes {
		if _, ok := types[dataType]; ok {
			return sensitivity{sensitive: true, reason: "data:" + dataType}
		}
	}
	category := app.CategorySlug()
	if _, ok := categories[category]; ok {
		return sensitivity{sensitive: true, reason: "category:" + category}
	}
	return sensitivity{}
}

func decide(app audit.App, host string, classification audit.Classification, sens sensitivity, pol *policy.Policy) (Verdict, Scope, string) {
	if override, ok := pol.Domains[host]; ok {
		switch override.Action {
		case "allow":
			return VerdictAllow, ScopeApp, "domain allow override"
		case "review":
			return VerdictReview, ScopeApp, "domain review override"
		case "block":
			return VerdictBlock, ScopeGlobal, "domain block override (global)"
		}
	}

	override := pol.Apps[app.Package]
	if contains(override.Allow, host) {
		return VerdictAllow, ScopeApp, "app allowlist"
	}
	if contains(override.Block, host) {
		return VerdictBlock, ScopeApp, "app blocklist"
	}
	switch override.Mode {
	case "allow":
		return VerdictAllow, ScopeApp, "app mode allow"
	case "review":
		return VerdictReview, ScopeApp, "app mode review"
	}

	if classification.Class == audit.ClassFunctional {
		return VerdictAllow, ScopeApp, "functional endpoint"
	}
	if override.Mode == "block" && classification.Class == audit.ClassTracker {
		return VerdictBlock, ScopeApp, "app mode block"
	}
	if !pol.Compile.IncludeSystem && app.System {
		return VerdictReview, ScopeApp, "system app excluded"
	}
	if app.Score < pol.Sensitive.MinScore {
		return VerdictReview, ScopeApp, "score below min_score"
	}

	if classification.Class == audit.ClassTracker {
		if !pol.Sensitive.Require {
			return VerdictBlock, ScopeApp, "tracker (sensitivity gate disabled)"
		}
		if sens.sensitive {
			return VerdictBlock, ScopeApp, "tracker + " + sens.reason
		}
		return VerdictReview, ScopeApp, "tracker without sensitive signal"
	}
	return VerdictReview, ScopeApp, "unclassified endpoint"
}

type evidence struct {
	urls    []string
	uploads []string
}

func groupEndpoints(app audit.App) (map[string]*evidence, []Ignored) {
	groups := make(map[string]*evidence)
	ignored := make([]Ignored, 0)
	seenIgnored := make(map[string]struct{})

	for _, raw := range app.Endpoints {
		ep, err := audit.ParseEndpoint(raw)
		if err != nil {
			if _, ok := seenIgnored[raw]; ok {
				continue
			}
			seenIgnored[raw] = struct{}{}
			ignored = append(ignored, Ignored{Package: app.Package, Raw: raw, Reason: err.Error()})
			continue
		}
		group, ok := groups[ep.Host]
		if !ok {
			group = &evidence{}
			groups[ep.Host] = group
		}
		if len(group.urls) < 6 && !contains(group.urls, raw) {
			group.urls = append(group.urls, raw)
		}
		if segment, ok := audit.UploadPath(ep.Path); ok && !contains(group.uploads, segment) {
			group.uploads = append(group.uploads, segment)
		}
	}
	return groups, ignored
}

// 眠る影
// ゆれる窓辺に
// 鍵をかけ
func recompute(plan *Plan) {
	stats := Stats{Apps: plan.AppCount}
	uniqueDomains := make(map[string]struct{})
	blockedDomains := make(map[string]struct{})
	globalDomains := make(map[string]struct{})
	appsWithBlocks := make(map[string]struct{})
	blockedByApp := make(map[string]map[string]struct{})
	meta := make(map[string]Finding)

	for _, finding := range plan.Findings {
		stats.Findings++
		uniqueDomains[finding.Domain] = struct{}{}
		switch finding.Verdict {
		case VerdictBlock:
			stats.Blocked++
			blockedDomains[finding.Domain] = struct{}{}
			appsWithBlocks[finding.Package] = struct{}{}
			if finding.Scope == ScopeGlobal {
				stats.Global++
				globalDomains[finding.Domain] = struct{}{}
			} else {
				stats.Scoped++
			}
			domains, ok := blockedByApp[finding.Package]
			if !ok {
				domains = make(map[string]struct{})
				blockedByApp[finding.Package] = domains
			}
			domains[finding.Domain] = struct{}{}
		case VerdictReview:
			stats.Review++
		case VerdictAllow:
			stats.Allowed++
		}
		if _, ok := meta[finding.Package]; !ok {
			meta[finding.Package] = finding
		}
	}

	stats.UniqueDomains = len(uniqueDomains)
	stats.BlockedDomains = len(blockedDomains)
	stats.GlobalDomains = len(globalDomains)
	stats.AppsWithBlocks = len(appsWithBlocks)
	stats.Ignored = len(plan.Ignored)

	plan.Quarantine = nil
	plan.Skipped = nil
	if plan.Policy != nil && quarantineEnabled(plan.Policy) {
		q := plan.Policy.Quarantine
		for pkg, domains := range blockedByApp {
			finding := meta[pkg]
			if len(domains) < q.MinBlockedDomains {
				continue
			}
			if plan.Policy.Apps[pkg].Mode == "allow" {
				plan.Skipped = append(plan.Skipped, Skipped{Package: pkg, UID: finding.UID, Reason: "app mode allow"})
				continue
			}
			if finding.System && !q.IncludeSystem {
				plan.Skipped = append(plan.Skipped, Skipped{Package: pkg, UID: finding.UID, Reason: "system app"})
				continue
			}
			if finding.SharedUID != "" && !q.IncludeSharedUID {
				plan.Skipped = append(plan.Skipped, Skipped{Package: pkg, UID: finding.UID, Reason: "shared UID"})
				continue
			}
			uid, err := strconv.Atoi(finding.UID)
			if err != nil || uid < 10000 {
				plan.Skipped = append(plan.Skipped, Skipped{Package: pkg, UID: finding.UID, Reason: "uid not eligible for netpolicy"})
				continue
			}
			plan.Quarantine = append(plan.Quarantine, QuarantineTarget{
				Package:        pkg,
				UID:            finding.UID,
				System:         finding.System,
				SharedUID:      finding.SharedUID,
				Score:          finding.Score,
				DataTypes:      finding.DataTypes,
				BlockedDomains: sortedKeys(domains),
			})
		}
	}
	sort.Slice(plan.Quarantine, func(i, j int) bool {
		if plan.Quarantine[i].Score != plan.Quarantine[j].Score {
			return plan.Quarantine[i].Score > plan.Quarantine[j].Score
		}
		return plan.Quarantine[i].Package < plan.Quarantine[j].Package
	})
	sort.Slice(plan.Skipped, func(i, j int) bool {
		return plan.Skipped[i].Package < plan.Skipped[j].Package
	})
	stats.Quarantine = len(plan.Quarantine)
	stats.QuarantineSkipped = len(plan.Skipped)
	plan.Stats = stats
}

func quarantineEnabled(p *policy.Policy) bool {
	q := p.Quarantine
	return q.BackgroundRestrict || q.AppOpsBackground || q.ForceStop
}

func findingID(pkg, domain string) string {
	return pkg + "|" + domain
}

func sortFindings(findings []Finding) {
	sort.Slice(findings, func(i, j int) bool {
		if findings[i].Package != findings[j].Package {
			return findings[i].Package < findings[j].Package
		}
		return findings[i].Domain < findings[j].Domain
	})
}

func stringSet(values []string) map[string]struct{} {
	set := make(map[string]struct{}, len(values))
	for _, value := range values {
		set[value] = struct{}{}
	}
	return set
}

func contains(values []string, value string) bool {
	for _, candidate := range values {
		if candidate == value {
			return true
		}
	}
	return false
}

func sortedKeys(set map[string]struct{}) []string {
	out := make([]string, 0, len(set))
	for key := range set {
		out = append(out, key)
	}
	sort.Strings(out)
	return out
}

func copyDecisions(in map[string]Verdict) map[string]Verdict {
	out := make(map[string]Verdict, len(in))
	for key, value := range in {
		out[key] = value
	}
	return out
}
