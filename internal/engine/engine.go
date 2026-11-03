package engine

import (
	"fmt"
	"sort"

	"github.com/blanc-sh/blanc/internal/audit"
	"github.com/blanc-sh/blanc/internal/policy"
)

type Verdict string

const (
	VerdictBlock  Verdict = "block"
	VerdictReview Verdict = "review"
	VerdictAllow  Verdict = "allow"
)

type Finding struct {
	ID              string            `json:"id"`
	Package         string            `json:"package"`
	System          bool              `json:"system"`
	Category        string            `json:"category"`
	DataTypes       []string          `json:"data_types,omitempty"`
	Sensitive       bool              `json:"sensitive"`
	SensitiveReason string            `json:"sensitive_reason,omitempty"`
	Domain          string            `json:"domain"`
	Class           audit.DomainClass `json:"class"`
	Verdict         Verdict           `json:"verdict"`
	Reason          string            `json:"reason"`
	Evidence        []string          `json:"evidence,omitempty"`
}

type Ignored struct {
	Package string `json:"package"`
	Raw     string `json:"raw"`
	Reason  string `json:"reason"`
}

type Stats struct {
	Apps           int `json:"apps"`
	Endpoints      int `json:"endpoints"`
	Findings       int `json:"findings"`
	Blocked        int `json:"blocked"`
	Review         int `json:"review"`
	Allowed        int `json:"allowed"`
	AppsWithBlocks int `json:"apps_with_blocks"`
	UniqueDomains  int `json:"unique_domains"`
	BlockedDomains int `json:"blocked_domains"`
	Ignored        int `json:"ignored"`
}

type Plan struct {
	Device               audit.Device      `json:"device"`
	AppCount             int               `json:"app_count"`
	Findings             []Finding         `json:"findings"`
	Ignored              []Ignored         `json:"ignored"`
	Stats                Stats             `json:"stats"`
	ReportHash           string            `json:"report_hash"`
	PolicyHash           string            `json:"policy_hash"`
	ReportSource         string            `json:"report_source,omitempty"`
	PolicySource         string            `json:"policy_source,omitempty"`
	ReportKeys           []string          `json:"report_keys"`
	DomainsDir           string            `json:"domains_dir"`
	DomainSources        map[string]string `json:"domain_sources"`
	DomainHashes         map[string]string `json:"domain_hashes"`
	ClassificationSource string            `json:"classification_source"`
}

// 暗き夜
// 見えぬ声を
// 星に数え
func Compile(report *audit.Report, domains *audit.DomainSet, pol *policy.Policy) (*Plan, error) {
	if report == nil {
		return nil, fmt.Errorf("engine: nil report")
	}
	if domains == nil {
		return nil, fmt.Errorf("engine: nil NOIR domain export")
	}
	if pol == nil {
		return nil, fmt.Errorf("engine: nil policy")
	}

	plan := &Plan{
		Device:               report.Device,
		AppCount:             len(report.Apps),
		ReportHash:           report.Hash,
		PolicyHash:           pol.Hash,
		ReportSource:         report.Source,
		PolicySource:         pol.Path,
		ReportKeys:           append([]string(nil), report.Keys...),
		DomainsDir:           domains.Dir,
		DomainSources:        domainSources(domains.Sources),
		DomainHashes:         copyMap(domains.Hashes),
		ClassificationSource: "noir",
	}

	types := stringSet(pol.Sensitive.DataTypes)
	categories := stringSet(pol.Sensitive.Categories)

	for _, app := range report.Apps {
		dataTypes := app.DataTypeSlugs()
		sensitive, sensitiveReason := appSensitivity(app, dataTypes, types, categories)
		override := pol.Apps[app.Package]
		allow := stringSet(override.Allow)
		block := stringSet(override.Block)

		groups := make(map[string][]string)
		ignored := make([]Ignored, 0)
		seenIgnored := make(map[string]struct{})

		for _, raw := range app.Endpoints {
			plan.Stats.Endpoints++
			ep, err := audit.ParseEndpoint(raw)
			if err != nil {
				if _, seen := seenIgnored[raw]; !seen {
					seenIgnored[raw] = struct{}{}
					ignored = append(ignored, Ignored{Package: app.Package, Raw: raw, Reason: err.Error()})
				}
				continue
			}
			if _, known := domains.Class(ep.Host); !known {
				if _, explicitlyBlocked := block[ep.Host]; !explicitlyBlocked {
					if _, seen := seenIgnored[raw]; !seen {
						seenIgnored[raw] = struct{}{}
						ignored = append(ignored, Ignored{
							Package: app.Package,
							Raw:     raw,
							Reason:  "not in NOIR domain export",
						})
					}
					continue
				}
			}
			if !contains(groups[ep.Host], raw) && len(groups[ep.Host]) < 6 {
				groups[ep.Host] = append(groups[ep.Host], raw)
			}
		}

		hosts := make([]string, 0, len(groups))
		for host := range groups {
			hosts = append(hosts, host)
		}
		sort.Strings(hosts)

		for _, host := range hosts {
			class, known := domains.Class(host)
			if !known {
				class = audit.ClassUnknown
			}
			verdict, reason := decide(app, host, class, sensitive, sensitiveReason, override, allow, block, pol.IncludeSystem)
			plan.Findings = append(plan.Findings, Finding{
				ID:              findingID(app.Package, host),
				Package:         app.Package,
				System:          app.System,
				Category:        app.CategorySlug(),
				DataTypes:       dataTypes,
				Sensitive:       sensitive,
				SensitiveReason: sensitiveReason,
				Domain:          host,
				Class:           class,
				Verdict:         verdict,
				Reason:          reason,
				Evidence:        groups[host],
			})
		}
		plan.Ignored = append(plan.Ignored, ignored...)
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

func appSensitivity(app audit.App, dataTypes []string, types, categories map[string]struct{}) (bool, string) {
	for _, dataType := range dataTypes {
		if _, ok := types[dataType]; ok {
			return true, "data:" + dataType
		}
	}
	category := app.CategorySlug()
	if category != "" {
		if _, ok := categories[category]; ok {
			return true, "category:" + category
		}
	}
	return false, ""
}

func decide(app audit.App, host string, class audit.DomainClass, sensitive bool, sensitiveReason string, override policy.AppOverride, allow, block map[string]struct{}, includeSystem bool) (Verdict, string) {
	if _, ok := allow[host]; ok {
		return VerdictAllow, "app allowlist"
	}
	if _, ok := block[host]; ok {
		if class == audit.ClassUnknown {
			return VerdictBlock, "app blocklist (not in NOIR domain export)"
		}
		return VerdictBlock, "app blocklist"
	}
	switch override.Mode {
	case "allow":
		return VerdictAllow, "app mode allow"
	case "review":
		return VerdictReview, "app mode review"
	}

	switch class {
	case audit.ClassFunctional:
		return VerdictAllow, "functional per NOIR"
	case audit.ClassReview, audit.ClassUnknown:
		return VerdictReview, "review per NOIR"
	}

	if override.Mode == "block" {
		return VerdictBlock, "app mode block"
	}
	if !includeSystem && app.System {
		return VerdictReview, "system app excluded"
	}
	if sensitive {
		return VerdictBlock, "tracker + app capability: " + sensitiveReason
	}
	return VerdictReview, "tracker without sensitive app capability"
}

// 眠る影
// ゆれる窓辺に
// 鍵をかけ
func recompute(plan *Plan) {
	stats := Stats{Apps: plan.AppCount, Endpoints: plan.Stats.Endpoints}
	uniqueDomains := make(map[string]struct{})
	blockedDomains := make(map[string]struct{})
	appsWithBlocks := make(map[string]struct{})

	for _, finding := range plan.Findings {
		stats.Findings++
		uniqueDomains[finding.Domain] = struct{}{}
		switch finding.Verdict {
		case VerdictBlock:
			stats.Blocked++
			blockedDomains[finding.Domain] = struct{}{}
			appsWithBlocks[finding.Package] = struct{}{}
		case VerdictReview:
			stats.Review++
		case VerdictAllow:
			stats.Allowed++
		}
	}
	stats.UniqueDomains = len(uniqueDomains)
	stats.BlockedDomains = len(blockedDomains)
	stats.AppsWithBlocks = len(appsWithBlocks)
	stats.Ignored = len(plan.Ignored)
	plan.Stats = stats
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

func copyMap(in map[string]string) map[string]string {
	out := make(map[string]string, len(in))
	for key, value := range in {
		out[key] = value
	}
	return out
}

func domainSources(in map[audit.DomainClass]string) map[string]string {
	out := make(map[string]string, len(in))
	for class, path := range in {
		out[string(class)] = path
	}
	return out
}
