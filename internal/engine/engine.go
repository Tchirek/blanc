package engine

import (
	"fmt"
	"sort"
	"strings"

	"github.com/Tchirek/blanc/internal/audit"
	"github.com/Tchirek/blanc/internal/policy"
)

type Finding struct {
	Package   string            `json:"package"`
	System    bool              `json:"system"`
	SharedUID string            `json:"shared_uid,omitempty"`
	Domain    string            `json:"domain"`
	Class     audit.DomainClass `json:"class"`
	Verdict   Verdict           `json:"verdict"`
	Reason    string            `json:"reason"`
	Evidence  []string          `json:"evidence,omitempty"`
}

func (f Finding) Blocked() bool {
	return f.Verdict == VerdictBlock
}

type Level string

const (
	LevelWarn Level = "warn"
	LevelInfo Level = "info"
)

type Note struct {
	Level   Level  `json:"level"`
	Subject string `json:"subject"`
	Message string `json:"message"`
}

type Stats struct {
	Apps              int `json:"apps"`
	Endpoints         int `json:"endpoints"`
	EndpointsOutside  int `json:"endpoints_outside_export"`
	Trackers          int `json:"noir_trackers"`
	Functional        int `json:"noir_functional"`
	Review            int `json:"noir_review"`
	Rules             int `json:"rules"`
	GlobalRules       int `json:"global_rules"`
	AppRules          int `json:"app_rules"`
	Exceptions        int `json:"exceptions"`
	Findings          int `json:"findings"`
	BlockedFindings   int `json:"blocked_findings"`
	AllowedFindings   int `json:"allowed_findings"`
	SkippedDomainRows int `json:"skipped_domain_rows"`
}

type Plan struct {
	Device       audit.Device      `json:"device"`
	HasReport    bool              `json:"has_report"`
	Rules        []Rule            `json:"rules"`
	Findings     []Finding         `json:"findings"`
	Notes        []Note            `json:"notes"`
	Stats        Stats             `json:"stats"`
	Skipped      map[string]string `json:"skipped_packages,omitempty"`
	ReportHash   string            `json:"report_hash,omitempty"`
	PolicyHash   string            `json:"policy_hash"`
	ReportSource string            `json:"report_source,omitempty"`
	PolicySource string            `json:"policy_source,omitempty"`
	ReportKeys   []string          `json:"report_keys,omitempty"`
	DomainsDir   string            `json:"domains_dir"`
	DomainHashes map[string]string `json:"domain_hashes"`
	DomainIssues DomainIssues      `json:"domain_issues"`

	decider *Decider
}

type DomainIssues struct {
	SkippedIPs int               `json:"skipped_ips,omitempty"`
	Skipped    []audit.LineIssue `json:"skipped,omitempty"`
	Repaired   []audit.LineIssue `json:"repaired,omitempty"`
	Conflicts  []audit.Conflict  `json:"conflicts,omitempty"`
}

const maxEvidence = 6

// 暗き夜
// 見えぬ声を
// 星に数え
func Compile(report *audit.Report, domains *audit.DomainSet, pol *policy.Policy) (*Plan, error) {
	if domains == nil {
		return nil, fmt.Errorf("engine: nil NOIR domain export")
	}
	if pol == nil {
		return nil, fmt.Errorf("engine: nil policy")
	}
	plan := &Plan{
		PolicyHash:   pol.Hash,
		PolicySource: pol.Path,
		DomainsDir:   domains.Dir,
		DomainHashes: copyMap(domains.Hashes),
		DomainIssues: DomainIssues{
			SkippedIPs: domains.SkippedIPs,
			Skipped:    domains.Skipped,
			Repaired:   domains.Repaired,
			Conflicts:  domains.Conflicts,
		},
		Skipped: map[string]string{},
	}
	if report != nil {
		plan.HasReport = true
		plan.Device = report.Device
		plan.ReportHash = report.Hash
		plan.ReportSource = report.Source
		plan.ReportKeys = append([]string(nil), report.Keys...)
		plan.Stats.Apps = len(report.Apps)
	}

	plan.Notes = append(plan.Notes, packageNotes(report, pol, plan.Skipped)...)
	decider := NewDecider(pol, domains, plan.Skipped)
	plan.decider = decider
	plan.Rules = decider.Rules()
	plan.Notes = append(plan.Notes, entryNotes(pol, domains)...)
	plan.Notes = append(plan.Notes, domainNotes(domains)...)

	if report != nil {
		plan.Findings = findings(report, decider, plan)
	}
	recompute(plan, domains)
	return plan, nil
}

// 問いかけに
// 段の理由を
// 答えけり
func (p *Plan) Explain(pkg, host string) Decision {
	return p.decider.Decide(pkg, host)
}

func (p *Plan) Find(pkg, domain string) (Finding, bool) {
	for _, finding := range p.Findings {
		if finding.Package == pkg && finding.Domain == domain {
			return finding, true
		}
	}
	return Finding{}, false
}

// 同じ戸の
// 名に掛けた鍵
// 外しけり
func packageNotes(report *audit.Report, pol *policy.Policy, skipped map[string]string) []Note {
	notes := make([]Note, 0)
	if report == nil {
		if len(pol.Apps) > 0 {
			notes = append(notes, Note{Level: LevelWarn, Subject: "apps",
				Message: "no NOIR report was read, so shared-UID packages cannot be detected; per-app entries are applied as written"})
		}
		return notes
	}
	shared := make(map[string][]string)
	for _, app := range report.Apps {
		if app.SharesUID() {
			shared[app.SharedUID] = append(shared[app.SharedUID], app.Package)
		}
	}
	for _, pkg := range pol.Packages() {
		app, ok := report.App(pkg)
		if !ok {
			notes = append(notes, Note{Level: LevelInfo, Subject: "apps." + pkg,
				Message: "not in the NOIR report (NOIR lists only flagged apps; check the spelling)"})
			continue
		}
		if !app.SharesUID() {
			continue
		}
		reason := fmt.Sprintf("shares UID %s (%s) with other packages; Android attributes traffic per UID, so proxies cannot tell this package apart", uidLabel(app.UID), app.SharedUID)
		skipped[pkg] = reason
		peers := len(shared[app.SharedUID]) - 1
		message := reason + "; entry ignored, use a global allow/block instead"
		if peers > 0 {
			message = fmt.Sprintf("%s (the report lists %d more package(s) on this UID)", message, peers)
		}
		notes = append(notes, Note{Level: LevelWarn, Subject: "apps." + pkg, Message: message})
	}
	return notes
}

func uidLabel(uid string) string {
	if uid == "" {
		return "?"
	}
	return uid
}

// 空の札
// 用なき鍵を
// 告げにけり
func entryNotes(pol *policy.Policy, domains *audit.DomainSet) []Note {
	notes := make([]Note, 0)
	trackers := domains.Hosts(audit.ClassTracker)
	functional := domains.Hosts(audit.ClassFunctional)

	blockTargets := append(append([]string(nil), trackers...), pol.Block...)
	for _, allow := range pol.Allow {
		if !intersectsAny(blockTargets, allow) {
			notes = append(notes, Note{Level: LevelInfo, Subject: "allow " + allow,
				Message: "matches no NOIR tracker and no global block; it has no effect"})
		}
	}
	for _, block := range pol.Block {
		if hits := underOrOver(functional, block); len(hits) > 0 {
			notes = append(notes, Note{Level: LevelWarn, Subject: "block " + block,
				Message: "blocks NOIR functional host(s) " + joinLimit(hits, 3) + " for every app; push/login/update may break"})
		}
	}
	for _, pkg := range pol.Packages() {
		app := pol.Apps[pkg]
		appTargets := append(append([]string(nil), blockTargets...), app.Block...)
		for _, allow := range app.Allow {
			if !intersectsAny(appTargets, allow) {
				notes = append(notes, Note{Level: LevelInfo, Subject: "apps." + pkg + ".allow " + allow,
					Message: "matches nothing that is blocked; it has no effect"})
			}
		}
		for _, block := range app.Block {
			if hits := underOrOver(functional, block); len(hits) > 0 {
				notes = append(notes, Note{Level: LevelWarn, Subject: "apps." + pkg + ".block " + block,
					Message: "blocks NOIR functional host(s) " + joinLimit(hits, 3) + " for this app"})
			}
		}
	}
	return notes
}

func domainNotes(domains *audit.DomainSet) []Note {
	notes := make([]Note, 0)
	if n := len(domains.Skipped); n > 0 {
		samples := make([]string, 0, 3)
		for _, issue := range domains.Skipped {
			if len(samples) == 3 {
				break
			}
			samples = append(samples, fmt.Sprintf("%s:%d %q", issue.File, issue.Line, issue.Raw))
		}
		notes = append(notes, Note{Level: LevelInfo, Subject: "NOIR export",
			Message: fmt.Sprintf("skipped %d row(s) that are not hostnames, e.g. %s", n, joinLimit(samples, 3))})
	}
	if n := len(domains.Repaired); n > 0 {
		notes = append(notes, Note{Level: LevelInfo, Subject: "NOIR export",
			Message: fmt.Sprintf("trimmed URL noise from %d row(s), e.g. %q -> %s", n, domains.Repaired[0].Raw, domains.Repaired[0].Host)})
	}
	for _, conflict := range domains.Conflicts {
		notes = append(notes, Note{Level: LevelInfo, Subject: conflict.Host,
			Message: fmt.Sprintf("listed as %v by NOIR; kept %s", conflict.Classes, conflict.Kept)})
	}
	return notes
}

// 帳を繰り
// 窓ごとの声
// 書き留める
func findings(report *audit.Report, decider *Decider, plan *Plan) []Finding {
	out := make([]Finding, 0)
	for _, app := range report.Apps {
		groups := make(map[string][]string)
		for _, raw := range app.Endpoints {
			plan.Stats.Endpoints++
			ep, err := audit.ParseEndpoint(raw)
			if err != nil {
				plan.Stats.EndpointsOutside++
				continue
			}
			decision := decider.Decide(app.Package, ep.Host)
			if decision.Tier == TierDefault {
				plan.Stats.EndpointsOutside++
				continue
			}
			if !contains(groups[ep.Host], ep.Raw) && len(groups[ep.Host]) < maxEvidence {
				groups[ep.Host] = append(groups[ep.Host], ep.Raw)
			}
		}
		hosts := make([]string, 0, len(groups))
		for host := range groups {
			hosts = append(hosts, host)
		}
		sort.Strings(hosts)
		for _, host := range hosts {
			decision := decider.Decide(app.Package, host)
			out = append(out, Finding{
				Package:   app.Package,
				System:    app.System,
				SharedUID: app.SharedUID,
				Domain:    host,
				Class:     decision.Class,
				Verdict:   decision.Verdict,
				Reason:    decision.Reason,
				Evidence:  groups[host],
			})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Package != out[j].Package {
			return out[i].Package < out[j].Package
		}
		return out[i].Domain < out[j].Domain
	})
	return out
}

// 眠る影
// ゆれる窓辺に
// 鍵をかけ
func recompute(plan *Plan, domains *audit.DomainSet) {
	stats := &plan.Stats
	stats.Trackers = domains.Count(audit.ClassTracker)
	stats.Functional = domains.Count(audit.ClassFunctional)
	stats.Review = domains.Count(audit.ClassReview)
	stats.SkippedDomainRows = len(domains.Skipped)
	stats.Rules = len(plan.Rules)
	for _, rule := range plan.Rules {
		if rule.Package == "" {
			stats.GlobalRules++
		} else {
			stats.AppRules++
		}
		stats.Exceptions += len(rule.Except)
	}
	stats.Findings = len(plan.Findings)
	for _, finding := range plan.Findings {
		if finding.Blocked() {
			stats.BlockedFindings++
		} else {
			stats.AllowedFindings++
		}
	}
	sort.SliceStable(plan.Notes, func(i, j int) bool {
		return plan.Notes[i].Level == LevelWarn && plan.Notes[j].Level != LevelWarn
	})
}

func intersectsAny(domains []string, entry string) bool {
	for _, domain := range domains {
		if audit.Covers(domain, entry) || audit.Covers(entry, domain) {
			return true
		}
	}
	return false
}

func underOrOver(domains []string, entry string) []string {
	out := make([]string, 0)
	for _, domain := range domains {
		if audit.Covers(domain, entry) || audit.Covers(entry, domain) {
			out = append(out, domain)
		}
	}
	return out
}

func joinLimit(values []string, limit int) string {
	if len(values) <= limit {
		return strings.Join(values, ", ")
	}
	return fmt.Sprintf("%s (+%d more)", strings.Join(values[:limit], ", "), len(values)-limit)
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
