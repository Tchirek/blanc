package engine

import (
	"github.com/Tchirek/blanc/internal/audit"
	"github.com/Tchirek/blanc/internal/policy"
)

type Verdict string

const (
	VerdictBlock Verdict = "block"
	VerdictAllow Verdict = "allow"
)

type Tier string

const (
	TierApp     Tier = "app"
	TierGlobal  Tier = "global"
	TierNoir    Tier = "noir"
	TierDefault Tier = "default"
)

type Decision struct {
	Verdict Verdict           `json:"verdict"`
	Tier    Tier              `json:"tier"`
	Match   string            `json:"match,omitempty"`
	Class   audit.DomainClass `json:"class"`
	Reason  string            `json:"reason"`
}

func (d Decision) Blocked() bool {
	return d.Verdict == VerdictBlock
}

// 掟あり
// 近き札こそ
// 先に立つ
type Decider struct {
	policy  *policy.Policy
	domains *audit.DomainSet
	skipped map[string]string
	noir    []noirEntry
}

type noirEntry struct {
	host  string
	class audit.DomainClass
}

func NewDecider(pol *policy.Policy, domains *audit.DomainSet, skipped map[string]string) *Decider {
	d := &Decider{policy: pol, domains: domains, skipped: skipped}
	for host, class := range domains.Classes {
		d.noir = append(d.noir, noirEntry{host: host, class: class})
	}
	return d
}

// 名と窓
// 四つの段を
// 下りゆく
func (d *Decider) Decide(pkg, host string) Decision {
	class := d.classOf(host)
	if app, ok := d.app(pkg); ok {
		if match, verdict, found := longest(app.Allow, app.Block, host); found {
			return Decision{Verdict: verdict, Tier: TierApp, Match: match, Class: class,
				Reason: "app " + string(verdict) + " " + match}
		}
		if app.AllowAll {
			return Decision{Verdict: VerdictAllow, Tier: TierApp, Class: class, Reason: "app allow all"}
		}
	}
	if match, verdict, found := longest(d.policy.Allow, d.policy.Block, host); found {
		return Decision{Verdict: verdict, Tier: TierGlobal, Match: match, Class: class,
			Reason: "global " + string(verdict) + " " + match}
	}
	if entry, found := d.noirMatch(host); found {
		verdict := VerdictAllow
		if entry.class == audit.ClassTracker {
			verdict = VerdictBlock
		}
		return Decision{Verdict: verdict, Tier: TierNoir, Match: entry.host, Class: class,
			Reason: "NOIR " + string(entry.class) + " " + entry.host}
	}
	return Decision{Verdict: VerdictAllow, Tier: TierDefault, Class: class, Reason: "not in NOIR export"}
}

func (d *Decider) app(pkg string) (policy.App, bool) {
	if pkg == "" {
		return policy.App{}, false
	}
	if _, skip := d.skipped[pkg]; skip {
		return policy.App{}, false
	}
	app, ok := d.policy.Apps[pkg]
	return app, ok
}

func (d *Decider) classOf(host string) audit.DomainClass {
	if class, ok := d.domains.Class(host); ok {
		return class
	}
	return audit.ClassUnknown
}

func (d *Decider) noirMatch(host string) (noirEntry, bool) {
	best := noirEntry{}
	found := false
	for _, entry := range d.noir {
		if audit.Covers(entry.host, host) && len(entry.host) > len(best.host) {
			best, found = entry, true
		}
	}
	return best, found
}

// 長き名は
// 細き枝まで
// 言い当てる
func longest(allow, block []string, host string) (string, Verdict, bool) {
	match, verdict, found := "", VerdictAllow, false
	for _, candidate := range allow {
		if audit.Covers(candidate, host) && len(candidate) > len(match) {
			match, verdict, found = candidate, VerdictAllow, true
		}
	}
	for _, candidate := range block {
		if audit.Covers(candidate, host) && len(candidate) > len(match) {
			match, verdict, found = candidate, VerdictBlock, true
		}
	}
	return match, verdict, found
}
