package engine

import (
	"sort"

	"github.com/Tchirek/blanc/internal/audit"
)

type Source string

const (
	SourceAppBlock    Source = "app block"
	SourceGlobalBlock Source = "global block"
	SourceNoirTracker Source = "NOIR tracker"
)

type Cond struct {
	Package string `json:"package,omitempty"`
	Domain  string `json:"domain,omitempty"`
}

type Rule struct {
	Domain  string `json:"domain"`
	Package string `json:"package,omitempty"`
	Except  []Cond `json:"except,omitempty"`
	Source  Source `json:"source"`
}

// 条件の
// 一つも欠けず
// 揃う時
func (c Cond) Matches(pkg, host string) bool {
	if c.Package != "" && c.Package != pkg {
		return false
	}
	return c.Domain == "" || audit.Covers(c.Domain, host)
}

// 網を張り
// 除けの札なき
// 時に閉づ
func (r Rule) Matches(pkg, host string) bool {
	if !audit.Covers(r.Domain, host) {
		return false
	}
	if r.Package != "" && r.Package != pkg {
		return false
	}
	for _, cond := range r.Except {
		if cond.Matches(pkg, host) {
			return false
		}
	}
	return true
}

func (r Rule) Scoped() bool {
	return r.Package != "" || r.hasPackageExcept()
}

func (r Rule) hasPackageExcept() bool {
	for _, cond := range r.Except {
		if cond.Package != "" {
			return true
		}
	}
	return false
}

// 白き網
// 例外だけを
// 編み残す
func (d *Decider) Rules() []Rule {
	rules := make([]Rule, 0)
	pol := d.policy

	for _, pkg := range d.activePackages() {
		app := pol.Apps[pkg]
		for _, domain := range app.Block {
			rules = append(rules, Rule{
				Domain:  domain,
				Package: pkg,
				Except:  domainConds(strictlyUnder(app.Allow, domain)),
				Source:  SourceAppBlock,
			})
		}
	}

	for _, domain := range pol.Block {
		except := domainConds(strictlyUnder(pol.Allow, domain))
		except = append(except, d.appExceptions(domain)...)
		rules = append(rules, Rule{Domain: domain, Except: sortConds(except), Source: SourceGlobalBlock})
	}

	shields := d.noirShields()
	trackers := d.domains.Hosts(audit.ClassTracker)
	for _, tracker := range trackers {
		if coveredByAny(pol.Allow, tracker) || coveredByAny(pol.Block, tracker) {
			continue
		}
		if d.dominated(tracker, trackers, shields) {
			continue
		}
		except := domainConds(strictlyUnder(pol.Allow, tracker))
		except = append(except, domainConds(strictlyUnder(shields, tracker))...)
		except = append(except, d.appExceptions(tracker)...)
		rules = append(rules, Rule{Domain: tracker, Except: sortConds(except), Source: SourceNoirTracker})
	}

	for i := range rules {
		rules[i].Except = sortConds(rules[i].Except)
	}
	sort.SliceStable(rules, func(i, j int) bool {
		if (rules[i].Package == "") != (rules[j].Package == "") {
			return rules[i].Package == ""
		}
		if rules[i].Package != rules[j].Package {
			return rules[i].Package < rules[j].Package
		}
		return rules[i].Domain < rules[j].Domain
	})
	return rules
}

// 守る名は
// 網の目からも
// 抜けにけり
func (d *Decider) appExceptions(base string) []Cond {
	out := make([]Cond, 0)
	for _, pkg := range d.activePackages() {
		app := d.policy.Apps[pkg]
		if app.AllowAll || coveredByAny(app.Allow, base) {
			out = append(out, Cond{Package: pkg})
			continue
		}
		for _, domain := range strictlyUnder(app.Allow, base) {
			out = append(out, Cond{Package: pkg, Domain: domain})
		}
	}
	return out
}

func (d *Decider) noirShields() []string {
	out := make([]string, 0)
	out = append(out, d.domains.Hosts(audit.ClassFunctional)...)
	out = append(out, d.domains.Hosts(audit.ClassReview)...)
	sort.Strings(out)
	return out
}

// 親の網
// 子をも包めば
// 子は要らず
func (d *Decider) dominated(tracker string, trackers, shields []string) bool {
	for _, parent := range trackers {
		if parent == tracker || !audit.Covers(parent, tracker) {
			continue
		}
		shielded := false
		for _, shield := range shields {
			if shield != parent && audit.Covers(parent, shield) && audit.Covers(shield, tracker) {
				shielded = true
				break
			}
		}
		if !shielded {
			return true
		}
	}
	return false
}

func (d *Decider) activePackages() []string {
	out := make([]string, 0, len(d.policy.Apps))
	for _, pkg := range d.policy.Packages() {
		if _, skip := d.skipped[pkg]; !skip {
			out = append(out, pkg)
		}
	}
	return out
}

func strictlyUnder(domains []string, base string) []string {
	out := make([]string, 0)
	for _, domain := range domains {
		if domain != base && audit.Covers(base, domain) {
			out = append(out, domain)
		}
	}
	return out
}

func coveredByAny(domains []string, host string) bool {
	for _, domain := range domains {
		if audit.Covers(domain, host) {
			return true
		}
	}
	return false
}

func domainConds(domains []string) []Cond {
	out := make([]Cond, 0, len(domains))
	for _, domain := range domains {
		out = append(out, Cond{Domain: domain})
	}
	return out
}

func sortConds(conds []Cond) []Cond {
	seen := make(map[Cond]struct{}, len(conds))
	out := make([]Cond, 0, len(conds))
	for _, cond := range conds {
		if _, ok := seen[cond]; ok {
			continue
		}
		seen[cond] = struct{}{}
		out = append(out, cond)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Package != out[j].Package {
			return out[i].Package < out[j].Package
		}
		return out[i].Domain < out[j].Domain
	})
	return out
}
