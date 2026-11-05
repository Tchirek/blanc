package render

import (
	"sort"

	"github.com/Tchirek/blanc/internal/engine"
)

type SourceRuleSet struct {
	Version int        `json:"version"`
	Rules   []Headless `json:"rules"`
}

type Headless struct {
	Type         string     `json:"type,omitempty"`
	Mode         string     `json:"mode,omitempty"`
	Rules        []Headless `json:"rules,omitempty"`
	PackageName  []string   `json:"package_name,omitempty"`
	Domain       []string   `json:"domain,omitempty"`
	DomainSuffix []string   `json:"domain_suffix,omitempty"`
	Invert       bool       `json:"invert,omitempty"`
}

type RouteFragment struct {
	Route Route `json:"route"`
}

type Route struct {
	RuleSet []RuleSetRef `json:"rule_set"`
	Rules   []RouteRule  `json:"rules"`
}

type RuleSetRef struct {
	Tag    string `json:"tag"`
	Type   string `json:"type"`
	Format string `json:"format"`
	Path   string `json:"path"`
}

type RouteRule struct {
	RuleSet string `json:"rule_set,omitempty"`
	Action  string `json:"action"`
}

const SingboxTag = "blanc"

// 素の網は
// 一つに束ね
// 軽くせり
func SingboxRuleSet(rules []engine.Rule) SourceRuleSet {
	set := SourceRuleSet{Version: 3, Rules: []Headless{}}
	global := make([]string, 0)
	scoped := make(map[string][]string)
	logical := make([]Headless, 0)

	for _, rule := range rules {
		switch {
		case len(rule.Except) > 0:
			logical = append(logical, singboxLogical(rule))
		case rule.Package == "":
			global = append(global, rule.Domain)
		default:
			scoped[rule.Package] = append(scoped[rule.Package], rule.Domain)
		}
	}
	if len(global) > 0 {
		set.Rules = append(set.Rules, domainRule(global))
	}
	packages := make([]string, 0, len(scoped))
	for pkg := range scoped {
		packages = append(packages, pkg)
	}
	sort.Strings(packages)
	for _, pkg := range packages {
		rule := domainRule(scoped[pkg])
		rule.PackageName = []string{pkg}
		set.Rules = append(set.Rules, rule)
	}
	set.Rules = append(set.Rules, logical...)
	return set
}

// 否の札
// 並べて閉ざす
// 一つ門
func singboxLogical(rule engine.Rule) Headless {
	subs := []Headless{domainRule([]string{rule.Domain})}
	if rule.Package != "" {
		subs = append(subs, Headless{PackageName: []string{rule.Package}})
	}
	for _, cond := range rule.Except {
		sub := Headless{Invert: true}
		if cond.Domain != "" {
			sub = domainRule([]string{cond.Domain})
			sub.Invert = true
		}
		if cond.Package != "" {
			sub.PackageName = []string{cond.Package}
		}
		subs = append(subs, sub)
	}
	return Headless{Type: "logical", Mode: "and", Rules: subs}
}

func domainRule(domains []string) Headless {
	sorted := append([]string(nil), domains...)
	sort.Strings(sorted)
	suffix := make([]string, len(sorted))
	for i, domain := range sorted {
		suffix[i] = "." + domain
	}
	return Headless{Domain: sorted, DomainSuffix: suffix}
}

// 嗅ぎてのち
// 名を確かめて
// 門を閉づ
func SingboxRoute(path string) RouteFragment {
	return RouteFragment{
		Route: Route{
			RuleSet: []RuleSetRef{{Tag: SingboxTag, Type: "local", Format: "source", Path: path}},
			Rules: []RouteRule{
				{Action: "sniff"},
				{RuleSet: SingboxTag, Action: "reject"},
			},
		},
	}
}
