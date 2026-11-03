package render

import (
	"sort"

	"github.com/blanc-sh/blanc/internal/engine"
)

type sourceRuleSet struct {
	Version int          `json:"version"`
	Rules   []sourceRule `json:"rules"`
}

type sourceRule struct {
	PackageName  []string `json:"package_name,omitempty"`
	DomainSuffix []string `json:"domain_suffix,omitempty"`
}

type routeFragment struct {
	Route route `json:"route"`
}

type route struct {
	RuleSet []ruleSetRef `json:"rule_set"`
	Rules   []routeRule  `json:"rules"`
}

type ruleSetRef struct {
	Tag    string `json:"tag"`
	Type   string `json:"type"`
	Format string `json:"format"`
	Path   string `json:"path"`
}

type routeRule struct {
	RuleSet string `json:"rule_set"`
	Action  string `json:"action"`
}

func sourceRuleSetFor(plan *engine.Plan) sourceRuleSet {
	globals := globalBlockedDomains(plan)
	globalSet := make(map[string]struct{}, len(globals))
	for _, domain := range globals {
		globalSet[domain] = struct{}{}
	}

	scoped := make(map[string]map[string]struct{})
	for _, finding := range plan.Findings {
		if !finding.Blocked() || finding.Global() {
			continue
		}
		if _, ok := globalSet[finding.Domain]; ok {
			continue
		}
		domains, ok := scoped[finding.Package]
		if !ok {
			domains = make(map[string]struct{})
			scoped[finding.Package] = domains
		}
		domains[finding.Domain] = struct{}{}
	}

	rules := make([]sourceRule, 0, len(scoped)+1)
	if len(globals) > 0 {
		rules = append(rules, sourceRule{DomainSuffix: globals})
	}

	packages := make([]string, 0, len(scoped))
	for pkg := range scoped {
		packages = append(packages, pkg)
	}
	sort.Strings(packages)
	for _, pkg := range packages {
		domains := sortedSet(scoped[pkg])
		if len(domains) == 0 {
			continue
		}
		rules = append(rules, sourceRule{
			PackageName:  []string{pkg},
			DomainSuffix: domains,
		})
	}
	return sourceRuleSet{Version: 3, Rules: rules}
}

func singboxRoute() routeFragment {
	return routeFragment{
		Route: route{
			RuleSet: []ruleSetRef{
				{
					Tag:    "blanc",
					Type:   "local",
					Format: "source",
					Path:   "./blanc/singbox.json",
				},
			},
			Rules: []routeRule{
				{RuleSet: "blanc", Action: "reject"},
			},
		},
	}
}
