package render

import (
	"fmt"
	"sort"
	"strings"

	"github.com/blanc-sh/blanc/internal/engine"
)

func mihomoRules(plan *engine.Plan) []byte {
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

	var b strings.Builder
	b.WriteString("# 電波絶ち\n# 紙の白さよ\n# 冴返る\n")
	for _, domain := range globals {
		fmt.Fprintf(&b, "- DOMAIN-SUFFIX,%s,REJECT\n", domain)
	}

	packages := make([]string, 0, len(scoped))
	for pkg := range scoped {
		packages = append(packages, pkg)
	}
	sort.Strings(packages)

	for _, pkg := range packages {
		domains := sortedSet(scoped[pkg])
		for _, domain := range domains {
			fmt.Fprintf(&b, "- AND,((PROCESS-NAME,%s),(DOMAIN-SUFFIX,%s)),REJECT\n", pkg, domain)
		}
	}
	return []byte(b.String())
}

func mihomoProvider(plan *engine.Plan) []byte {
	globals := globalBlockedDomains(plan)
	var b strings.Builder
	b.WriteString("# 静けさを\n# 守るリストの\n# 白き門\n")
	if len(globals) == 0 {
		b.WriteString("payload: []\n")
		return []byte(b.String())
	}
	b.WriteString("payload:\n")
	for _, domain := range globals {
		fmt.Fprintf(&b, "  - DOMAIN-SUFFIX,%s\n", domain)
	}
	return []byte(b.String())
}
