package render

import (
	"fmt"
	"sort"
	"strings"

	"github.com/Tchirek/blanc/internal/engine"
)

func mihomoRules(plan *engine.Plan) []byte {
	scoped := make(map[string]map[string]struct{})
	for _, finding := range plan.Findings {
		if !finding.Blocked() {
			continue
		}
		domains, ok := scoped[finding.Package]
		if !ok {
			domains = make(map[string]struct{})
			scoped[finding.Package] = domains
		}
		domains[finding.Domain] = struct{}{}
	}

	packages := make([]string, 0, len(scoped))
	for pkg := range scoped {
		packages = append(packages, pkg)
	}
	sort.Strings(packages)

	var b strings.Builder
	b.WriteString("# 電波絶ち\n# 紙の白さよ\n# 冴返る\n")
	for _, pkg := range packages {
		for _, domain := range sortedSet(scoped[pkg]) {
			fmt.Fprintf(&b, "- AND,((PROCESS-NAME,%s),(DOMAIN-SUFFIX,%s)),REJECT\n", pkg, domain)
		}
	}
	return []byte(b.String())
}
