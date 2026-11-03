package render

import (
	"fmt"
	"strings"

	"github.com/blanc-sh/blanc/internal/audit"
	"github.com/blanc-sh/blanc/internal/engine"
)

func adguard(plan *engine.Plan) []byte {
	var b strings.Builder
	b.WriteString("! 白き紙\n! 闇の通信を\n! 断ち切る\n")
	for _, domain := range globalBlockedDomains(plan) {
		fmt.Fprintf(&b, "||%s^\n", domain)
	}
	return []byte(b.String())
}

func hosts(plan *engine.Plan) []byte {
	var b strings.Builder
	b.WriteString("# 白き紙\n# 闇の通信を\n# 断ち切る\n")
	for _, domain := range globalBlockedDomains(plan) {
		fmt.Fprintf(&b, "0.0.0.0 %s\n", domain)
	}
	return []byte(b.String())
}

func globalDomains(plan *engine.Plan) []byte {
	domains := globalBlockedDomains(plan)
	return []byte(strings.Join(domains, "\n") + trailingNewline(domains))
}

func blockedDomains(plan *engine.Plan) []byte {
	domains := uniqueBlockedDomains(plan)
	return []byte(strings.Join(domains, "\n") + trailingNewline(domains))
}

func reviewDomains(plan *engine.Plan) []byte {
	set := make(map[string]struct{})
	for _, finding := range plan.Findings {
		if finding.Class == audit.ClassTracker && finding.Verdict == engine.VerdictReview {
			set[finding.Domain] = struct{}{}
		}
	}
	domains := sortedSet(set)
	return []byte(strings.Join(domains, "\n") + trailingNewline(domains))
}

func trailingNewline(domains []string) string {
	if len(domains) == 0 {
		return ""
	}
	return "\n"
}
