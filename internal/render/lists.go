package render

import (
	"fmt"
	"strings"

	"github.com/blanc-sh/blanc/internal/audit"
	"github.com/blanc-sh/blanc/internal/engine"
)

func adguard(plan *engine.Plan) []byte {
	var b strings.Builder
	b.WriteString("! 電波絶ち\n! 紙の白さよ\n! 冴返る\n")
	for _, domain := range globalBlockedDomains(plan) {
		fmt.Fprintf(&b, "||%s^\n", domain)
	}
	return []byte(b.String())
}

func hosts(plan *engine.Plan) []byte {
	var b strings.Builder
	b.WriteString("# 電波絶ち\n# 紙の白さよ\n# 冴返る\n")
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

func reviewEndpoints(plan *engine.Plan) []byte {
	var b strings.Builder
	for _, finding := range plan.Findings {
		if finding.Verdict != engine.VerdictReview || len(finding.UploadPaths) == 0 {
			continue
		}
		fmt.Fprintf(&b, "%s\t%s\t%s\t%s\t%s\n",
			finding.Package, finding.Domain, finding.Class,
			strings.Join(finding.UploadPaths, ","), finding.Reason)
	}
	return []byte(b.String())
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
