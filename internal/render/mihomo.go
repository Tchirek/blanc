package render

import (
	"strings"

	"github.com/Tchirek/blanc/internal/engine"
)

// 一行に
// 網と例外
// 畳み込む
func MihomoRule(rule engine.Rule) string {
	parts := []string{"DOMAIN-SUFFIX," + rule.Domain}
	if rule.Package != "" {
		parts = append(parts, "PROCESS-NAME,"+rule.Package)
	}
	for _, cond := range rule.Except {
		parts = append(parts, "NOT,(("+mihomoCond(cond)+"))")
	}
	if len(parts) == 1 {
		return parts[0] + ",REJECT"
	}
	return "AND,((" + strings.Join(parts, "),(") + ")),REJECT"
}

func mihomoCond(cond engine.Cond) string {
	switch {
	case cond.Package != "" && cond.Domain != "":
		return "AND,((PROCESS-NAME," + cond.Package + "),(DOMAIN-SUFFIX," + cond.Domain + "))"
	case cond.Package != "":
		return "PROCESS-NAME," + cond.Package
	default:
		return "DOMAIN-SUFFIX," + cond.Domain
	}
}

func mihomoRules(plan *engine.Plan) []byte {
	var b strings.Builder
	b.WriteString("# 電波絶ち\n# 紙の白さよ\n# 冴返る\n")
	for _, rule := range plan.Rules {
		b.WriteString("- ")
		b.WriteString(MihomoRule(rule))
		b.WriteByte('\n')
	}
	return []byte(b.String())
}
