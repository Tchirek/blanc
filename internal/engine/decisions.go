package engine

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/blanc-sh/blanc/internal/audit"
)

type decisionDocument struct {
	Version   int                `json:"version"`
	Decisions map[string]Verdict `json:"decisions"`
}

func LoadDecisions(path string) (map[string]Verdict, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read decisions: %w", err)
	}
	var doc decisionDocument
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("parse decisions: %w", err)
	}
	if doc.Version != 1 {
		return nil, fmt.Errorf("decisions: unsupported version %d (want 1)", doc.Version)
	}
	for id, verdict := range doc.Decisions {
		if !validVerdict(verdict) {
			return nil, fmt.Errorf("decisions: invalid verdict %q for %s", verdict, id)
		}
		pkg, domain, ok := strings.Cut(id, "|")
		if !ok || !audit.ValidPackage(pkg) || !audit.ValidDomain(domain) {
			return nil, fmt.Errorf("decisions: invalid finding id %q", id)
		}
	}
	if doc.Decisions == nil {
		doc.Decisions = map[string]Verdict{}
	}
	return doc.Decisions, nil
}

func SaveDecisions(path string, decisions map[string]Verdict) error {
	if decisions == nil {
		decisions = map[string]Verdict{}
	}
	raw, err := json.MarshalIndent(decisionDocument{Version: 1, Decisions: decisions}, "", "  ")
	if err != nil {
		return err
	}
	raw = append(raw, '\n')
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		return fmt.Errorf("write decisions: %w", err)
	}
	return nil
}

// 白黒を
// 人の指先に
// 委ねけり
func ApplyDecisions(plan *Plan, decisions map[string]Verdict) (*Plan, error) {
	if plan == nil {
		return nil, fmt.Errorf("engine: nil plan")
	}
	for id, verdict := range decisions {
		if !validVerdict(verdict) {
			return nil, fmt.Errorf("engine: invalid verdict %q for %s", verdict, id)
		}
	}
	clone := *plan
	clone.Findings = append([]Finding(nil), plan.Findings...)
	clone.Ignored = append([]Ignored(nil), plan.Ignored...)
	clone.Decisions = copyDecisions(decisions)

	for i := range clone.Findings {
		finding := &clone.Findings[i]
		decision, ok := decisions[finding.ID]
		if !ok || finding.Scope == ScopeGlobal {
			continue
		}
		applyDecision(finding, decision)
	}
	recompute(&clone)
	return &clone, nil
}

func validVerdict(verdict Verdict) bool {
	switch verdict {
	case VerdictBlock, VerdictReview, VerdictAllow:
		return true
	default:
		return false
	}
}
