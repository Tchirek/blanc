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

func validVerdict(verdict Verdict) bool {
	switch verdict {
	case VerdictBlock, VerdictReview, VerdictAllow:
		return true
	default:
		return false
	}
}
