package webapi

import (
	"fmt"
	"path"
	"sort"
	"strings"
	"time"

	"github.com/Tchirek/blanc/internal/audit"
	"github.com/Tchirek/blanc/internal/engine"
	"github.com/Tchirek/blanc/internal/policy"
	"github.com/Tchirek/blanc/internal/render"
	"github.com/Tchirek/blanc/internal/version"
)

type Result struct {
	Files     map[string]string `json:"files"`
	Order     []string          `json:"order"`
	Stats     engine.Stats      `json:"stats"`
	Notes     []engine.Note     `json:"notes"`
	Device    audit.Device      `json:"device"`
	HasReport bool              `json:"has_report"`
	Policy    string            `json:"policy"`
	Unused    []string          `json:"unused"`
	Version   string            `json:"version"`
}

const (
	reportName = "report.json"
	policyName = "blanc.yaml"
)

// 手の内で
// 網を編みては
// 漏らさざり
func Compile(uploads map[string][]byte, policyText string, now time.Time) (*Result, error) {
	files := make(map[string][]byte)
	unused := make([]string, 0)
	wanted := map[string]bool{reportName: true, policyName: true}
	for _, name := range audit.DomainFiles() {
		wanted[name] = true
	}
	for name, raw := range uploads {
		base := path.Base(strings.ReplaceAll(name, `\`, "/"))
		if !wanted[base] {
			unused = append(unused, name)
			continue
		}
		files[base] = raw
	}
	sort.Strings(unused)

	missing := make([]string, 0)
	for _, name := range audit.DomainFiles() {
		if _, ok := files[name]; !ok {
			missing = append(missing, name)
		}
	}
	if len(missing) > 0 {
		return nil, fmt.Errorf("missing %s; choose the whole folder that noir scan wrote (noir-out)", strings.Join(missing, ", "))
	}
	domains, err := audit.ParseDomains("upload", files)
	if err != nil {
		return nil, err
	}

	var report *audit.Report
	if raw, ok := files[reportName]; ok {
		report, err = audit.Parse(raw)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", reportName, err)
		}
		if len(report.Apps) == 0 {
			return nil, fmt.Errorf("%s lists 0 apps; NOIR may have failed or its schema changed", reportName)
		}
		report.Source = reportName
	}

	policyLabel := "built-in"
	policyRaw := []byte(policyText)
	if strings.TrimSpace(policyText) != "" {
		policyLabel = "pasted"
	} else if raw, ok := files[policyName]; ok {
		policyRaw, policyLabel = raw, policyName
	}
	var pol *policy.Policy
	if policyLabel == "built-in" {
		pol, err = policy.Load("")
	} else {
		pol, err = policy.Parse(policyRaw)
		if err == nil {
			pol.Path = policyLabel
		}
	}
	if err != nil {
		return nil, fmt.Errorf("policy (%s): %w", policyLabel, err)
	}

	plan, err := engine.Compile(report, domains, pol)
	if err != nil {
		return nil, err
	}
	out, err := render.All(plan, render.Options{GeneratedAt: now.UTC()})
	if err != nil {
		return nil, err
	}

	result := &Result{
		Files:     make(map[string]string, len(out)),
		Order:     []string{render.FileMihomo, render.FileSingbox, render.FileSingboxRoute, render.FileSummary, render.FileManifest},
		Stats:     plan.Stats,
		Notes:     plan.Notes,
		Device:    plan.Device,
		HasReport: plan.HasReport,
		Policy:    policyLabel,
		Unused:    unused,
		Version:   version.String(),
	}
	if result.Notes == nil {
		result.Notes = []engine.Note{}
	}
	for name, data := range out {
		result.Files[name] = string(data)
	}
	return result, nil
}
