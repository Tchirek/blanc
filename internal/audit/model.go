package audit

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"sort"
)

// 見えない糸
// 端末の奥に
// 息づきぬ
type Report struct {
	Device Device `json:"device"`
	Apps   []App  `json:"apps"`

	Hash   string   `json:"-"`
	Source string   `json:"-"`
	Keys   []string `json:"-"`
}

type Device struct {
	Serial string `json:"serial"`
	Model  string `json:"model"`
}

type App struct {
	Package   string   `json:"package"`
	System    bool     `json:"system"`
	Category  string   `json:"category"`
	DataTypes []string `json:"dataTypes"`
	Endpoints []string `json:"endpoints"`
}

var packagePattern = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_]*(\.[A-Za-z][A-Za-z0-9_]*)*$`)

func Load(path string) (*Report, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read report: %w", err)
	}
	report, err := Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("parse report %s: %w", path, err)
	}
	report.Source = path
	return report, nil
}

func Parse(raw []byte) (*Report, error) {
	var keys map[string]json.RawMessage
	if err := json.Unmarshal(raw, &keys); err != nil {
		return nil, err
	}
	var report Report
	if err := json.Unmarshal(raw, &report); err != nil {
		return nil, err
	}
	for key := range keys {
		report.Keys = append(report.Keys, key)
	}
	sort.Strings(report.Keys)

	sum := sha256.Sum256(raw)
	report.Hash = hex.EncodeToString(sum[:])
	if err := report.validate(); err != nil {
		return nil, err
	}
	return &report, nil
}

func ValidPackage(name string) bool {
	return packagePattern.MatchString(name)
}

func (r *Report) validate() error {
	seen := make(map[string]struct{}, len(r.Apps))
	for i, app := range r.Apps {
		if !ValidPackage(app.Package) {
			return fmt.Errorf("apps[%d]: invalid package %q", i, app.Package)
		}
		if _, ok := seen[app.Package]; ok {
			return fmt.Errorf("apps[%d]: duplicate package %q", i, app.Package)
		}
		seen[app.Package] = struct{}{}
	}
	return nil
}

func (a App) CategorySlug() string {
	slug, _ := NormalizeCategory(a.Category)
	return slug
}

func (a App) DataTypeSlugs() []string {
	return DataTypesFromLabels(a.DataTypes)
}
