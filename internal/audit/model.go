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

// 白き紙
// 端末の声
// 聞きとめる
type Report struct {
	Device          Device           `json:"device"`
	Apps            []App            `json:"apps"`
	Recommendations []Recommendation `json:"recommendations"`

	Hash   string `json:"-"`
	Source string `json:"-"`
}

type Device struct {
	Serial string `json:"serial"`
	Model  string `json:"model"`
}

type App struct {
	Package     string              `json:"package"`
	UID         string              `json:"uid"`
	System      bool                `json:"system"`
	Debuggable  bool                `json:"debuggable"`
	Installer   *string             `json:"installer"`
	Category    string              `json:"category"`
	Vendor      *string             `json:"vendor"`
	SharedUID   *string             `json:"sharedUid"`
	DataTypes   []string            `json:"dataTypes"`
	Leaks       map[string][]string `json:"leaks"`
	Score       int                 `json:"score"`
	Permissions []string            `json:"permissions"`
	Endpoints   []string            `json:"endpoints"`
}

type Recommendation struct {
	Package  string `json:"package"`
	Action   string `json:"action"`
	Risk     string `json:"risk"`
	Reason   string `json:"reason"`
	AutoSafe bool   `json:"autoSafe"`
}

var packagePattern = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_]*(\.[A-Za-z][A-Za-z0-9_]*)+$`)

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
	var report Report
	if err := json.Unmarshal(raw, &report); err != nil {
		return nil, err
	}
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
		if !packagePattern.MatchString(app.Package) {
			return fmt.Errorf("apps[%d]: invalid package %q", i, app.Package)
		}
		if _, ok := seen[app.Package]; ok {
			return fmt.Errorf("apps[%d]: duplicate package %q", i, app.Package)
		}
		seen[app.Package] = struct{}{}
		if app.Score < 0 {
			return fmt.Errorf("apps[%d]: negative score", i)
		}
	}
	return nil
}

func (a App) CategorySlug() string {
	slug, _ := NormalizeCategory(a.Category)
	return slug
}

func (a App) DataTypeSlugs() []string {
	out := DataTypesFromLabels(a.DataTypes)
	if len(out) == 0 {
		out = DataTypesFromPermissions(a.Permissions)
	}
	return out
}

func (a App) EndpointHosts() []string {
	set := make(map[string]struct{}, len(a.Endpoints))
	for _, raw := range a.Endpoints {
		ep, err := ParseEndpoint(raw)
		if err != nil {
			continue
		}
		set[ep.Host] = struct{}{}
	}
	out := make([]string, 0, len(set))
	for host := range set {
		out = append(out, host)
	}
	sort.Strings(out)
	return out
}
