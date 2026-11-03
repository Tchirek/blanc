package render

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/blanc-sh/blanc/internal/audit"
	"github.com/blanc-sh/blanc/internal/engine"
	"github.com/blanc-sh/blanc/internal/policy"
	"gopkg.in/yaml.v3"
)

var fixedTime = time.Date(2026, 11, 4, 0, 0, 0, 0, time.UTC)

func testPlan(t *testing.T, mutate func(*policy.Policy)) *engine.Plan {
	t.Helper()
	report, err := audit.Load("../../testdata/report.json")
	if err != nil {
		t.Fatal(err)
	}
	domains, err := audit.LoadDomains("../../testdata")
	if err != nil {
		t.Fatal(err)
	}
	pol, err := policy.Load("")
	if err != nil {
		t.Fatal(err)
	}
	if mutate != nil {
		mutate(pol)
	}
	plan, err := engine.Compile(report, domains, pol)
	if err != nil {
		t.Fatal(err)
	}
	return plan
}

func renderPlan(t *testing.T, plan *engine.Plan) map[string][]byte {
	t.Helper()
	files, err := All(plan, Options{Version: "test", Commit: "abc", GeneratedAt: fixedTime})
	if err != nil {
		t.Fatal(err)
	}
	return files
}

// 墨を置き
// 紙の上にて
// 影を読む
func TestAllDefault(t *testing.T) {
	plan := testPlan(t, nil)
	files := renderPlan(t, plan)

	if len(files) != 5 {
		t.Fatalf("files = %d", len(files))
	}
	for _, name := range []string{FileMihomo, FileSingbox, FileSingboxRoute, FileManifest, FileSummary} {
		if _, ok := files[name]; !ok {
			t.Fatalf("missing %s", name)
		}
	}
	for _, gone := range []string{"adguard.txt", "hosts.txt", "quarantine.sh", "rollback.sh", "decisions.json"} {
		if _, ok := files[gone]; ok {
			t.Fatalf("unexpected %s", gone)
		}
	}

	var rules []string
	if err := yaml.Unmarshal(files[FileMihomo], &rules); err != nil {
		t.Fatal(err)
	}
	if len(rules) != 5 {
		t.Fatalf("rules = %v", rules)
	}
	for _, rule := range rules {
		if !strings.HasPrefix(rule, "AND,") {
			t.Fatalf("not app-scoped: %q", rule)
		}
	}
	if !containsLine(rules, "AND,((PROCESS-NAME,com.nightmarket.shop),(DOMAIN-SUFFIX,alog.umeng.com)),REJECT") {
		t.Fatalf("missing shop rule: %v", rules)
	}

	var set sourceRuleSet
	if err := json.Unmarshal(files[FileSingbox], &set); err != nil {
		t.Fatal(err)
	}
	if set.Version != 3 || len(set.Rules) != 3 {
		t.Fatalf("singbox = %+v", set)
	}
	if set.Rules[0].PackageName[0] != "cn.mailroom.app" || set.Rules[1].PackageName[0] != "com.nightmarket.shop" {
		t.Fatalf("order = %+v", set.Rules)
	}
	if got := strings.Join(set.Rules[1].Domain, ","); got != "alog.umeng.com,collect.adsight.io,metrics.quietreader.jp" {
		t.Fatalf("shop domains = %q", got)
	}
	if got := strings.Join(set.Rules[1].DomainSuffix, ","); got != ".alog.umeng.com,.collect.adsight.io,.metrics.quietreader.jp" {
		t.Fatalf("shop suffixes = %q", got)
	}

	var fragment routeFragment
	if err := json.Unmarshal(files[FileSingboxRoute], &fragment); err != nil {
		t.Fatal(err)
	}
	if fragment.Route.RuleSet[0].Path != "./blanc-out/singbox.json" || fragment.Route.Rules[0].Action != "reject" {
		t.Fatalf("route = %+v", fragment)
	}

	var m manifest
	if err := json.Unmarshal(files[FileManifest], &m); err != nil {
		t.Fatal(err)
	}
	if m.Tool.Name != "BLANC" || m.Tool.Version != "test" || m.Tool.Commit != "abc" {
		t.Fatalf("tool = %+v", m.Tool)
	}
	if m.GeneratedAt != "2026-11-04T00:00:00Z" || m.ClassificationSource != "noir" {
		t.Fatalf("manifest = %+v", m)
	}
	if m.Stats != plan.Stats || m.Stats.Blocked != 5 || m.Stats.Findings != 16 {
		t.Fatalf("stats = %+v", m.Stats)
	}
	if len(m.Files) != 4 {
		t.Fatalf("file hashes = %d", len(m.Files))
	}
	if _, ok := m.Files[FileManifest]; ok {
		t.Fatal("manifest hash includes itself")
	}
	sum := sha256.Sum256(files[FileMihomo])
	if m.Files[FileMihomo] != hex.EncodeToString(sum[:]) {
		t.Fatal("mihomo hash mismatch")
	}
	if len(m.Inputs.DomainSHA256) != 3 || len(m.Inputs.ReportKeys) == 0 {
		t.Fatalf("inputs = %+v", m.Inputs)
	}
	if !strings.Contains(strings.Join(m.Warnings, " "), "process matching") {
		t.Fatalf("warnings = %v", m.Warnings)
	}

	summary := string(files[FileSummary])
	for _, want := range []string{"## Blocked", "## Review", "## Make it take effect", "GEOSITE,cn", "blanc doctor", "trusted device", "Ignored: 3 (15%)", "not in NOIR domain export ×2"} {
		if !strings.Contains(summary, want) {
			t.Fatalf("summary missing %q:\n%s", want, summary)
		}
	}
}

func TestEmptyPlanWarnings(t *testing.T) {
	report, err := audit.Parse([]byte(`{"device":{"serial":"X","model":"Empty"},"apps":[]}`))
	if err != nil {
		t.Fatal(err)
	}
	domains, err := audit.LoadDomains("../../testdata")
	if err != nil {
		t.Fatal(err)
	}
	pol, err := policy.Load("")
	if err != nil {
		t.Fatal(err)
	}
	plan, err := engine.Compile(report, domains, pol)
	if err != nil {
		t.Fatal(err)
	}
	files := renderPlan(t, plan)

	var rules []string
	if err := yaml.Unmarshal(files[FileMihomo], &rules); err != nil {
		t.Fatal(err)
	}
	if len(rules) != 0 {
		t.Fatalf("rules = %v", rules)
	}
	var set sourceRuleSet
	if err := json.Unmarshal(files[FileSingbox], &set); err != nil {
		t.Fatal(err)
	}
	if set.Rules == nil || len(set.Rules) != 0 {
		t.Fatalf("rules = %#v", set.Rules)
	}
	var m manifest
	if err := json.Unmarshal(files[FileManifest], &m); err != nil {
		t.Fatal(err)
	}
	warnings := strings.Join(m.Warnings, " ")
	for _, want := range []string{"0 apps", "0 endpoints", "No BLANC rules"} {
		if !strings.Contains(warnings, want) {
			t.Fatalf("warnings missing %q: %v", want, m.Warnings)
		}
	}
	if !strings.Contains(string(files[FileSummary]), "No rules were emitted") {
		t.Fatalf("summary:\n%s", files[FileSummary])
	}
}

func TestIgnoredWarning(t *testing.T) {
	plan := testPlan(t, nil)
	plan.Stats.Endpoints = 10
	if !strings.Contains(strings.Join(warnings(plan), " "), "not in the NOIR domain export") {
		t.Fatalf("warnings = %v", warnings(plan))
	}
}

func TestRoutePathOption(t *testing.T) {
	plan := testPlan(t, nil)
	files, err := All(plan, Options{Version: "test", Commit: "abc", GeneratedAt: fixedTime, RuleSetPath: "./custom/singbox.json"})
	if err != nil {
		t.Fatal(err)
	}
	var fragment routeFragment
	if err := json.Unmarshal(files[FileSingboxRoute], &fragment); err != nil {
		t.Fatal(err)
	}
	if fragment.Route.RuleSet[0].Path != "./custom/singbox.json" {
		t.Fatalf("path = %q", fragment.Route.RuleSet[0].Path)
	}
}

func TestDeterministic(t *testing.T) {
	plan := testPlan(t, nil)
	first := renderPlan(t, plan)
	second := renderPlan(t, plan)
	if !reflect.DeepEqual(first, second) {
		t.Fatal("rendered files are not deterministic")
	}
}

func containsLine(lines []string, want string) bool {
	for _, line := range lines {
		if line == want {
			return true
		}
	}
	return false
}
