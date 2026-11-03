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

func testPlan(t *testing.T, mutate func(*policy.Policy), decisions map[string]engine.Verdict) *engine.Plan {
	t.Helper()
	report, err := audit.Load("../../testdata/report.json")
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
	plan, err := engine.Compile(report, pol, engine.Options{Overrides: decisions})
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
	plan := testPlan(t, nil, nil)
	files := renderPlan(t, plan)

	if len(files) != 16 {
		t.Fatalf("files = %d", len(files))
	}
	for _, name := range []string{
		FileSingbox, FileSingboxRoute, FileMihomoRules, FileMihomoProvider,
		FileAdGuard, FileHosts, FileGlobalDomains, FileBlockedDomains,
		FileReviewDomains, FileReviewEndpoints, FileSummary, FileManifest,
		FileQuarantinePlan, FileQuarantineScript, FileRollbackScript, FileDecisions,
	} {
		if _, ok := files[name]; !ok {
			t.Fatalf("missing %s", name)
		}
	}

	var set sourceRuleSet
	if err := json.Unmarshal(files[FileSingbox], &set); err != nil {
		t.Fatal(err)
	}
	if set.Version != 3 || len(set.Rules) != 3 {
		t.Fatalf("singbox = %+v", set)
	}
	if set.Rules[0].PackageName[0] != "cn.mailroom.app" || set.Rules[1].PackageName[0] != "com.nightmarket.shop" {
		t.Fatalf("singbox order = %+v", set.Rules)
	}
	if got := strings.Join(set.Rules[1].Domain, ","); got != "alog.umeng.com,collect.adsight.io,metrics.quietreader.jp" {
		t.Fatalf("shop domains = %q", got)
	}
	if got := strings.Join(set.Rules[1].DomainSuffix, ","); got != ".alog.umeng.com,.collect.adsight.io,.metrics.quietreader.jp" {
		t.Fatalf("shop suffixes = %q", got)
	}

	var rules []string
	if err := yaml.Unmarshal(files[FileMihomoRules], &rules); err != nil {
		t.Fatal(err)
	}
	if len(rules) != 5 {
		t.Fatalf("mihomo rules = %d: %v", len(rules), rules)
	}
	if !containsLine(rules, "AND,((PROCESS-NAME,com.nightmarket.shop),(DOMAIN-SUFFIX,alog.umeng.com)),REJECT") {
		t.Fatalf("missing shop rule: %v", rules)
	}

	var provider struct {
		Payload []string `yaml:"payload"`
	}
	if err := yaml.Unmarshal(files[FileMihomoProvider], &provider); err != nil {
		t.Fatal(err)
	}
	if len(provider.Payload) != 0 {
		t.Fatalf("provider payload = %v", provider.Payload)
	}

	if strings.Contains(string(files[FileAdGuard]), "||") || strings.Contains(string(files[FileHosts]), "0.0.0.0") {
		t.Fatal("default DNS lists should contain no domains")
	}
	if string(files[FileGlobalDomains]) != "" {
		t.Fatalf("global domains = %q", files[FileGlobalDomains])
	}
	if got := countLines(files[FileBlockedDomains]); got != 5 {
		t.Fatalf("blocked domains = %d\n%s", got, files[FileBlockedDomains])
	}
	if got := strings.TrimSpace(string(files[FileReviewDomains])); got != "metrics.quietreader.jp" {
		t.Fatalf("review domains = %q", got)
	}
	reviewEndpoints := string(files[FileReviewEndpoints])
	if !strings.Contains(reviewEndpoints, "com.nightmarket.shop\tapi.nightmarket.cn\treview\tcollect") {
		t.Fatalf("review endpoints:\n%s", reviewEndpoints)
	}

	summary := string(files[FileSummary])
	if !strings.Contains(summary, "com.nightmarket.shop") ||
		!strings.Contains(summary, "Quarantine candidates") ||
		!strings.Contains(summary, "A blocked URL is not privacy") {
		t.Fatalf("summary:\n%s", summary)
	}

	var m manifest
	if err := json.Unmarshal(files[FileManifest], &m); err != nil {
		t.Fatal(err)
	}
	if m.Tool.Name != "BLANC" || m.Tool.Version != "test" || m.Tool.Commit != "abc" {
		t.Fatalf("tool = %+v", m.Tool)
	}
	if m.GeneratedAt != "2026-11-04T00:00:00Z" {
		t.Fatalf("generated at = %q", m.GeneratedAt)
	}
	if m.Stats != plan.Stats {
		t.Fatalf("stats = %+v", m.Stats)
	}
	if len(m.Files) != 15 {
		t.Fatalf("file hashes = %d", len(m.Files))
	}
	if _, ok := m.Files[FileManifest]; ok {
		t.Fatal("manifest hash includes itself")
	}
	sum := sha256.Sum256(files[FileSingbox])
	if m.Files[FileSingbox] != hex.EncodeToString(sum[:]) {
		t.Fatal("singbox hash mismatch")
	}
	if !strings.Contains(strings.Join(m.Warnings, " "), "vendor-preinstalled") {
		t.Fatalf("warnings = %v", m.Warnings)
	}

	var qp quarantinePlan
	if err := json.Unmarshal(files[FileQuarantinePlan], &qp); err != nil {
		t.Fatal(err)
	}
	if len(qp.Targets) != 2 {
		t.Fatalf("quarantine targets = %+v", qp.Targets)
	}
	if qp.Targets[0].Package != "cn.mailroom.app" {
		t.Fatalf("quarantine order = %+v", qp.Targets)
	}
	if !containsLine(qp.Targets[0].Commands, "cmd netpolicy add restrict-background-blacklist 10103") {
		t.Fatalf("quarantine commands = %v", qp.Targets[0].Commands)
	}
	if !containsLine(qp.Targets[0].Rollback, "cmd netpolicy remove restrict-background-blacklist 10103") {
		t.Fatalf("quarantine rollback = %v", qp.Targets[0].Rollback)
	}
	script := string(files[FileQuarantineScript])
	if !strings.Contains(script, "#!/usr/bin/env sh") ||
		!strings.Contains(script, "adb -s \"$serial\" shell 'cmd netpolicy add restrict-background-blacklist 10103'") {
		t.Fatalf("quarantine script:\n%s", script)
	}
	rollback := string(files[FileRollbackScript])
	if !strings.Contains(rollback, "adb -s \"$serial\" shell 'cmd netpolicy remove restrict-background-blacklist 10103'") {
		t.Fatalf("rollback script:\n%s", rollback)
	}
	if Mode(FileQuarantineScript) != 0o755 || Mode(FileSingbox) != 0o644 {
		t.Fatal("unexpected file modes")
	}

	var dec decisionsFile
	if err := json.Unmarshal(files[FileDecisions], &dec); err != nil {
		t.Fatal(err)
	}
	if dec.Version != 1 || len(dec.Decisions) != 0 {
		t.Fatalf("decisions = %+v", dec)
	}
}

func TestAllGlobalized(t *testing.T) {
	plan := testPlan(t, func(p *policy.Policy) {
		p.Compile.Globalize = "trackers"
	}, nil)
	files := renderPlan(t, plan)

	var set sourceRuleSet
	if err := json.Unmarshal(files[FileSingbox], &set); err != nil {
		t.Fatal(err)
	}
	if len(set.Rules) != 1 || len(set.Rules[0].PackageName) != 0 || len(set.Rules[0].Domain) != 5 || len(set.Rules[0].DomainSuffix) != 5 {
		t.Fatalf("singbox = %+v", set)
	}

	var rules []string
	if err := yaml.Unmarshal(files[FileMihomoRules], &rules); err != nil {
		t.Fatal(err)
	}
	if len(rules) != 5 {
		t.Fatalf("rules = %v", rules)
	}
	for _, rule := range rules {
		if !strings.HasPrefix(rule, "DOMAIN-SUFFIX,") {
			t.Fatalf("not a global rule: %q", rule)
		}
	}

	var provider struct {
		Payload []string `yaml:"payload"`
	}
	if err := yaml.Unmarshal(files[FileMihomoProvider], &provider); err != nil {
		t.Fatal(err)
	}
	if len(provider.Payload) != 5 {
		t.Fatalf("provider = %v", provider.Payload)
	}
	if got := countLines(files[FileHosts]) - 3; got != 5 {
		t.Fatalf("hosts domains = %d\n%s", got, files[FileHosts])
	}
	if got := countLines(files[FileAdGuard]) - 3; got != 5 {
		t.Fatalf("adguard domains = %d\n%s", got, files[FileAdGuard])
	}
	if got := countLines(files[FileGlobalDomains]); got != 5 {
		t.Fatalf("global domains = %d", got)
	}

	var m manifest
	if err := json.Unmarshal(files[FileManifest], &m); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.Join(m.Warnings, " "), "app scope is lost") {
		t.Fatalf("warnings = %v", m.Warnings)
	}
}

func TestQuarantinePlanFlags(t *testing.T) {
	plan := testPlan(t, func(p *policy.Policy) {
		p.Quarantine.AppOpsBackground = true
		p.Quarantine.BackgroundRestrict = false
	}, nil)
	files := renderPlan(t, plan)
	var qp quarantinePlan
	if err := json.Unmarshal(files[FileQuarantinePlan], &qp); err != nil {
		t.Fatal(err)
	}
	for _, command := range qp.Targets[0].Commands {
		if strings.Contains(command, "netpolicy") {
			t.Fatalf("unexpected netpolicy command: %v", qp.Targets[0].Commands)
		}
	}
	if !containsLine(qp.Targets[0].Commands, "cmd appops set cn.mailroom.app RUN_IN_BACKGROUND ignore") {
		t.Fatalf("commands = %v", qp.Targets[0].Commands)
	}
	if !containsLine(qp.Targets[0].Rollback, "cmd appops set cn.mailroom.app RUN_IN_BACKGROUND default") {
		t.Fatalf("rollback = %v", qp.Targets[0].Rollback)
	}
}

func TestScriptSerialSafety(t *testing.T) {
	plan := testPlan(t, nil, nil)
	plan.Device.Serial = `bad";rm -rf /`
	files := renderPlan(t, plan)
	script := string(files[FileQuarantineScript])
	if strings.Contains(script, "bad") || !strings.Contains(script, "BLANC_SERIAL") {
		t.Fatalf("unsafe serial was embedded:\n%s", script)
	}
}

func TestEmptyScripts(t *testing.T) {
	report, err := audit.Parse([]byte(`{"device":{"serial":"X","model":"Empty"},"apps":[]}`))
	if err != nil {
		t.Fatal(err)
	}
	pol, err := policy.Load("")
	if err != nil {
		t.Fatal(err)
	}
	plan, err := engine.Compile(report, pol, engine.Options{})
	if err != nil {
		t.Fatal(err)
	}
	files := renderPlan(t, plan)
	if !strings.Contains(string(files[FileQuarantineScript]), "no quarantine targets") {
		t.Fatalf("script:\n%s", files[FileQuarantineScript])
	}
	if !strings.Contains(string(files[FileRollbackScript]), "nothing to roll back") {
		t.Fatalf("script:\n%s", files[FileRollbackScript])
	}
}

func TestDecisionsFlow(t *testing.T) {
	decisions := map[string]engine.Verdict{
		"com.nightmarket.shop|alog.umeng.com":   engine.VerdictAllow,
		"jp.quietreader.app|api.quietreader.jp": engine.VerdictBlock,
	}
	plan := testPlan(t, nil, decisions)
	files := renderPlan(t, plan)

	var set sourceRuleSet
	if err := json.Unmarshal(files[FileSingbox], &set); err != nil {
		t.Fatal(err)
	}
	if len(set.Rules) != 4 {
		t.Fatalf("rules = %+v", set.Rules)
	}
	shop := set.Rules[1]
	if got := strings.Join(shop.Domain, ","); got != "collect.adsight.io,metrics.quietreader.jp" {
		t.Fatalf("shop domains = %q", got)
	}
	if set.Rules[0].PackageName[0] != "cn.mailroom.app" || set.Rules[3].PackageName[0] != "jp.quietreader.app" {
		t.Fatalf("order = %+v", set.Rules)
	}

	var dec decisionsFile
	if err := json.Unmarshal(files[FileDecisions], &dec); err != nil {
		t.Fatal(err)
	}
	if len(dec.Decisions) != 2 || dec.Decisions["com.nightmarket.shop|alog.umeng.com"] != engine.VerdictAllow {
		t.Fatalf("decisions = %+v", dec.Decisions)
	}
}

func TestEmptyReport(t *testing.T) {
	report, err := audit.Parse([]byte(`{"device":{"serial":"X","model":"Empty"},"apps":[]}`))
	if err != nil {
		t.Fatal(err)
	}
	pol, err := policy.Load("")
	if err != nil {
		t.Fatal(err)
	}
	plan, err := engine.Compile(report, pol, engine.Options{})
	if err != nil {
		t.Fatal(err)
	}
	files := renderPlan(t, plan)

	var set sourceRuleSet
	if err := json.Unmarshal(files[FileSingbox], &set); err != nil {
		t.Fatal(err)
	}
	if set.Rules == nil || len(set.Rules) != 0 {
		t.Fatalf("rules = %#v", set.Rules)
	}
	var rules []string
	if err := yaml.Unmarshal(files[FileMihomoRules], &rules); err != nil {
		t.Fatal(err)
	}
	if len(rules) != 0 {
		t.Fatalf("rules = %v", rules)
	}
	if string(files[FileBlockedDomains]) != "" {
		t.Fatalf("blocked = %q", files[FileBlockedDomains])
	}
	var qp quarantinePlan
	if err := json.Unmarshal(files[FileQuarantinePlan], &qp); err != nil {
		t.Fatal(err)
	}
	if qp.Targets == nil || len(qp.Targets) != 0 {
		t.Fatalf("targets = %#v", qp.Targets)
	}
}

func TestDeterministic(t *testing.T) {
	plan := testPlan(t, nil, nil)
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

func countLines(raw []byte) int {
	text := strings.TrimSuffix(string(raw), "\n")
	if text == "" {
		return 0
	}
	return len(strings.Split(text, "\n"))
}
