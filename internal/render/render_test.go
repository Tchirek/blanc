package render

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"math/rand"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/Tchirek/blanc/internal/audit"
	"github.com/Tchirek/blanc/internal/engine"
	"github.com/Tchirek/blanc/internal/mihomo"
	"github.com/Tchirek/blanc/internal/policy"
	"gopkg.in/yaml.v3"
)

var fixedTime = time.Date(2026, 11, 4, 0, 0, 0, 0, time.UTC)

const examplePolicy = `version: 2
allow: [c.umengcloud.com]
block: [api.nightmarket.cn]
apps:
  jp.quietreader.app: allow
  com.nightmarket.shop:
    allow: [metrics.quietreader.jp]
    block: [cdn.nightmarket.cn]
`

func testPlan(t *testing.T, raw string) *engine.Plan {
	t.Helper()
	report, err := audit.Load("../../testdata/report.json")
	if err != nil {
		t.Fatal(err)
	}
	domains, err := audit.LoadDomains("../../testdata")
	if err != nil {
		t.Fatal(err)
	}
	pol, err := policy.Parse([]byte(raw))
	if err != nil {
		t.Fatal(err)
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

func mihomoLines(t *testing.T, raw []byte) []string {
	t.Helper()
	var rules []string
	if err := yaml.Unmarshal(raw, &rules); err != nil {
		t.Fatal(err)
	}
	return rules
}

// 墨を置き
// 紙の上にて
// 影を読む
func TestAllDefault(t *testing.T) {
	plan := testPlan(t, "version: 2\n")
	files := renderPlan(t, plan)

	if len(files) != 5 {
		t.Fatalf("files = %d", len(files))
	}
	rules := mihomoLines(t, files[FileMihomo])
	want := []string{
		"DOMAIN-SUFFIX,alog.umeng.com,REJECT",
		"DOMAIN-SUFFIX,analytics.vendorwatch.cn,REJECT",
		"DOMAIN-SUFFIX,c.umengcloud.com,REJECT",
		"DOMAIN-SUFFIX,collect.adsight.io,REJECT",
		"DOMAIN-SUFFIX,metrics.quietreader.jp,REJECT",
	}
	if !reflect.DeepEqual(rules, want) {
		t.Fatalf("rules = %#v", rules)
	}

	var set SourceRuleSet
	if err := json.Unmarshal(files[FileSingbox], &set); err != nil {
		t.Fatal(err)
	}
	if set.Version != 3 || len(set.Rules) != 1 || len(set.Rules[0].Domain) != 5 || set.Rules[0].DomainSuffix[0] != ".alog.umeng.com" {
		t.Fatalf("singbox = %+v", set)
	}

	var fragment RouteFragment
	if err := json.Unmarshal(files[FileSingboxRoute], &fragment); err != nil {
		t.Fatal(err)
	}
	if fragment.Route.RuleSet[0].Path != "./blanc-out/singbox.json" ||
		fragment.Route.Rules[0].Action != "sniff" || fragment.Route.Rules[1].Action != "reject" || fragment.Route.Rules[1].RuleSet != SingboxTag {
		t.Fatalf("route = %+v", fragment)
	}

	var m Manifest
	if err := json.Unmarshal(files[FileManifest], &m); err != nil {
		t.Fatal(err)
	}
	if m.Tool.Name != "BLANC" || m.Tool.Version != "test" || m.Tool.Commit != "abc" || m.GeneratedAt != "2026-11-04T00:00:00Z" {
		t.Fatalf("manifest = %+v", m)
	}
	if m.Stats != plan.Stats || len(m.Rules) != 5 || m.Rules[0].Mihomo != want[0] {
		t.Fatalf("manifest stats/rules = %+v %+v", m.Stats, m.Rules)
	}
	if len(m.Files) != 4 {
		t.Fatalf("file hashes = %d", len(m.Files))
	}
	sum := sha256.Sum256(files[FileMihomo])
	if m.Files[FileMihomo] != hex.EncodeToString(sum[:]) {
		t.Fatal("mihomo hash mismatch")
	}
	if len(m.Inputs.DomainSHA256) != 3 || len(m.Inputs.ReportKeys) == 0 {
		t.Fatalf("inputs = %+v", m.Inputs)
	}

	summary := string(files[FileSummary])
	for _, want := range []string{
		"5 rules (5 for every app, 0 app-only)", "| `metrics.quietreader.jp` | every app | — | NOIR tracker |",
		"`com.nightmarket.shop`, `jp.quietreader.app`", "Review hosts (not blocked)", "`api.nightmarket.cn`",
		"parse-pure-ip", "after a `{\"action\": \"sniff\"}` rule", "blanc explain", "trusted device",
	} {
		if !strings.Contains(summary, want) {
			t.Fatalf("summary missing %q:\n%s", want, summary)
		}
	}
	if strings.Contains(summary, "find-process-mode") {
		t.Fatal("no app-scoped rules, so process matching must not be demanded")
	}
}

// 例外の
// 書きぶり確かに
// 一字ずつ
func TestExceptionsRender(t *testing.T) {
	plan := testPlan(t, examplePolicy)
	files := renderPlan(t, plan)
	rules := mihomoLines(t, files[FileMihomo])
	for _, want := range []string{
		"AND,((DOMAIN-SUFFIX,api.nightmarket.cn),(NOT,((PROCESS-NAME,jp.quietreader.app)))),REJECT",
		"AND,((DOMAIN-SUFFIX,metrics.quietreader.jp),(NOT,((PROCESS-NAME,com.nightmarket.shop))),(NOT,((PROCESS-NAME,jp.quietreader.app)))),REJECT",
		"AND,((DOMAIN-SUFFIX,cdn.nightmarket.cn),(PROCESS-NAME,com.nightmarket.shop)),REJECT",
	} {
		found := false
		for _, rule := range rules {
			found = found || rule == want
		}
		if !found {
			t.Fatalf("missing %s in\n%s", want, strings.Join(rules, "\n"))
		}
	}
	for _, rule := range rules {
		if strings.Contains(rule, "c.umengcloud.com") {
			t.Fatalf("allowed host rendered: %s", rule)
		}
	}
	if !strings.Contains(string(files[FileSummary]), "find-process-mode") {
		t.Fatal("app-scoped rules need the process-matching hint")
	}
}

// 写し絵の
// 網も掟と
// 寸分違わず
func TestRenderedRulesAgreeWithEngine(t *testing.T) {
	rng := rand.New(rand.NewSource(1104))
	pool := []string{"a.cn", "x.a.cn", "y.x.a.cn", "z.y.x.a.cn", "w.a.cn", "b.cn", "x.b.cn", "y.x.b.cn"}
	packages := []string{"com.p.one", "com.p.two", "com.p.three"}
	probes := append([]string{"", "com.other.app"}, packages...)

	for round := 0; round < 1500; round++ {
		domains := &audit.DomainSet{Classes: map[string]audit.DomainClass{}}
		classes := []audit.DomainClass{audit.ClassTracker, audit.ClassTracker, audit.ClassFunctional, audit.ClassReview}
		for _, host := range pool {
			if rng.Intn(3) == 0 {
				domains.Classes[host] = classes[rng.Intn(len(classes))]
			}
		}
		pol := policy.Default()
		pol.Allow, pol.Block = randomLists(rng, pool)
		for _, pkg := range packages {
			if rng.Intn(3) == 0 {
				continue
			}
			allow, block := randomLists(rng, pool)
			app := policy.App{AllowAll: rng.Intn(5) == 0, Block: block}
			if !app.AllowAll {
				app.Allow = allow
			}
			pol.Apps[pkg] = app
		}
		plan, err := engine.Compile(nil, domains, pol)
		if err != nil {
			t.Fatal(err)
		}
		files := renderPlan(t, plan)
		parsed := make([]*mihomo.Rule, 0)
		for _, line := range mihomoLines(t, files[FileMihomo]) {
			rule, err := mihomo.ParseLine(line)
			if err != nil {
				t.Fatalf("unparseable rule %q: %v", line, err)
			}
			parsed = append(parsed, rule)
		}
		var set SourceRuleSet
		if err := json.Unmarshal(files[FileSingbox], &set); err != nil {
			t.Fatal(err)
		}

		for _, host := range pool {
			for _, probe := range []string{host, "deep." + host} {
				for _, pkg := range probes {
					want := plan.Explain(pkg, probe).Blocked()
					gotMihomo := false
					for _, rule := range parsed {
						matched, known := rule.Match(mihomo.Metadata{Host: probe, Process: pkg})
						if !known {
							t.Fatalf("rendered rule uses an unknown type: %+v", rule)
						}
						gotMihomo = gotMihomo || matched
					}
					gotSingbox := false
					for _, rule := range set.Rules {
						gotSingbox = gotSingbox || singboxMatch(rule, pkg, probe)
					}
					if gotMihomo != want || gotSingbox != want {
						t.Fatalf("round %d pkg=%q host=%q: engine=%v mihomo=%v singbox=%v\n%s\n%s",
							round, pkg, probe, want, gotMihomo, gotSingbox, files[FileMihomo], files[FileSingbox])
					}
				}
			}
		}
	}
}

// 異国の
// 網の掟を
// 写し読む
func singboxMatch(rule Headless, pkg, host string) bool {
	var matched bool
	if rule.Type == "logical" {
		matched = rule.Mode == "and"
		for _, sub := range rule.Rules {
			if rule.Mode == "and" {
				matched = matched && singboxMatch(sub, pkg, host)
			} else {
				matched = matched || singboxMatch(sub, pkg, host)
			}
		}
	} else {
		matched = true
		if len(rule.Domain) > 0 || len(rule.DomainSuffix) > 0 {
			domainHit := false
			for _, domain := range rule.Domain {
				domainHit = domainHit || host == domain
			}
			for _, suffix := range rule.DomainSuffix {
				domainHit = domainHit || strings.HasSuffix(host, suffix)
			}
			matched = domainHit
		}
		if len(rule.PackageName) > 0 {
			pkgHit := false
			for _, name := range rule.PackageName {
				pkgHit = pkgHit || (pkg != "" && pkg == name)
			}
			matched = matched && pkgHit
		}
	}
	if rule.Invert {
		return !matched
	}
	return matched
}

func randomLists(rng *rand.Rand, pool []string) ([]string, []string) {
	var allow, block []string
	for _, host := range pool {
		switch rng.Intn(9) {
		case 0:
			allow = append(allow, host)
		case 1:
			block = append(block, host)
		}
	}
	return allow, block
}

func TestEmptyPlan(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"domains-trackers.txt", "domains-functional.txt", "domains-other.txt"} {
		writeFile(t, dir, name, "# empty\n")
	}
	domains, err := audit.LoadDomains(dir)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := engine.Compile(nil, domains, policy.Default())
	if err != nil {
		t.Fatal(err)
	}
	files := renderPlan(t, plan)
	if rules := mihomoLines(t, files[FileMihomo]); len(rules) != 0 {
		t.Fatalf("rules = %v", rules)
	}
	var set SourceRuleSet
	if err := json.Unmarshal(files[FileSingbox], &set); err != nil {
		t.Fatal(err)
	}
	if set.Rules == nil || len(set.Rules) != 0 {
		t.Fatalf("rules = %#v", set.Rules)
	}
	if !strings.Contains(string(files[FileSingbox]), `"rules": []`) {
		t.Fatalf("empty rule set must stay a list:\n%s", files[FileSingbox])
	}
	summary := string(files[FileSummary])
	if !strings.Contains(summary, "No rules.") || !strings.Contains(summary, "no NOIR report") {
		t.Fatalf("summary:\n%s", summary)
	}
}

func TestRoutePathOption(t *testing.T) {
	plan := testPlan(t, "version: 2\n")
	files, err := All(plan, Options{Version: "test", Commit: "abc", GeneratedAt: fixedTime, RuleSetPath: "./custom/singbox.json"})
	if err != nil {
		t.Fatal(err)
	}
	var fragment RouteFragment
	if err := json.Unmarshal(files[FileSingboxRoute], &fragment); err != nil {
		t.Fatal(err)
	}
	if fragment.Route.RuleSet[0].Path != "./custom/singbox.json" {
		t.Fatalf("path = %q", fragment.Route.RuleSet[0].Path)
	}
}

func TestDeterministic(t *testing.T) {
	plan := testPlan(t, examplePolicy)
	if !reflect.DeepEqual(renderPlan(t, plan), renderPlan(t, plan)) {
		t.Fatal("rendered files are not deterministic")
	}
}

func writeFile(t *testing.T, dir, name, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}
