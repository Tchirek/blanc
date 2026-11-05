package engine

import (
	"fmt"
	"math/rand"
	"strings"
	"testing"

	"github.com/Tchirek/blanc/internal/audit"
	"github.com/Tchirek/blanc/internal/policy"
)

// 灯をともし
// 影の行方を
// 数えけり
func fixture(t *testing.T) (*audit.Report, *audit.DomainSet) {
	t.Helper()
	report, err := audit.Load("../../testdata/report.json")
	if err != nil {
		t.Fatal(err)
	}
	domains, err := audit.LoadDomains("../../testdata")
	if err != nil {
		t.Fatal(err)
	}
	return report, domains
}

func compileWith(t *testing.T, raw string) *Plan {
	t.Helper()
	report, domains := fixture(t)
	pol, err := policy.Parse([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	plan, err := Compile(report, domains, pol)
	if err != nil {
		t.Fatal(err)
	}
	return plan
}

func mustFind(t *testing.T, plan *Plan, pkg, domain string) Finding {
	t.Helper()
	finding, ok := plan.Find(pkg, domain)
	if !ok {
		t.Fatalf("finding %s|%s not found", pkg, domain)
	}
	return finding
}

func ruleFor(t *testing.T, plan *Plan, pkg, domain string) Rule {
	t.Helper()
	for _, rule := range plan.Rules {
		if rule.Package == pkg && rule.Domain == domain {
			return rule
		}
	}
	t.Fatalf("rule %q|%q not found in %+v", pkg, domain, plan.Rules)
	return Rule{}
}

// 全ての窓
// 同じ網にて
// 塞ぎけり
func TestDefaultBlocksEveryTrackerForEveryApp(t *testing.T) {
	plan := compileWith(t, "version: 2\n")
	got := make([]string, 0)
	for _, rule := range plan.Rules {
		if rule.Package != "" || len(rule.Except) != 0 || rule.Source != SourceNoirTracker {
			t.Fatalf("unexpected rule %+v", rule)
		}
		got = append(got, rule.Domain)
	}
	want := "alog.umeng.com,analytics.vendorwatch.cn,c.umengcloud.com,collect.adsight.io,metrics.quietreader.jp"
	if strings.Join(got, ",") != want {
		t.Fatalf("rules = %s", strings.Join(got, ","))
	}

	reader := mustFind(t, plan, "jp.quietreader.app", "metrics.quietreader.jp")
	if !reader.Blocked() || reader.Reason != "NOIR tracker metrics.quietreader.jp" {
		t.Fatalf("the reader's own telemetry must be blocked: %+v", reader)
	}
	if got := plan.Explain("com.never.scanned", "alog.umeng.com"); !got.Blocked() {
		t.Fatalf("unscanned apps must be covered too: %+v", got)
	}
	if got := plan.Explain("", "sub.alog.umeng.com"); !got.Blocked() || got.Match != "alog.umeng.com" {
		t.Fatalf("subdomains must follow the tracker: %+v", got)
	}
	login := mustFind(t, plan, "com.nightmarket.shop", "login.nightpass.cn")
	if login.Blocked() || login.Class != audit.ClassFunctional {
		t.Fatalf("login = %+v", login)
	}
	api := mustFind(t, plan, "com.nightmarket.shop", "api.nightmarket.cn")
	if api.Blocked() || api.Reason != "NOIR review api.nightmarket.cn" {
		t.Fatalf("api = %+v", api)
	}

	want2 := Stats{
		Apps: 5, Endpoints: 20, EndpointsOutside: 3,
		Trackers: 5, Functional: 5, Review: 5,
		Rules: 5, GlobalRules: 5,
		Findings: 16, BlockedFindings: 6, AllowedFindings: 10,
	}
	if plan.Stats != want2 {
		t.Fatalf("stats = %+v\nwant    %+v", plan.Stats, want2)
	}
}

// 例外は
// 網の目に入れ
// 外さずに
func TestExceptionsAreFoldedIntoRules(t *testing.T) {
	plan := compileWith(t, `version: 2
allow: [c.umengcloud.com]
block: [api.nightmarket.cn]
apps:
  jp.quietreader.app: allow
  com.nightmarket.shop:
    allow: [metrics.quietreader.jp]
    block: [cdn.nightmarket.cn]
`)
	for _, rule := range plan.Rules {
		if rule.Domain == "c.umengcloud.com" {
			t.Fatalf("globally allowed tracker still has a rule: %+v", rule)
		}
	}
	metrics := ruleFor(t, plan, "", "metrics.quietreader.jp")
	if fmt.Sprint(metrics.Except) != "[{com.nightmarket.shop } {jp.quietreader.app }]" {
		t.Fatalf("metrics except = %+v", metrics.Except)
	}
	if !metrics.Matches("cn.mailroom.app", "metrics.quietreader.jp") || metrics.Matches("jp.quietreader.app", "metrics.quietreader.jp") {
		t.Fatal("metrics rule semantics")
	}
	api := ruleFor(t, plan, "", "api.nightmarket.cn")
	if api.Source != SourceGlobalBlock || len(api.Except) != 1 || api.Except[0].Package != "jp.quietreader.app" {
		t.Fatalf("api = %+v", api)
	}
	cdn := ruleFor(t, plan, "com.nightmarket.shop", "cdn.nightmarket.cn")
	if cdn.Source != SourceAppBlock || len(cdn.Except) != 0 {
		t.Fatalf("cdn = %+v", cdn)
	}
	if got := plan.Explain("jp.quietreader.app", "alog.umeng.com"); got.Blocked() || got.Reason != "app allow all" {
		t.Fatalf("allow-all = %+v", got)
	}
	if got := plan.Explain("com.nightmarket.shop", "api.nightmarket.cn"); !got.Blocked() || got.Tier != TierGlobal {
		t.Fatalf("global block = %+v", got)
	}
}

// 同じ戸の
// 名には鍵をば
// 掛けぬなり
func TestSharedUIDEntriesAreSkipped(t *testing.T) {
	plan := compileWith(t, `version: 2
apps:
  com.vendorwatch.telemetry:
    block: [api.vendorwatch.cn]
  com.typo.app: allow
`)
	if _, ok := plan.Skipped["com.vendorwatch.telemetry"]; !ok {
		t.Fatalf("skipped = %+v", plan.Skipped)
	}
	for _, rule := range plan.Rules {
		if rule.Package == "com.vendorwatch.telemetry" {
			t.Fatalf("shared-UID rule emitted: %+v", rule)
		}
	}
	notes := fmt.Sprint(plan.Notes)
	for _, want := range []string{"shares UID 1000", "android.uid.system", "global allow/block", "com.typo.app", "not in the NOIR report"} {
		if !strings.Contains(notes, want) {
			t.Fatalf("notes lack %q: %s", want, notes)
		}
	}
	if plan.Notes[0].Level != LevelWarn {
		t.Fatalf("warnings must come first: %+v", plan.Notes)
	}
	if got := ruleFor(t, plan, "", "metrics.quietreader.jp"); len(got.Except) != 1 || got.Except[0].Package != "com.typo.app" {
		t.Fatalf("typo package still gets its exception: %+v", got)
	}
}

func TestEntryNotes(t *testing.T) {
	plan := compileWith(t, `version: 2
allow: [nothing.example.cn]
block: [login.nightpass.cn]
apps:
  com.nightmarket.shop:
    allow: [other.example.cn]
`)
	notes := fmt.Sprint(plan.Notes)
	for _, want := range []string{"allow nothing.example.cn", "no effect", "block login.nightpass.cn", "may break", "other.example.cn"} {
		if !strings.Contains(notes, want) {
			t.Fatalf("notes lack %q: %s", want, notes)
		}
	}
}

func TestCompileWithoutReport(t *testing.T) {
	_, domains := fixture(t)
	pol, err := policy.Parse([]byte("version: 2\napps:\n  com.a.b: allow\n"))
	if err != nil {
		t.Fatal(err)
	}
	plan, err := Compile(nil, domains, pol)
	if err != nil {
		t.Fatal(err)
	}
	if plan.HasReport || len(plan.Findings) != 0 || len(plan.Rules) != 5 {
		t.Fatalf("plan = %+v", plan)
	}
	if !strings.Contains(fmt.Sprint(plan.Notes), "shared-UID") {
		t.Fatalf("notes = %+v", plan.Notes)
	}
}

// 網と掟
// 千の問いにも
// 食い違わず
func TestRulesAgreeWithDecisions(t *testing.T) {
	rng := rand.New(rand.NewSource(20261104))
	pool := hostPool()
	packages := []string{"com.p.one", "com.p.two", "com.p.three"}
	probes := append([]string{"com.other.app", ""}, packages...)

	for round := 0; round < 4000; round++ {
		domains := &audit.DomainSet{Classes: map[string]audit.DomainClass{}}
		classes := []audit.DomainClass{audit.ClassTracker, audit.ClassTracker, audit.ClassFunctional, audit.ClassReview}
		for _, host := range pick(rng, pool, rng.Intn(10)) {
			domains.Classes[host] = classes[rng.Intn(len(classes))]
		}
		pol := policy.Default()
		pol.Allow, pol.Block = split(rng, pick(rng, pool, rng.Intn(5)))
		for _, pkg := range packages {
			if rng.Intn(3) == 0 {
				continue
			}
			app := policy.App{AllowAll: rng.Intn(5) == 0}
			allow, block := split(rng, pick(rng, pool, rng.Intn(5)))
			if !app.AllowAll {
				app.Allow = allow
			}
			app.Block = block
			pol.Apps[pkg] = app
		}
		skipped := map[string]string{}
		if rng.Intn(4) == 0 {
			skipped[packages[rng.Intn(len(packages))]] = "shared"
		}

		decider := NewDecider(pol, domains, skipped)
		rules := decider.Rules()
		for _, host := range pool {
			for _, probe := range []string{host, "deep." + host} {
				for _, pkg := range probes {
					want := decider.Decide(pkg, probe).Blocked()
					got := false
					for _, rule := range rules {
						if rule.Matches(pkg, probe) {
							got = true
							break
						}
					}
					if got != want {
						t.Fatalf("round %d: pkg=%q host=%q rules say %v, decision says %v (%s)\nnoir=%v\npolicy allow=%v block=%v apps=%+v skipped=%v\nrules=%+v",
							round, pkg, probe, got, want, decider.Decide(pkg, probe).Reason,
							domains.Classes, pol.Allow, pol.Block, pol.Apps, skipped, rules)
					}
				}
			}
		}
	}
}

func hostPool() []string {
	out := make([]string, 0)
	labels := []string{"x", "y"}
	var grow func(host string, depth int)
	grow = func(host string, depth int) {
		out = append(out, host)
		if depth == 3 {
			return
		}
		for _, label := range labels {
			grow(label+"."+host, depth+1)
		}
	}
	grow("a.cn", 0)
	grow("b.cn", 1)
	return out
}

func pick(rng *rand.Rand, pool []string, n int) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, n)
	for len(out) < n {
		host := pool[rng.Intn(len(pool))]
		if _, ok := seen[host]; ok {
			continue
		}
		seen[host] = struct{}{}
		out = append(out, host)
	}
	return out
}

func split(rng *rand.Rand, hosts []string) ([]string, []string) {
	var allow, block []string
	for _, host := range hosts {
		if rng.Intn(2) == 0 {
			allow = append(allow, host)
		} else {
			block = append(block, host)
		}
	}
	return allow, block
}
