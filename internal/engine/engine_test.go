package engine

import (
	"testing"

	"github.com/blanc-sh/blanc/internal/audit"
	"github.com/blanc-sh/blanc/internal/policy"
)

// 灯をともし
// 影の行方を
// 数えけり
func fixture(t *testing.T) (*audit.Report, *policy.Policy) {
	t.Helper()
	report, err := audit.Load("../../testdata/report.json")
	if err != nil {
		t.Fatal(err)
	}
	pol, err := policy.Load("")
	if err != nil {
		t.Fatal(err)
	}
	return report, pol
}

func compileFixture(t *testing.T, mutate func(*policy.Policy)) *Plan {
	t.Helper()
	report, pol := fixture(t)
	if mutate != nil {
		mutate(pol)
	}
	plan, err := Compile(report, pol, Options{})
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

func TestCompileDefault(t *testing.T) {
	plan := compileFixture(t, nil)
	want := Stats{
		Apps:              5,
		Findings:          16,
		Blocked:           5,
		Scoped:            5,
		Global:            0,
		Review:            6,
		Allowed:           5,
		AppsWithBlocks:    3,
		UniqueDomains:     15,
		BlockedDomains:    5,
		GlobalDomains:     0,
		Ignored:           3,
		Quarantine:        2,
		QuarantineSkipped: 1,
	}
	if plan.Stats != want {
		t.Fatalf("stats = %+v, want %+v", plan.Stats, want)
	}

	alog := mustFind(t, plan, "com.nightmarket.shop", "alog.umeng.com")
	if !alog.Blocked() || alog.Global() || !alog.Sensitive || alog.Reason != "tracker + data:location" {
		t.Fatalf("alog = %+v", alog)
	}
	login := mustFind(t, plan, "com.nightmarket.shop", "login.nightpass.cn")
	if login.Verdict != VerdictAllow || login.Class != audit.ClassFunctional {
		t.Fatalf("login = %+v", login)
	}
	api := mustFind(t, plan, "com.nightmarket.shop", "api.nightmarket.cn")
	if api.Verdict != VerdictReview || api.Class != audit.ClassReview {
		t.Fatalf("api = %+v", api)
	}
	reader := mustFind(t, plan, "jp.quietreader.app", "metrics.quietreader.jp")
	if reader.Verdict != VerdictReview || reader.Reason != "tracker without sensitive signal" {
		t.Fatalf("reader = %+v", reader)
	}
	vendor := mustFind(t, plan, "com.vendorwatch.telemetry", "analytics.vendorwatch.cn")
	if !vendor.Blocked() || vendor.Reason != "tracker + category:telemetry" || vendor.SensitiveReason != "category:telemetry" {
		t.Fatalf("vendor = %+v", vendor)
	}
	clean := mustFind(t, plan, "jp.cleanroom.tool", "api.cleanroom.jp")
	if clean.Verdict != VerdictReview {
		t.Fatalf("clean = %+v", clean)
	}

	if len(plan.Quarantine) != 2 || plan.Quarantine[0].Package != "cn.mailroom.app" {
		t.Fatalf("quarantine = %+v", plan.Quarantine)
	}
	if len(plan.Skipped) != 1 || plan.Skipped[0].Package != "com.vendorwatch.telemetry" || plan.Skipped[0].Reason != "system app" {
		t.Fatalf("skipped = %+v", plan.Skipped)
	}
}

func TestGlobalize(t *testing.T) {
	plan := compileFixture(t, func(p *policy.Policy) {
		p.Compile.Globalize = "trackers"
	})
	if plan.Stats.Global != 5 || plan.Stats.Scoped != 0 || plan.Stats.GlobalDomains != 5 {
		t.Fatalf("stats = %+v", plan.Stats)
	}
	alog := mustFind(t, plan, "com.nightmarket.shop", "alog.umeng.com")
	if !alog.Global() || alog.Reason != "tracker + data:location (globalized)" {
		t.Fatalf("alog = %+v", alog)
	}
	login := mustFind(t, plan, "com.nightmarket.shop", "login.nightpass.cn")
	if login.Global() {
		t.Fatalf("functional endpoint was globalized: %+v", login)
	}
}

func TestSensitivityGateDisabled(t *testing.T) {
	plan := compileFixture(t, func(p *policy.Policy) {
		p.Sensitive.Require = false
	})
	if plan.Stats.Blocked != 6 || plan.Stats.Quarantine != 3 {
		t.Fatalf("stats = %+v", plan.Stats)
	}
	reader := mustFind(t, plan, "jp.quietreader.app", "metrics.quietreader.jp")
	if !reader.Blocked() {
		t.Fatalf("reader = %+v", reader)
	}
}

func TestSystemExcluded(t *testing.T) {
	plan := compileFixture(t, func(p *policy.Policy) {
		p.Compile.IncludeSystem = false
	})
	vendor := mustFind(t, plan, "com.vendorwatch.telemetry", "analytics.vendorwatch.cn")
	if vendor.Verdict != VerdictReview || vendor.Reason != "system app excluded" {
		t.Fatalf("vendor = %+v", vendor)
	}
	if plan.Stats.Blocked != 4 {
		t.Fatalf("stats = %+v", plan.Stats)
	}
}

func TestOverrides(t *testing.T) {
	t.Run("app allow", func(t *testing.T) {
		plan := compileFixture(t, func(p *policy.Policy) {
			p.Apps["com.nightmarket.shop"] = policy.AppOverride{Mode: "allow"}
		})
		if plan.Stats.Blocked != 2 || plan.Stats.Quarantine != 1 {
			t.Fatalf("stats = %+v", plan.Stats)
		}
		if got := mustFind(t, plan, "com.nightmarket.shop", "alog.umeng.com"); got.Verdict != VerdictAllow {
			t.Fatalf("alog = %+v", got)
		}
	})
	t.Run("domain allow", func(t *testing.T) {
		plan := compileFixture(t, func(p *policy.Policy) {
			p.Domains["c.umengcloud.com"] = policy.DomainOverride{Action: "allow"}
		})
		if plan.Stats.Blocked != 4 || plan.Stats.Quarantine != 1 {
			t.Fatalf("stats = %+v", plan.Stats)
		}
	})
	t.Run("domain block", func(t *testing.T) {
		plan := compileFixture(t, func(p *policy.Policy) {
			p.Domains["api.nightmarket.cn"] = policy.DomainOverride{Action: "block"}
		})
		got := mustFind(t, plan, "com.nightmarket.shop", "api.nightmarket.cn")
		if !got.Blocked() || !got.Global() || plan.Stats.Blocked != 6 || plan.Stats.GlobalDomains != 1 {
			t.Fatalf("finding = %+v stats = %+v", got, plan.Stats)
		}
	})
	t.Run("app blocklist", func(t *testing.T) {
		plan := compileFixture(t, func(p *policy.Policy) {
			p.Apps["jp.cleanroom.tool"] = policy.AppOverride{Block: []string{"api.cleanroom.jp"}}
		})
		got := mustFind(t, plan, "jp.cleanroom.tool", "api.cleanroom.jp")
		if !got.Blocked() || got.Global() || plan.Stats.Blocked != 6 {
			t.Fatalf("finding = %+v stats = %+v", got, plan.Stats)
		}
	})
}

func TestMinScore(t *testing.T) {
	plan := compileFixture(t, func(p *policy.Policy) {
		p.Sensitive.MinScore = 35
	})
	shop := mustFind(t, plan, "com.nightmarket.shop", "alog.umeng.com")
	if shop.Verdict != VerdictReview || shop.Reason != "score below min_score" {
		t.Fatalf("shop = %+v", shop)
	}
	if plan.Stats.Blocked != 2 {
		t.Fatalf("stats = %+v", plan.Stats)
	}
}

func TestQuarantineFilters(t *testing.T) {
	t.Run("shared uid", func(t *testing.T) {
		plan := compileFixture(t, func(p *policy.Policy) {
			p.Quarantine.IncludeSystem = true
		})
		if len(plan.Skipped) != 1 || plan.Skipped[0].Reason != "shared UID" {
			t.Fatalf("skipped = %+v", plan.Skipped)
		}
	})
	t.Run("system uid ineligible", func(t *testing.T) {
		plan := compileFixture(t, func(p *policy.Policy) {
			p.Quarantine.IncludeSystem = true
			p.Quarantine.IncludeSharedUID = true
		})
		if len(plan.Skipped) != 1 || plan.Skipped[0].Reason != "uid not eligible for netpolicy" {
			t.Fatalf("skipped = %+v", plan.Skipped)
		}
	})
	t.Run("minimum domains", func(t *testing.T) {
		plan := compileFixture(t, func(p *policy.Policy) {
			p.Quarantine.MinBlockedDomains = 2
		})
		if len(plan.Quarantine) != 1 || plan.Quarantine[0].Package != "com.nightmarket.shop" {
			t.Fatalf("quarantine = %+v", plan.Quarantine)
		}
	})
}

func TestQuarantineDisabled(t *testing.T) {
	plan := compileFixture(t, func(p *policy.Policy) {
		p.Quarantine.BackgroundRestrict = false
		p.Quarantine.AppOpsBackground = false
		p.Quarantine.ForceStop = false
	})
	if plan.Stats.Quarantine != 0 || plan.Stats.QuarantineSkipped != 0 || len(plan.Quarantine) != 0 {
		t.Fatalf("stats = %+v quarantine = %+v", plan.Stats, plan.Quarantine)
	}
}

func TestDecisionOverrides(t *testing.T) {
	report, pol := fixture(t)
	plan, err := Compile(report, pol, Options{Overrides: map[string]Verdict{
		"com.nightmarket.shop|alog.umeng.com":   VerdictAllow,
		"jp.quietreader.app|api.quietreader.jp": VerdictBlock,
	}})
	if err != nil {
		t.Fatal(err)
	}
	if got := mustFind(t, plan, "com.nightmarket.shop", "alog.umeng.com"); got.Verdict != VerdictAllow || got.AutoVerdict != VerdictBlock {
		t.Fatalf("alog = %+v", got)
	}
	if got := mustFind(t, plan, "jp.quietreader.app", "api.quietreader.jp"); !got.Blocked() {
		t.Fatalf("reader api = %+v", got)
	}
	if plan.Stats.Blocked != 5 {
		t.Fatalf("stats = %+v", plan.Stats)
	}
}

func TestDecisionCannotUnlockGlobal(t *testing.T) {
	report, pol := fixture(t)
	pol.Compile.Globalize = "trackers"
	plan, err := Compile(report, pol, Options{Overrides: map[string]Verdict{
		"com.nightmarket.shop|alog.umeng.com": VerdictAllow,
	}})
	if err != nil {
		t.Fatal(err)
	}
	got := mustFind(t, plan, "com.nightmarket.shop", "alog.umeng.com")
	if got.Verdict != VerdictBlock || !got.Global() {
		t.Fatalf("global finding was unlocked: %+v", got)
	}
}

func TestCompileRejectsNil(t *testing.T) {
	if _, err := Compile(nil, nil, Options{}); err == nil {
		t.Fatal("expected error")
	}
}
