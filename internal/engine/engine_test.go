package engine

import (
	"strings"
	"testing"

	"github.com/blanc-sh/blanc/internal/audit"
	"github.com/blanc-sh/blanc/internal/policy"
)

// 灯をともし
// 影の行方を
// 数えけり
func fixture(t *testing.T) (*audit.Report, *audit.DomainSet, *policy.Policy) {
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
	return report, domains, pol
}

func compileFixture(t *testing.T, mutate func(*policy.Policy)) *Plan {
	t.Helper()
	report, domains, pol := fixture(t)
	if mutate != nil {
		mutate(pol)
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

func TestCompileDefault(t *testing.T) {
	plan := compileFixture(t, nil)
	want := Stats{
		Apps:           5,
		Endpoints:      20,
		Findings:       16,
		Blocked:        5,
		Review:         6,
		Allowed:        5,
		AppsWithBlocks: 3,
		UniqueDomains:  15,
		BlockedDomains: 5,
		Ignored:        3,
	}
	if plan.Stats != want {
		t.Fatalf("stats = %+v, want %+v", plan.Stats, want)
	}
	if plan.ClassificationSource != "noir" || len(plan.DomainHashes) != 3 {
		t.Fatalf("provenance = %+v", plan)
	}
	if strings.Join(plan.ReportKeys, ",") != "apps,device,recommendations" {
		t.Fatalf("report keys = %v", plan.ReportKeys)
	}

	alog := mustFind(t, plan, "com.nightmarket.shop", "alog.umeng.com")
	if !alog.Blocked() || alog.Class != audit.ClassTracker {
		t.Fatalf("alog = %+v", alog)
	}
	if alog.Reason != "tracker + app capability: data:location" {
		t.Fatalf("alog reason = %q", alog.Reason)
	}
	if !alog.Sensitive || alog.SensitiveReason != "data:location" {
		t.Fatalf("alog sensitivity = %+v", alog)
	}
	if len(alog.Evidence) == 0 || !strings.Contains(alog.Evidence[0], "alog.umeng.com") {
		t.Fatalf("evidence = %v", alog.Evidence)
	}

	metrics := mustFind(t, plan, "com.nightmarket.shop", "metrics.quietreader.jp")
	if metrics.Reason != alog.Reason {
		t.Fatalf("reason should be app-level, not host-specific: %q", metrics.Reason)
	}

	if got := mustFind(t, plan, "com.nightmarket.shop", "login.nightpass.cn"); got.Verdict != VerdictAllow || got.Reason != "functional per NOIR" {
		t.Fatalf("login = %+v", got)
	}
	if got := mustFind(t, plan, "com.nightmarket.shop", "api.nightmarket.cn"); got.Verdict != VerdictReview || got.Class != audit.ClassReview {
		t.Fatalf("api = %+v", got)
	}
	if got := mustFind(t, plan, "jp.quietreader.app", "metrics.quietreader.jp"); got.Verdict != VerdictReview || got.Reason != "tracker without sensitive app capability" {
		t.Fatalf("reader = %+v", got)
	}
	vendor := mustFind(t, plan, "com.vendorwatch.telemetry", "analytics.vendorwatch.cn")
	if !vendor.Blocked() || vendor.Reason != "tracker + app capability: category:telemetry" {
		t.Fatalf("vendor = %+v", vendor)
	}
	if vendor.SensitiveReason != "category:telemetry" || len(vendor.DataTypes) != 0 {
		t.Fatalf("vendor sensitivity = %+v", vendor)
	}
	if got := mustFind(t, plan, "jp.cleanroom.tool", "api.cleanroom.jp"); got.Verdict != VerdictReview {
		t.Fatalf("clean = %+v", got)
	}

	if reason := ignoredReason(plan, "https://staging.telemetry.nightsight.io/beacon"); reason != "not in NOIR domain export" {
		t.Fatalf("staging ignore = %q", reason)
	}
	if reason := ignoredReason(plan, "http://203.0.113.7:8080/collect"); reason != "ip literal" {
		t.Fatalf("ip ignore = %q", reason)
	}
}

func TestAppOverrides(t *testing.T) {
	t.Run("allow app", func(t *testing.T) {
		plan := compileFixture(t, func(p *policy.Policy) {
			p.Apps["com.nightmarket.shop"] = policy.AppOverride{Mode: "allow"}
		})
		if plan.Stats.Blocked != 2 || plan.Stats.Allowed != 9 || plan.Stats.Review != 5 {
			t.Fatalf("stats = %+v", plan.Stats)
		}
		if got := mustFind(t, plan, "com.nightmarket.shop", "alog.umeng.com"); got.Verdict != VerdictAllow {
			t.Fatalf("alog = %+v", got)
		}
	})
	t.Run("block review host", func(t *testing.T) {
		plan := compileFixture(t, func(p *policy.Policy) {
			p.Apps["jp.cleanroom.tool"] = policy.AppOverride{Block: []string{"api.cleanroom.jp"}}
		})
		got := mustFind(t, plan, "jp.cleanroom.tool", "api.cleanroom.jp")
		if !got.Blocked() || got.Class != audit.ClassReview || got.Reason != "app blocklist" {
			t.Fatalf("clean = %+v", got)
		}
		if plan.Stats.Blocked != 6 {
			t.Fatalf("stats = %+v", plan.Stats)
		}
	})
	t.Run("block unclassified host", func(t *testing.T) {
		plan := compileFixture(t, func(p *policy.Policy) {
			p.Apps["com.nightmarket.shop"] = policy.AppOverride{Block: []string{"staging.telemetry.nightsight.io"}}
		})
		got := mustFind(t, plan, "com.nightmarket.shop", "staging.telemetry.nightsight.io")
		if !got.Blocked() || got.Class != audit.ClassUnknown || !strings.Contains(got.Reason, "not in NOIR") {
			t.Fatalf("staging = %+v", got)
		}
		if plan.Stats.Blocked != 6 || plan.Stats.Ignored != 2 {
			t.Fatalf("stats = %+v", plan.Stats)
		}
	})
	t.Run("mode block only trackers", func(t *testing.T) {
		plan := compileFixture(t, func(p *policy.Policy) {
			p.Apps["jp.cleanroom.tool"] = policy.AppOverride{Mode: "block"}
		})
		if got := mustFind(t, plan, "jp.cleanroom.tool", "api.cleanroom.jp"); got.Verdict != VerdictReview {
			t.Fatalf("review host blocked: %+v", got)
		}
		if got := mustFind(t, plan, "jp.cleanroom.tool", "update.cleanroom.jp"); got.Verdict != VerdictAllow {
			t.Fatalf("functional host blocked: %+v", got)
		}
	})
	t.Run("mode block tracker", func(t *testing.T) {
		plan := compileFixture(t, func(p *policy.Policy) {
			p.Apps["jp.quietreader.app"] = policy.AppOverride{Mode: "block"}
		})
		got := mustFind(t, plan, "jp.quietreader.app", "metrics.quietreader.jp")
		if !got.Blocked() || got.Reason != "app mode block" {
			t.Fatalf("reader = %+v", got)
		}
	})
	t.Run("allowlist wins", func(t *testing.T) {
		plan := compileFixture(t, func(p *policy.Policy) {
			p.Apps["com.nightmarket.shop"] = policy.AppOverride{Allow: []string{"metrics.quietreader.jp"}}
		})
		got := mustFind(t, plan, "com.nightmarket.shop", "metrics.quietreader.jp")
		if got.Verdict != VerdictAllow || got.Reason != "app allowlist" {
			t.Fatalf("metrics = %+v", got)
		}
		if plan.Stats.Blocked != 4 {
			t.Fatalf("stats = %+v", plan.Stats)
		}
	})
}

func TestSystemExcluded(t *testing.T) {
	plan := compileFixture(t, func(p *policy.Policy) {
		p.IncludeSystem = false
	})
	vendor := mustFind(t, plan, "com.vendorwatch.telemetry", "analytics.vendorwatch.cn")
	if vendor.Verdict != VerdictReview || vendor.Reason != "system app excluded" {
		t.Fatalf("vendor = %+v", vendor)
	}
	if plan.Stats.Blocked != 4 {
		t.Fatalf("stats = %+v", plan.Stats)
	}
}

func TestCompileRejectsNil(t *testing.T) {
	if _, err := Compile(nil, nil, nil); err == nil {
		t.Fatal("expected error")
	}
}

func ignoredReason(plan *Plan, raw string) string {
	for _, ignored := range plan.Ignored {
		if ignored.Raw == raw {
			return ignored.Reason
		}
	}
	return ""
}
