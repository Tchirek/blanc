package policy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// 春の宵
// ルールの糸を
// 結び直す
func TestDefaultPolicy(t *testing.T) {
	p, err := Load("")
	if err != nil {
		t.Fatal(err)
	}
	if p.Compile.Globalize != "none" || !p.Compile.IncludeSystem {
		t.Fatalf("unexpected compile defaults: %+v", p.Compile)
	}
	if len(p.Sensitive.DataTypes) != 12 || !p.Sensitive.Require {
		t.Fatalf("unexpected sensitive defaults: %+v", p.Sensitive)
	}
	if p.Quarantine.MinBlockedDomains != 1 || !p.Quarantine.BackgroundRestrict || !p.Quarantine.ForceStop {
		t.Fatalf("unexpected quarantine defaults: %+v", p.Quarantine)
	}
	if len(p.Hash) != 64 {
		t.Fatalf("hash = %q", p.Hash)
	}
	if len(DefaultYAML()) == 0 {
		t.Fatal("default YAML is empty")
	}
}

func TestLoadOverridesAndShorthand(t *testing.T) {
	raw := `version: 1
compile:
  globalize: trackers
  include_system: false
sensitive:
  require: false
  data_types: [位置, sms]
  categories: [遥测/统计]
  min_score: 12
apps:
  com.nightmarket.shop: allow
  com.nightmarket.shop.extra:
    mode: block
    block: [Tracker.Adsight.IO]
    allow: [api.nightmarket.cn]
domains:
  C.UMENGCLOUD.COM: allow
  analytics.vendorwatch.cn:
    action: block
quarantine:
  min_blocked_domains: 2
  appops_background: true
`
	p := loadString(t, raw)
	if p.Compile.Globalize != "trackers" || p.Compile.IncludeSystem {
		t.Fatalf("compile = %+v", p.Compile)
	}
	if got := strings.Join(p.Sensitive.DataTypes, ","); got != "sms,location" && got != "location,sms" {
		t.Fatalf("data types = %q", got)
	}
	if got := strings.Join(p.Sensitive.Categories, ","); got != "telemetry" {
		t.Fatalf("categories = %q", got)
	}
	if p.Apps["com.nightmarket.shop"].Mode != "allow" {
		t.Fatalf("shorthand app mode = %+v", p.Apps["com.nightmarket.shop"])
	}
	extra := p.Apps["com.nightmarket.shop.extra"]
	if extra.Mode != "block" || len(extra.Block) != 1 || extra.Block[0] != "tracker.adsight.io" {
		t.Fatalf("extra = %+v", extra)
	}
	if p.Domains["c.umengcloud.com"].Action != "allow" {
		t.Fatalf("domain normalization failed: %+v", p.Domains)
	}
	if p.Domains["analytics.vendorwatch.cn"].Action != "block" {
		t.Fatalf("domain block failed: %+v", p.Domains)
	}
	if p.Quarantine.MinBlockedDomains != 2 || !p.Quarantine.AppOpsBackground || !p.Quarantine.ForceStop {
		t.Fatalf("quarantine defaults not preserved: %+v", p.Quarantine)
	}
}

func TestRejectsBadPolicies(t *testing.T) {
	cases := []struct {
		name string
		raw  string
		want string
	}{
		{"version", "version: 2\n", "version"},
		{"globalize", "version: 1\ncompile:\n  globalize: everywhere\n", "globalize"},
		{"unknown field", "version: 1\ncompile:\n  globalise: none\n", "globalise"},
		{"unknown app field", "version: 1\napps:\n  com.a.b:\n    mode: allow\n    bogus: 1\n", "bogus"},
		{"mode", "version: 1\napps:\n  com.a.b: nope\n", "mode"},
		{"action", "version: 1\ndomains:\n  a.cn: warn\n", "action"},
		{"overlap", "version: 1\napps:\n  com.a.b:\n    block: [x.cn]\n    allow: [x.cn]\n", "both"},
		{"package", "version: 1\napps:\n  nodot: allow\n", "package"},
		{"domain", "version: 1\ndomains:\n  '*.a.cn': allow\n", "domain"},
		{"data type", "version: 1\nsensitive:\n  data_types: [wat]\n", "data type"},
		{"category", "version: 1\nsensitive:\n  categories: [wat]\n", "category"},
		{"empty data types", "version: 1\nsensitive:\n  data_types: []\n", "data_types"},
		{"min blocked", "version: 1\nquarantine:\n  min_blocked_domains: 0\n", "min_blocked_domains"},
		{"duplicate domain", "version: 1\ndomains:\n  A.example.cn: allow\n  a.example.cn: block\n", "duplicate"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "blanc.yaml")
			if err := os.WriteFile(path, []byte(tc.raw), 0o600); err != nil {
				t.Fatal(err)
			}
			_, err := Load(path)
			if err == nil {
				t.Fatal("expected error")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error %q does not contain %q", err, tc.want)
			}
		})
	}
}

func loadString(t *testing.T, raw string) *Policy {
	t.Helper()
	path := filepath.Join(t.TempDir(), "blanc.yaml")
	if err := os.WriteFile(path, []byte(raw), 0o600); err != nil {
		t.Fatal(err)
	}
	p, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	return p
}
