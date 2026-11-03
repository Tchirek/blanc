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
	if p.Version != 1 || !p.IncludeSystem {
		t.Fatalf("defaults = %+v", p)
	}
	if len(p.Sensitive.DataTypes) != 12 || len(p.Sensitive.Categories) != 5 {
		t.Fatalf("sensitive = %+v", p.Sensitive)
	}
	if len(p.Apps) != 0 {
		t.Fatalf("apps = %+v", p.Apps)
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
sensitive:
  data_types: [位置, sms]
  categories: [遥测/统计]
include_system: false
apps:
  com.nightmarket.shop: allow
  jp.quietreader.app:
    mode: block
    allow: [Metrics.Quietreader.JP]
    block: [api.quietreader.jp]
`
	p := loadString(t, raw)
	if p.IncludeSystem {
		t.Fatal("include_system not applied")
	}
	if got := strings.Join(p.Sensitive.DataTypes, ","); got != "location,sms" {
		t.Fatalf("data types = %q", got)
	}
	if got := strings.Join(p.Sensitive.Categories, ","); got != "telemetry" {
		t.Fatalf("categories = %q", got)
	}
	if p.Apps["com.nightmarket.shop"].Mode != "allow" {
		t.Fatalf("shorthand = %+v", p.Apps["com.nightmarket.shop"])
	}
	reader := p.Apps["jp.quietreader.app"]
	if reader.Mode != "block" || len(reader.Allow) != 1 || reader.Allow[0] != "metrics.quietreader.jp" {
		t.Fatalf("reader = %+v", reader)
	}
	if len(reader.Block) != 1 || reader.Block[0] != "api.quietreader.jp" {
		t.Fatalf("reader block = %+v", reader.Block)
	}
}

func TestRejectsBadPolicies(t *testing.T) {
	cases := []struct {
		name string
		raw  string
		want string
	}{
		{"version", "version: 2\n", "version"},
		{"unknown field", "version: 1\ncompile:\n  globalize: none\n", "compile"},
		{"unknown app field", "version: 1\napps:\n  com.a.b:\n    mode: allow\n    bogus: 1\n", "bogus"},
		{"mode", "version: 1\napps:\n  com.a.b: nope\n", "mode"},
		{"package", "version: 1\napps:\n  com..bad: allow\n", "package"},
		{"domain", "version: 1\napps:\n  com.a.b:\n    block: ['*.a.cn']\n", "domain"},
		{"overlap", "version: 1\napps:\n  com.a.b:\n    block: [x.cn]\n    allow: [x.cn]\n", "both"},
		{"empty sensitive", "version: 1\nsensitive:\n  data_types: []\n  categories: []\n", "both empty"},
		{"data type", "version: 1\nsensitive:\n  data_types: [wat]\n", "data type"},
		{"category", "version: 1\nsensitive:\n  categories: [wat]\n", "category"},
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
