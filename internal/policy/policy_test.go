package policy

import (
	"errors"
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
	if p.Version != Version || len(p.Allow) != 0 || len(p.Block) != 0 || len(p.Apps) != 0 {
		t.Fatalf("defaults = %+v", p)
	}
	if len(p.Hash) != 64 {
		t.Fatalf("hash = %q", p.Hash)
	}
	if _, err := Parse(DefaultYAML()); err != nil {
		t.Fatalf("default YAML does not parse: %v", err)
	}
}

// 例外の
// 書き方三つ
// 確かめる
func TestLoadGlobalAndApps(t *testing.T) {
	raw := `version: 2
allow: [Umeng.com., "+.adsight.io"]
block: [api.nightmarket.cn]
apps:
  jp.quietreader.app: allow
  cn.mailroom.app:
    allow: all
    block: [cdn.mailroom.cn]
  com.nightmarket.shop:
    allow: [Metrics.Quietreader.JP]
    block: [push.nightpush.cn]
`
	p := loadString(t, raw)
	if got := strings.Join(p.Allow, ","); got != "adsight.io,umeng.com" {
		t.Fatalf("allow = %q", got)
	}
	if got := strings.Join(p.Block, ","); got != "api.nightmarket.cn" {
		t.Fatalf("block = %q", got)
	}
	if !p.Apps["jp.quietreader.app"].AllowAll {
		t.Fatalf("shorthand = %+v", p.Apps["jp.quietreader.app"])
	}
	mail := p.Apps["cn.mailroom.app"]
	if !mail.AllowAll || len(mail.Block) != 1 {
		t.Fatalf("mailroom = %+v", mail)
	}
	shop := p.Apps["com.nightmarket.shop"]
	if shop.AllowAll || strings.Join(shop.Allow, ",") != "metrics.quietreader.jp" || strings.Join(shop.Block, ",") != "push.nightpush.cn" {
		t.Fatalf("shop = %+v", shop)
	}
	if got := strings.Join(p.Packages(), ","); got != "cn.mailroom.app,com.nightmarket.shop,jp.quietreader.app" {
		t.Fatalf("packages = %q", got)
	}
}

// 古き札
// 捨てる道筋
// 添えて返す
func TestVersionOneExplainsMigration(t *testing.T) {
	raw := "version: 1\nsensitive:\n  data_types: [location]\ninclude_system: true\n"
	_, err := Parse([]byte(raw))
	if !errors.Is(err, ErrV1) {
		t.Fatalf("err = %v", err)
	}
	for _, want := range []string{"every app", "blanc init --force", "allow"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("migration hint lacks %q: %v", want, err)
		}
	}
}

func TestRejectsBadPolicies(t *testing.T) {
	cases := []struct {
		name string
		raw  string
		want string
	}{
		{"missing version", "allow: []\n", "missing"},
		{"future version", "version: 9\n", "unsupported version 9"},
		{"unknown field", "version: 2\nsensitive: {}\n", "sensitive"},
		{"unknown app field", "version: 2\napps:\n  com.a.b:\n    allow: all\n    bogus: 1\n", "bogus"},
		{"removed mode", "version: 2\napps:\n  com.a.b:\n    mode: allow\n", "removed"},
		{"bad shorthand", "version: 2\napps:\n  com.a.b: block\n", "shorthand"},
		{"bad allow scalar", "version: 2\napps:\n  com.a.b:\n    allow: some\n", "all"},
		{"package", "version: 2\napps:\n  com..bad: allow\n", "package"},
		{"domain", "version: 2\napps:\n  com.a.b:\n    block: ['*.a.cn']\n", "domain"},
		{"global domain", "version: 2\nblock: [localhost]\n", "domain"},
		{"app overlap", "version: 2\napps:\n  com.a.b:\n    block: [x.cn]\n    allow: [X.cn]\n", "both"},
		{"global overlap", "version: 2\nallow: [x.cn]\nblock: [x.cn]\n", "both"},
		{"empty app", "version: 2\napps:\n  com.a.b:\n    allow: all\n    block: []\n  com.c.d:\n    allow: [x.cn]\n    block: [y.cn]\n  com.e.f: {}\n", "empty"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Parse([]byte(tc.raw))
			if err == nil {
				t.Fatal("expected error")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error %q does not contain %q", err, tc.want)
			}
		})
	}
}

// 手本こそ
// 古びぬように
// 読み試す
func TestExamplePolicyLoads(t *testing.T) {
	p, err := Load(filepath.Join("..", "..", "examples", "blanc.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Allow) == 0 || len(p.Block) == 0 || !p.Apps["jp.quietreader.app"].AllowAll {
		t.Fatalf("example = %+v", p)
	}
}

func TestLoadNamesTheFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "blanc.yaml")
	if err := os.WriteFile(path, []byte("version: 2\nblock: [bad]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := Load(path)
	if err == nil || !strings.Contains(err.Error(), path) {
		t.Fatalf("err = %v", err)
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
