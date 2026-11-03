package audit

import (
	"strings"
	"testing"
)

// 鏡面
// 影を映して
// 確かめる
func TestLoadFixture(t *testing.T) {
	report, err := Load("../../testdata/report.json")
	if err != nil {
		t.Fatal(err)
	}
	if report.Device.Serial != "BLANC123" || report.Device.Model != "Pixel 7" {
		t.Fatalf("unexpected device: %+v", report.Device)
	}
	if len(report.Apps) != 5 {
		t.Fatalf("apps = %d, want 5", len(report.Apps))
	}
	if len(report.Hash) != 64 {
		t.Fatalf("hash = %q", report.Hash)
	}
	if strings.Join(report.Keys, ",") != "apps,device,recommendations" {
		t.Fatalf("keys = %v", report.Keys)
	}
	shop := report.Apps[0]
	if got, want := shop.CategorySlug(), "shopping"; got != want {
		t.Fatalf("category = %q, want %q", got, want)
	}
	if got, want := strings.Join(shop.DataTypeSlugs(), ","), "location,identity"; got != want {
		t.Fatalf("data types = %q, want %q", got, want)
	}
}

func TestParseRejectsDuplicateAndBadPackages(t *testing.T) {
	cases := []string{
		`{"apps":[{"package":"com.a.b"},{"package":"com.a.b"}]}`,
		`{"apps":[{"package":"com..b"}]}`,
		`{"apps":[{"package":"nodot"}]}`,
		`[]`,
	}
	for _, raw := range cases {
		if _, err := Parse([]byte(raw)); err == nil {
			t.Fatalf("expected error for %s", raw)
		}
	}
}

func TestNormalization(t *testing.T) {
	if slug, ok := NormalizeDataType("设备标识"); !ok || slug != "identity" {
		t.Fatalf("identity: %q %v", slug, ok)
	}
	if slug, ok := NormalizeCategory("遥测/统计"); !ok || slug != "telemetry" {
		t.Fatalf("telemetry: %q %v", slug, ok)
	}
	if _, ok := NormalizeDataType("不存在"); ok {
		t.Fatal("unknown data type accepted")
	}
	if got := len(KnownDataTypes()); got != 12 {
		t.Fatalf("known data types = %d", got)
	}
	app := App{DataTypes: []string{"位置", "未知"}}
	if got := strings.Join(app.DataTypeSlugs(), ","); got != "location" {
		t.Fatalf("data types = %q", got)
	}
}
