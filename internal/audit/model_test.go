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
	if shop := report.Apps[0]; shop.Package != "com.nightmarket.shop" || len(shop.Endpoints) != 10 || shop.System {
		t.Fatalf("shop = %+v", shop)
	}
}

// 同じ戸の
// 札を読みとり
// 印つけ
func TestSharedUIDIsRead(t *testing.T) {
	report, err := Load("../../testdata/report.json")
	if err != nil {
		t.Fatal(err)
	}
	vendor, ok := report.App("com.vendorwatch.telemetry")
	if !ok || !vendor.SharesUID() || vendor.SharedUID != "android.uid.system" || vendor.UID != "1000" {
		t.Fatalf("vendor = %+v", vendor)
	}
	shop, ok := report.App("com.nightmarket.shop")
	if !ok || shop.SharesUID() || shop.UID != "10101" {
		t.Fatalf("shop = %+v", shop)
	}
	if _, ok := report.App("missing.app"); ok {
		t.Fatal("missing app found")
	}
}

func TestParseRejectsDuplicateAndBadPackages(t *testing.T) {
	cases := []string{
		`{"apps":[{"package":"com.a.b"},{"package":"com.a.b"}]}`,
		`{"apps":[{"package":"com..b"}]}`,
		`[]`,
	}
	for _, raw := range cases {
		if _, err := Parse([]byte(raw)); err == nil {
			t.Fatalf("expected error for %s", raw)
		}
	}
}

func TestSingleSegmentSystemPackage(t *testing.T) {
	for _, name := range []string{"android", "oplus"} {
		if !ValidPackage(name) {
			t.Fatalf("rejected %q", name)
		}
	}
}
