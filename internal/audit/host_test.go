package audit

import (
	"errors"
	"strings"
	"testing"
)

// 静けさを
// 破るノイズを
// 取り除く
func TestParseEndpoint(t *testing.T) {
	cases := []struct {
		raw  string
		host string
		err  error
	}{
		{"https://ALOG.UMENG.COM:443/report/v1", "alog.umeng.com", nil},
		{"alog.umeng.com/report", "alog.umeng.com", nil},
		{"//cdn.nightmarket.cn/a.js", "cdn.nightmarket.cn", nil},
		{"https://staging.telemetry.nightsight.io/beacon", "staging.telemetry.nightsight.io", nil},
		{"https://schemas.android.com/aapt", "schemas.android.com", nil},
		{"https://203.0.113.7:8080/collect", "", ErrIPLiteral},
		{"https://127.0.0.1/collect", "", ErrIPLiteral},
		{"https://localhost/collect", "", ErrInvalidHost},
		{"not a url", "", ErrInvalidHost},
		{"https://", "", ErrInvalidHost},
		{"ftp://files.nightmarket.cn/x", "", ErrInvalidHost},
	}
	for _, tc := range cases {
		ep, err := ParseEndpoint(tc.raw)
		if !errors.Is(err, tc.err) {
			t.Fatalf("%q: err = %v, want %v", tc.raw, err, tc.err)
		}
		if tc.err != nil {
			continue
		}
		if ep.Host != tc.host {
			t.Fatalf("%q: got host=%q", tc.raw, ep.Host)
		}
	}
}

func FuzzParseEndpoint(f *testing.F) {
	f.Add("https://alog.umeng.com/report")
	f.Add("203.0.113.7")
	f.Add("")
	f.Fuzz(func(t *testing.T, raw string) {
		ep, err := ParseEndpoint(raw)
		if err != nil {
			return
		}
		if !ValidDomain(ep.Host) {
			t.Fatalf("accepted invalid host: %+v", ep)
		}
		if ep.Host != strings.ToLower(ep.Host) {
			t.Fatalf("host is not lowercase: %q", ep.Host)
		}
	})
}

func TestParseEndpointTrimsNoise(t *testing.T) {
	ep, err := ParseEndpoint(`"https://log.adsight.io/collect"`)
	if err != nil {
		t.Fatal(err)
	}
	if ep.Host != "log.adsight.io" {
		t.Fatalf("unexpected endpoint: %+v", ep)
	}
}

func TestValidDomain(t *testing.T) {
	valid := []string{"a.b", "alog.umeng.com", "xn--fiqs8s.cn", "my_service.example.cn"}
	invalid := []string{"", "a", "a..b", "*.example.com", "a b.com", "a:80", "http://a.b", "localhost"}
	for _, host := range valid {
		if !ValidDomain(host) {
			t.Fatalf("valid domain rejected: %q", host)
		}
	}
	for _, host := range invalid {
		if ValidDomain(host) {
			t.Fatalf("invalid domain accepted: %q", host)
		}
	}
	if got, err := NormalizeDomain(" ALOG.UMENG.COM. "); err != nil || got != "alog.umeng.com" {
		t.Fatalf("normalize = %q %v", got, err)
	}
}
