package audit

import (
	"errors"
	"testing"
)

// 静けさを
// 破るノイズを
// 取り除く
func TestParseEndpoint(t *testing.T) {
	cases := []struct {
		raw  string
		host string
		path string
		err  error
	}{
		{"https://ALOG.UMENG.COM:443/report/v1", "alog.umeng.com", "/report/v1", nil},
		{"alog.umeng.com/report", "alog.umeng.com", "/report", nil},
		{"//cdn.nightmarket.cn/a.js", "cdn.nightmarket.cn", "/a.js", nil},
		{"https://203.0.113.7:8080/collect", "", "", ErrIPLiteral},
		{"https://127.0.0.1/collect", "", "", ErrIPLiteral},
		{"https://localhost/collect", "", "", ErrLocalHost},
		{"https://staging.telemetry.nightsight.io/beacon", "", "", ErrTestHost},
		{"https://schemas.android.com/aapt", "", "", ErrDocsHost},
		{"https://example.com/report", "", "", ErrDocsHost},
		{"not a url", "", "", ErrInvalidHost},
		{"https://", "", "", ErrInvalidHost},
		{"ftp://files.nightmarket.cn/x", "", "", ErrInvalidHost},
	}
	for _, tc := range cases {
		ep, err := ParseEndpoint(tc.raw)
		if !errors.Is(err, tc.err) {
			t.Fatalf("%q: err = %v, want %v", tc.raw, err, tc.err)
		}
		if tc.err != nil {
			continue
		}
		if ep.Host != tc.host || ep.Path != tc.path {
			t.Fatalf("%q: got host=%q path=%q", tc.raw, ep.Host, ep.Path)
		}
	}
}

func TestParseEndpointTrimsNoise(t *testing.T) {
	ep, err := ParseEndpoint(`"https://log.adsight.io/collect"`)
	if err != nil {
		t.Fatal(err)
	}
	if ep.Host != "log.adsight.io" || ep.Path != "/collect" {
		t.Fatalf("unexpected endpoint: %+v", ep)
	}
}

func TestValidDomain(t *testing.T) {
	valid := []string{"a.b", "alog.umeng.com", "xn--fiqs8s.cn", "my_service.example.cn"}
	invalid := []string{"", "a", "a..b", "*.example.com", "a b.com", "a:80", "http://a.b"}
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
}
