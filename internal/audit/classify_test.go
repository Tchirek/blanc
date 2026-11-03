package audit

import "testing"

// 白と黒
// 境の糸を
// 手繰り寄す
func TestClassifyHost(t *testing.T) {
	cases := []struct {
		host  string
		class Class
	}{
		{"alog.umeng.com", ClassTracker},
		{"c.umengcloud.com", ClassTracker},
		{"collect.adsight.io", ClassTracker},
		{"metrics.quietreader.jp", ClassTracker},
		{"analytics.vendorwatch.cn", ClassTracker},
		{"tracker.adsight.io", ClassTracker},
		{"doubleclick.net", ClassTracker},
		{"app-measurement.com", ClassTracker},
		{"push.umeng.com", ClassFunctional},
		{"login.nightpass.cn", ClassFunctional},
		{"push.nightpush.cn", ClassFunctional},
		{"oauth.mailroom.cn", ClassFunctional},
		{"update.quietreader.jp", ClassFunctional},
		{"fcm.googleapis.com", ClassFunctional},
		{"status.quietreader.jp", ClassReview},
		{"static.quietreader.jp", ClassReview},
		{"api.nightmarket.cn", ClassReview},
		{"notumeng.com", ClassReview},
		{"cdn.mailroom.cn", ClassReview},
	}
	for _, tc := range cases {
		got := ClassifyHost(tc.host)
		if got.Class != tc.class {
			t.Fatalf("%s: got %s (%s), want %s", tc.host, got.Class, got.Signal, tc.class)
		}
		if got.Signal == "" {
			t.Fatalf("%s: empty signal", tc.host)
		}
	}
}

func TestUploadPath(t *testing.T) {
	cases := []struct {
		path string
		want string
		ok   bool
	}{
		{"/v1/report", "report", true},
		{"/collect.php", "collect", true},
		{"/v1/statistics", "", false},
		{"/v1/status", "", false},
		{"/upload/image", "upload", true},
		{"/beacon", "beacon", true},
		{"/", "", false},
	}
	for _, tc := range cases {
		got, ok := UploadPath(tc.path)
		if got != tc.want || ok != tc.ok {
			t.Fatalf("%s: got %q %v, want %q %v", tc.path, got, ok, tc.want, tc.ok)
		}
	}
}

func TestClassifyEndpointKeepsUploadSignal(t *testing.T) {
	ep := Endpoint{Host: "api.nightmarket.cn", Path: "/v1/collect"}
	got := ClassifyEndpoint(ep)
	if got.Class != ClassReview || got.Signal != "upload:collect" {
		t.Fatalf("unexpected classification: %+v", got)
	}
}
