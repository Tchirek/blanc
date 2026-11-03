package audit

import (
	"strings"
)

type Class string

const (
	ClassTracker    Class = "tracker"
	ClassFunctional Class = "functional"
	ClassReview     Class = "review"
)

type Classification struct {
	Class  Class
	Signal string
}

var functionalLabels = map[string]struct{}{
	"push": {}, "xmpush": {}, "mipush": {}, "fcm": {}, "gcm": {}, "mtalk": {},
	"firebase": {}, "jpush": {}, "getui": {},
	"account": {}, "accounts": {}, "login": {}, "passport": {}, "oauth": {},
	"sso": {}, "signin": {}, "auth": {}, "token": {},
	"update": {}, "updater": {}, "ota": {}, "download": {}, "dl": {},
	"pay": {}, "mipay": {}, "alipay": {}, "unionpay": {}, "wallet": {},
	"play": {}, "vending": {}, "market": {}, "appstore": {},
	"cloud": {}, "micloud": {}, "icloud": {}, "backup": {}, "sync": {}, "connect": {},
}

var functionalSuffixes = []string{
	"googleapis.com",
	"gstatic.com",
	"firebaseio.com",
	"firebaseapp.com",
	"oppomobile.com",
	"heytapmobi.com",
}

var functionalSubstrings = []string{
	"googleapis",
	"gstatic",
	"oppomobile",
	"heytapmobi",
}

var trackerLabels = map[string]struct{}{
	"log": {}, "logs": {}, "ads": {}, "ad": {}, "mon": {}, "px": {}, "ut": {},
	"mam": {}, "up4": {},
	"analytics": {}, "track": {}, "tracker": {}, "tracking": {},
	"beacon": {}, "telemetry": {}, "metrics": {}, "metric": {},
	"stat": {}, "stats": {}, "statistic": {}, "statistics": {},
	"report": {}, "reports": {}, "collect": {}, "collector": {},
	"crash": {}, "monitor": {}, "monitoring": {}, "apm": {}, "rum": {},
}

var trackerSubstrings = []string{
	"applog", "errlog", "rtlog", "uplog", "apmlog", "aegis-log",
	"analytics", "telemetry", "beacon", "track", "collect", "crash",
	"metrics", "report", "monitor", "coverage", "videoreport",
}

var trackerVendors = []string{
	"umeng", "appsflyer", "adjust", "oceanengine", "zijieapi", "qplus",
	"snssdk", "cnzz", "growingio", "sensorsdata", "mixpanel", "amplitude",
	"pangle", "sigmob", "adashx", "pingma", "talkingdata", "bugtrace",
	"huatuo", "apmplus", "zxid", "oaid", "wkanx",
}

var trackerSuffixes = []string{
	"umeng.com", "umengcloud.com", "appsflyer.com", "adjust.com",
	"crashlytics.com", "google-analytics.com", "googletagmanager.com",
	"doubleclick.net", "app-measurement.com", "bugly.qq.com",
	"talkingdata.com", "growingio.com", "sensorsdata.cn", "mixpanel.com",
	"amplitude.com", "segment.io", "segment.com", "heapanalytics.com",
	"matomo.cloud", "piwik.pro", "sentry.io", "bugsnag.com", "instabug.com",
	"newrelic.com", "datadoghq.com", "branch.io", "applovin.com",
	"unityads.unity3d.com", "ironsrc.com", "vungle.com", "mintegral.com",
	"chartboost.com", "adcolony.com", "inmobi.com", "smartadserver.com",
	"adnxs.com", "criteo.com", "taboola.com", "outbrain.com",
	"moatads.com", "adsafeprotected.com", "scorecardresearch.com",
	"quantserve.com", "krxd.net", "bluekai.com", "demdex.net",
	"omtrdc.net", "2o7.net", "everesttech.net", "adsrvr.org",
	"casalemedia.com", "pubmatic.com", "rubiconproject.com", "openx.net",
	"33across.com", "sharethrough.com", "smaato.net", "startapp.com",
	"tapjoy.com", "supersonicads.com", "fyber.com", "appnext.com",
}

var uploadSegments = map[string]struct{}{
	"report": {}, "reports": {}, "upload": {}, "uploads": {}, "collect": {},
	"track": {}, "beacon": {}, "log": {}, "logs": {}, "stat": {}, "stats": {},
	"metrics": {}, "telemetry": {}, "event": {}, "events": {},
}

// 黒き影
// 白き光を
// 見分けたる
func ClassifyHost(host string) Classification {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	labels := strings.Split(host, ".")

	for _, suffix := range functionalSuffixes {
		if matchesSuffix(host, suffix) {
			return Classification{Class: ClassFunctional, Signal: "suffix:" + suffix}
		}
	}
	for _, label := range labels {
		if _, ok := functionalLabels[label]; ok {
			return Classification{Class: ClassFunctional, Signal: "label:" + label}
		}
	}
	for _, part := range functionalSubstrings {
		if strings.Contains(host, part) {
			return Classification{Class: ClassFunctional, Signal: "substring:" + part}
		}
	}
	for _, suffix := range trackerSuffixes {
		if matchesSuffix(host, suffix) {
			return Classification{Class: ClassTracker, Signal: "suffix:" + suffix}
		}
	}
	for _, label := range labels {
		if _, ok := trackerLabels[label]; ok {
			return Classification{Class: ClassTracker, Signal: "label:" + label}
		}
		for _, part := range trackerSubstrings {
			if strings.Contains(label, part) {
				return Classification{Class: ClassTracker, Signal: "label:" + label}
			}
		}
		for _, vendor := range trackerVendors {
			if matchesVendorLabel(label, vendor) {
				return Classification{Class: ClassTracker, Signal: "vendor:" + vendor}
			}
		}
	}
	return Classification{Class: ClassReview, Signal: "unknown"}
}

func ClassifyEndpoint(ep Endpoint) Classification {
	classification := ClassifyHost(ep.Host)
	if classification.Class != ClassReview {
		return classification
	}
	if segment, ok := UploadPath(ep.Path); ok {
		classification.Signal = "upload:" + segment
	}
	return classification
}

func UploadPath(path string) (string, bool) {
	for _, segment := range strings.Split(strings.ToLower(path), "/") {
		if segment == "" {
			continue
		}
		if i := strings.IndexByte(segment, '.'); i >= 0 {
			segment = segment[:i]
		}
		if _, ok := uploadSegments[segment]; ok {
			return segment, true
		}
	}
	return "", false
}

func matchesSuffix(host, suffix string) bool {
	return host == suffix || strings.HasSuffix(host, "."+suffix)
}

func matchesVendorLabel(label, vendor string) bool {
	if label == vendor {
		return true
	}
	for _, sep := range []string{"-", "_"} {
		if strings.HasPrefix(label, vendor+sep) ||
			strings.HasSuffix(label, sep+vendor) ||
			strings.Contains(label, sep+vendor+sep) {
			return true
		}
	}
	return false
}
