package doctor

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const globalRules = `# 電波絶ち
- DOMAIN-SUFFIX,alog.umeng.com,REJECT
- AND,((DOMAIN-SUFFIX,metrics.quietreader.jp),(NOT,((PROCESS-NAME,jp.quietreader.app)))),REJECT
`

const scopedRules = globalRules + "- AND,((DOMAIN-SUFFIX,cdn.nightmarket.cn),(PROCESS-NAME,com.nightmarket.shop)),REJECT\n"

const goodSniffer = `sniffer:
  enable: true
  parse-pure-ip: true
  sniff:
    TLS: {ports: [443]}
    HTTP: {ports: [80]}
    QUIC: {ports: [443]}
`

func write(t *testing.T, dir, name, content string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func runMihomo(t *testing.T, rules, config string) *Report {
	t.Helper()
	dir := t.TempDir()
	rulesPath := write(t, dir, "mihomo.rules.yaml", rules)
	configPath := write(t, dir, "config.yaml", config)
	report, err := Run(configPath, rulesPath, "")
	if err != nil {
		t.Fatal(err)
	}
	if report.Kind != KindMihomo {
		t.Fatalf("kind = %s", report.Kind)
	}
	return report
}

func find(t *testing.T, report *Report, name string) Check {
	t.Helper()
	for _, check := range report.Checks {
		if check.Name == name {
			return check
		}
	}
	t.Fatalf("no %q check in %+v", name, report.Checks)
	return Check{}
}

func pasted(rules string) string {
	out := ""
	for _, line := range strings.Split(rules, "\n") {
		if strings.HasPrefix(line, "- ") {
			out += "  " + line + "\n"
		}
	}
	return out
}

// 整いし
// 門には何の
// 咎もなし
func TestMihomoHealthy(t *testing.T) {
	config := goodSniffer + "tun:\n  enable: true\ndns:\n  enable: true\n  enhanced-mode: fake-ip\nrules:\n" + pasted(globalRules) + "  - GEOSITE,cn,DIRECT\n  - MATCH,PROXY\n"
	report := runMihomo(t, globalRules, config)
	if report.Fails() != 0 || report.Warnings() != 0 {
		t.Fatalf("checks = %+v", report.Checks)
	}
	if got := find(t, report, "BLANC rules"); !strings.Contains(got.Message, "2/2") || got.Line == 0 {
		t.Fatalf("presence = %+v", got)
	}
	if got := find(t, report, "process mode"); got.Status != StatusOK {
		t.Fatalf("app exceptions need process lookup: %+v", got)
	}
}

func TestMihomoProcessChecksOnlyWhenNeeded(t *testing.T) {
	plain := "- DOMAIN-SUFFIX,alog.umeng.com,REJECT\n"
	report := runMihomo(t, plain, goodSniffer+"find-process-mode: off\nrules:\n"+pasted(plain))
	for _, check := range report.Checks {
		if check.Name == "process mode" || check.Name == "tun" {
			t.Fatalf("global-only rules do not need %s: %+v", check.Name, check)
		}
	}
	report = runMihomo(t, scopedRules, goodSniffer+"find-process-mode: off\nrules:\n"+pasted(scopedRules))
	if got := find(t, report, "process mode"); got.Status != StatusFail {
		t.Fatalf("process = %+v", got)
	}
	if got := find(t, report, "tun"); got.Status != StatusWarn || !strings.Contains(got.Message, "VPN") {
		t.Fatalf("tun = %+v", got)
	}
	report = runMihomo(t, scopedRules, goodSniffer+"tun:\n  enable: true\nrules:\n"+pasted(scopedRules))
	if got := find(t, report, "process mode"); got.Status != StatusOK || !strings.Contains(got.Message, "strict") {
		t.Fatalf("default process mode = %+v", got)
	}
}

// 先の札
// 奪う名をこそ
// 名指しせり
func TestMihomoShadowing(t *testing.T) {
	cases := []struct {
		rule   string
		status Status
		want   string
	}{
		{"DOMAIN-SUFFIX,umeng.com,DIRECT", StatusFail, "alog.umeng.com"},
		{"DOMAIN-KEYWORD,quietreader,PROXY", StatusFail, "metrics.quietreader.jp"},
		{"PROCESS-NAME,com.nightmarket.shop,DIRECT", StatusFail, "for com.nightmarket.shop"},
		{"PROCESS-NAME,org.mozilla.firefox,PROXY", StatusFail, "for org.mozilla.firefox"},
		{"AND,((DOMAIN-SUFFIX,umeng.com),(PROCESS-NAME,org.other)),DIRECT", StatusFail, "alog.umeng.com for org.other"},
		{"GEOSITE,cn,DIRECT", StatusFail, "GEOSITE"},
		{"GEOSITE,google,PROXY", StatusWarn, "GEOSITE"},
		{"GEOIP,CN,DIRECT", StatusFail, "no-resolve"},
		{"RULE-SET,private,DIRECT", StatusWarn, "offline"},
		{"DST-PORT,443,PROXY", StatusWarn, "not domain-specific"},
		{"MATCH,DIRECT", StatusFail, "takes 3"},
	}
	for _, tc := range cases {
		t.Run(tc.rule, func(t *testing.T) {
			config := goodSniffer + "rules:\n  - " + tc.rule + "\n" + pasted(scopedRules)
			report := runMihomo(t, scopedRules, config)
			got := find(t, report, "rule order")
			if got.Status != tc.status || !strings.Contains(got.Message, tc.want) || got.Line != 9 {
				t.Fatalf("order = %+v", got)
			}
		})
	}
	harmless := []string{
		"DOMAIN-SUFFIX,umeng.com,REJECT",
		"DOMAIN-SUFFIX,google.com,PROXY",
		"AND,((PROCESS-NAME,jp.quietreader.app),(DOMAIN-SUFFIX,metrics.quietreader.jp)),PROXY",
		"GEOIP,CN,DIRECT,no-resolve",
	}
	for _, rule := range harmless {
		config := goodSniffer + "rules:\n  - " + rule + "\n" + pasted(scopedRules)
		report := runMihomo(t, scopedRules, config)
		if got := find(t, report, "rule order"); got.Status != StatusOK {
			t.Fatalf("%s: order = %+v", rule, got)
		}
	}
}

func TestMihomoSplitPaste(t *testing.T) {
	lines := strings.Split(strings.TrimRight(pasted(scopedRules), "\n"), "\n")
	config := goodSniffer + "rules:\n" + lines[0] + "\n  - MATCH,DIRECT\n" + strings.Join(lines[1:], "\n") + "\n"
	report := runMihomo(t, scopedRules, config)
	if got := find(t, report, "rule order"); got.Status != StatusFail || !strings.Contains(got.Message, "MATCH") {
		t.Fatalf("BLANC rules after MATCH must fail: %+v", got)
	}
	missing := goodSniffer + "rules:\n" + lines[0] + "\n"
	if got := find(t, runMihomo(t, scopedRules, missing), "BLANC rules"); got.Status != StatusFail || !strings.Contains(got.Message, "1/3") {
		t.Fatalf("presence = %+v", got)
	}
	if got := find(t, runMihomo(t, scopedRules, goodSniffer+"rules: []\n"), "BLANC rules"); got.Status != StatusFail {
		t.Fatalf("presence = %+v", got)
	}
}

// 目を閉じた
// 網の在り処を
// 見咎める
func TestMihomoVisibility(t *testing.T) {
	cases := []struct {
		config string
		status Status
		want   string
	}{
		{goodSniffer, StatusOK, "parse-pure-ip"},
		{"sniffer:\n  enable: true\n  parse-pure-ip: false\n  sniff:\n    TLS: {ports: [443]}\n    QUIC: {ports: [443]}\n", StatusWarn, "parse-pure-ip is off"},
		{"sniffer:\n  enable: true\n  sniff:\n    TLS: {ports: [443]}\n    QUIC: {ports: [443]}\n", StatusOK, "sniffer on"},
		{"sniffer:\n  enable: true\n  parse-pure-ip: true\n  sniff:\n    TLS: {ports: [443]}\n", StatusWarn, "QUIC"},
		{"sniffer:\n  enable: true\n  parse-pure-ip: true\n  sniff:\n    HTTP: {ports: [80]}\n", StatusWarn, "TLS"},
		{"sniffer:\n  enable: true\n", StatusWarn, "no protocols"},
		{"sniffer:\n  enable: true\n  parse-pure-ip: true\n  sniffing: [tls, quic]\n", StatusOK, "sniffer on"},
		{"dns:\n  enable: true\n  enhanced-mode: fake-ip\n", StatusWarn, "HTTPDNS"},
		{"tun:\n  enable: true\n", StatusFail, "bare IPs"},
		{"", StatusWarn, "HTTP/SOCKS"},
	}
	for _, tc := range cases {
		report := runMihomo(t, globalRules, tc.config+"rules:\n"+pasted(globalRules))
		got := find(t, report, "domain names")
		if got.Status != tc.status || !strings.Contains(got.Message, tc.want) {
			t.Fatalf("%q: visibility = %+v", tc.config, got)
		}
	}
}

func TestMihomoErrors(t *testing.T) {
	dir := t.TempDir()
	config := write(t, dir, "config.yaml", "rules: []\n")
	if _, err := Run(config, filepath.Join(dir, "missing.yaml"), ""); err == nil || !strings.Contains(err.Error(), "blanc compile") {
		t.Fatalf("err = %v", err)
	}
	bad := write(t, dir, "bad.yaml", "- GEOSITE,cn,DIRECT\n")
	if _, err := Run(config, bad, ""); err == nil || !strings.Contains(err.Error(), "not a BLANC rule") {
		t.Fatalf("err = %v", err)
	}
	if _, err := Run(filepath.Join(dir, "nope.yaml"), bad, ""); err == nil {
		t.Fatal("missing config accepted")
	}
	empty := write(t, dir, "empty.yaml", "# nothing\n")
	report, err := Run(config, empty, "")
	if err != nil {
		t.Fatal(err)
	}
	if got := find(t, report, "BLANC rules"); got.Status != StatusWarn {
		t.Fatalf("empty rules = %+v", got)
	}
}

const ruleSet = `{"version": 3, "rules": [{"domain": ["alog.umeng.com"], "domain_suffix": [".alog.umeng.com"]}]}`
const scopedRuleSet = `{"version": 3, "rules": [{"package_name": ["com.a.b"], "domain": ["x.cn"], "domain_suffix": [".x.cn"]}]}`

func runSingbox(t *testing.T, set, config string) *Report {
	t.Helper()
	dir := t.TempDir()
	out := filepath.Join(dir, "blanc-out")
	if err := os.MkdirAll(out, 0o755); err != nil {
		t.Fatal(err)
	}
	write(t, out, "singbox.json", set)
	configPath := write(t, dir, "config.json", config)
	report, err := Run(configPath, "", out)
	if err != nil {
		t.Fatal(err)
	}
	if report.Kind != KindSingbox || !strings.HasSuffix(report.RulesPath, "singbox.json") {
		t.Fatalf("report = %+v", report)
	}
	return report
}

// 嗅ぎ取りて
// のちに閉ざせば
// 名も分かる
func TestSingboxHealthy(t *testing.T) {
	config := `{
  // comments are fine
  "inbounds": [{"type": "tun", "tag": "tun-in"}],
  "route": {
    "rule_set": [{"tag": "blanc", "type": "local", "format": "source", "path": "/sdcard/blanc/singbox.json"}],
    "rules": [
      {"action": "sniff"},
      {"protocol": "dns", "action": "hijack-dns"},
      {"ip_is_private": true, "outbound": "direct"},
      {"rule_set": ["blanc"], "action": "reject"},
      {"rule_set": "geosite-cn", "outbound": "direct"}
    ]
  }
}`
	report := runSingbox(t, scopedRuleSet, config)
	if report.Fails() != 0 || report.Warnings() != 0 {
		t.Fatalf("checks = %+v", report.Checks)
	}
	if got := find(t, report, "tun"); got.Status != StatusOK {
		t.Fatalf("tun = %+v", got)
	}
}

func TestSingboxProblems(t *testing.T) {
	cases := []struct {
		name   string
		rules  string
		extra  string
		check  string
		status Status
		want   string
	}{
		{"reject before sniff", `{"rule_set": "blanc", "action": "reject"}, {"action": "sniff"}`, "", "domain names", StatusFail, "comes after BLANC"},
		{"no sniff", `{"rule_set": "blanc", "action": "reject"}`, "", "domain names", StatusFail, "bare IPs"},
		{"legacy inbound sniff", `{"rule_set": "blanc", "action": "reject"}`, `"inbounds": [{"type": "tun", "sniff": true}],`, "domain names", StatusWarn, "deprecated"},
		{"fakeip only", `{"rule_set": "blanc", "action": "reject"}`, `"dns": {"servers": [{"type": "fakeip", "tag": "fake"}]},`, "domain names", StatusWarn, "HTTPDNS"},
		{"legacy outbound", `{"action": "sniff"}, {"rule_set": "blanc", "outbound": "block"}`, "", "BLANC rule", StatusFail, "action"},
		{"missing reject", `{"action": "sniff"}`, "", "BLANC rule", StatusFail, "no route rule"},
		{"catch-all first", `{"action": "sniff"}, {"inbound": "tun-in", "outbound": "direct"}, {"rule_set": "blanc", "action": "reject"}`, "", "rule order", StatusFail, "inbound"},
		{"domain rule first", `{"action": "sniff"}, {"domain_suffix": ["cn"], "outbound": "direct"}, {"rule_set": "blanc", "action": "reject"}`, "", "rule order", StatusWarn, "domain_suffix"},
		{"logical first", `{"action": "sniff"}, {"type": "logical", "mode": "or", "rules": [], "outbound": "direct"}, {"rule_set": "blanc", "action": "reject"}`, "", "rule order", StatusWarn, "logical"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			config := `{` + tc.extra + `"route": {"rule_set": [{"tag": "blanc", "type": "local", "path": "./blanc-out/singbox.json"}], "rules": [` + tc.rules + `]}}`
			report := runSingbox(t, ruleSet, config)
			got := find(t, report, tc.check)
			if got.Status != tc.status || !strings.Contains(got.Message, tc.want) {
				t.Fatalf("%s = %+v", tc.check, got)
			}
		})
	}
	report := runSingbox(t, ruleSet, `{"route": {"rules": []}}`)
	if got := find(t, report, "rule set"); got.Status != StatusFail {
		t.Fatalf("rule set = %+v", got)
	}
	report = runSingbox(t, scopedRuleSet, `{"route": {"rule_set": [{"tag": "blanc", "path": "singbox.json"}], "rules": [{"action": "sniff"}, {"rule_set": "blanc", "action": "reject"}]}}`)
	if got := find(t, report, "tun"); got.Status != StatusWarn {
		t.Fatalf("tun = %+v", got)
	}
}

func TestDetect(t *testing.T) {
	if Detect([]byte("rules:\n  - MATCH,DIRECT\n")) != KindMihomo {
		t.Fatal("yaml detected as sing-box")
	}
	if Detect([]byte("// c\n{\"route\": {}}")) != KindSingbox {
		t.Fatal("json not detected")
	}
	if Detect([]byte(`{"rules": ["MATCH,DIRECT"]}`)) != KindMihomo {
		t.Fatal("flow-style yaml detected as sing-box")
	}
	if got := string(stripJSONComments([]byte(`{"a": "http://x/*y*/" /* c */}`))); got != `{"a": "http://x/*y*/" }` {
		t.Fatalf("strip = %q", got)
	}
}
