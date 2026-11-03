package doctor

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

var testRules = []string{
	"AND,((PROCESS-NAME,com.a),(DOMAIN-SUFFIX,tracker.a)),REJECT",
	"AND,((PROCESS-NAME,com.b),(DOMAIN-SUFFIX,tracker.b)),REJECT",
}

// 門番
// 名を確かめて
// 通しけり
func TestRunGoodConfig(t *testing.T) {
	config := `find-process-mode: always
tun:
  enable: true
rules:
  - AND,((PROCESS-NAME,com.a),(DOMAIN-SUFFIX,tracker.a)),REJECT
  - AND,((PROCESS-NAME,com.b),(DOMAIN-SUFFIX,tracker.b)),REJECT
  - MATCH,DIRECT
`
	report := runTest(t, config)
	if report.Fails() != 0 || report.Warnings() != 0 {
		t.Fatalf("checks = %+v", report.Checks)
	}
	if !hasCheck(report, StatusOK, "2/2 BLANC rules") {
		t.Fatalf("checks = %+v", report.Checks)
	}
	if !hasCheck(report, StatusOK, "no obvious shadowing") {
		t.Fatalf("checks = %+v", report.Checks)
	}
}

func TestRunNormalizesWhitespace(t *testing.T) {
	config := `find-process-mode: always
tun:
  enable: true
rules:
  - AND, ((PROCESS-NAME,com.a),(DOMAIN-SUFFIX,tracker.a)), REJECT
  - AND,((PROCESS-NAME,com.b), (DOMAIN-SUFFIX,tracker.b)),REJECT
  - MATCH,DIRECT
`
	report := runTest(t, config)
	if report.Fails() != 0 || report.Warnings() != 0 {
		t.Fatalf("checks = %+v", report.Checks)
	}
	if !hasCheck(report, StatusOK, "2/2 BLANC rules") {
		t.Fatalf("checks = %+v", report.Checks)
	}
}

func TestRunNamesMissingRules(t *testing.T) {
	config := `find-process-mode: always
tun:
  enable: true
rules:
  - AND,((PROCESS-NAME,com.a),(DOMAIN-SUFFIX,tracker.a)),REJECT
  - MATCH,DIRECT
`
	report := runTest(t, config)
	if !hasCheck(report, StatusFail, "only 1/2") || !hasCheck(report, StatusFail, "com.b") {
		t.Fatalf("checks = %+v", report.Checks)
	}
}

func TestOrderCheckWithoutPresence(t *testing.T) {
	config := `find-process-mode: always
tun:
  enable: true
rules:
  - GEOSITE,cn,DIRECT
  - MATCH,DIRECT
`
	report := runTest(t, config)
	if !hasCheck(report, StatusFail, "BLANC rules not found") {
		t.Fatalf("checks = %+v", report.Checks)
	}
	if !hasCheck(report, StatusFail, "not in the config yet") || !hasCheck(report, StatusFail, "GEOSITE,cn") {
		t.Fatalf("order check skipped: %+v", report.Checks)
	}
}

func TestRunDetectsShadowing(t *testing.T) {
	cases := []struct {
		name   string
		before string
		want   string
	}{
		{"matcher", "MATCH,DIRECT", "MATCH"},
		{"geosite cn", "GEOSITE,cn,DIRECT", "GEOSITE,cn"},
		{"geoip cn", "GEOIP,CN,DIRECT", "GEOIP,CN"},
		{"tld suffix", "DOMAIN-SUFFIX,cn,DIRECT", "TLD-wide"},
		{"domain suffix", "DOMAIN-SUFFIX,tracker.a,DIRECT", "shadows a BLANC domain"},
		{"domain keyword", "DOMAIN-KEYWORD,tracker,DIRECT", "shadows a BLANC domain"},
		{"process name", "PROCESS-NAME,com.a,DIRECT", "matches a BLANC app"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			config := "find-process-mode: always\ntun:\n  enable: true\nrules:\n  - " + tc.before + "\n  - " + testRules[0] + "\n  - " + testRules[1] + "\n"
			report := runTest(t, config)
			if report.Fails() == 0 || !hasCheck(report, StatusFail, tc.want) {
				t.Fatalf("checks = %+v", report.Checks)
			}
		})
	}
}

func TestRunWarnsOnOpaqueRules(t *testing.T) {
	config := `find-process-mode: always
tun:
  enable: true
rules:
  - RULE-SET,trackers,DIRECT
  - AND,((NETWORK,UDP)),DIRECT
  - AND,((PROCESS-NAME,com.a),(DOMAIN-SUFFIX,tracker.a)),REJECT
  - AND,((PROCESS-NAME,com.b),(DOMAIN-SUFFIX,tracker.b)),REJECT
`
	report := runTest(t, config)
	if report.Fails() != 0 || report.Warnings() < 2 {
		t.Fatalf("checks = %+v", report.Checks)
	}
}

func TestRunMissingRules(t *testing.T) {
	config := `find-process-mode: always
tun:
  enable: true
rules:
  - MATCH,DIRECT
`
	report := runTest(t, config)
	if report.Fails() == 0 || !hasCheck(report, StatusFail, "not found") {
		t.Fatalf("checks = %+v", report.Checks)
	}
}

func TestRunEmptyRulesFile(t *testing.T) {
	dir := t.TempDir()
	rulesPath := filepath.Join(dir, "rules.yaml")
	if err := os.WriteFile(rulesPath, []byte("# 電波絶ち\n# 紙の白さよ\n# 冴返る\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(configPath, []byte("rules:\n  - MATCH,DIRECT\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	report, err := Run(configPath, rulesPath)
	if err != nil {
		t.Fatal(err)
	}
	if !hasCheck(report, StatusFail, "rules file is empty") {
		t.Fatalf("checks = %+v", report.Checks)
	}
}

func TestProcessModeAndTun(t *testing.T) {
	t.Run("process off", func(t *testing.T) {
		report := runTest(t, "find-process-mode: off\ntun:\n  enable: true\nrules:\n  - "+testRules[0]+"\n  - "+testRules[1]+"\n")
		if !hasCheck(report, StatusFail, "cannot match") {
			t.Fatalf("checks = %+v", report.Checks)
		}
	})
	t.Run("process strict", func(t *testing.T) {
		report := runTest(t, "find-process-mode: strict\ntun:\n  enable: true\nrules:\n  - "+testRules[0]+"\n  - "+testRules[1]+"\n")
		if report.Fails() != 0 || !hasCheck(report, StatusWarn, "prefer always") {
			t.Fatalf("checks = %+v", report.Checks)
		}
	})
	t.Run("process missing", func(t *testing.T) {
		report := runTest(t, "tun:\n  enable: true\nrules:\n  - "+testRules[0]+"\n  - "+testRules[1]+"\n")
		if !hasCheck(report, StatusFail, "is off") {
			t.Fatalf("checks = %+v", report.Checks)
		}
	})
	t.Run("tun false", func(t *testing.T) {
		report := runTest(t, "find-process-mode: always\ntun:\n  enable: false\nrules:\n  - "+testRules[0]+"\n  - "+testRules[1]+"\n")
		if !hasCheck(report, StatusFail, "tun.enable is false") {
			t.Fatalf("checks = %+v", report.Checks)
		}
	})
	t.Run("tun missing", func(t *testing.T) {
		report := runTest(t, "find-process-mode: always\nrules:\n  - "+testRules[0]+"\n  - "+testRules[1]+"\n")
		if !hasCheck(report, StatusFail, "tun.enable is missing") {
			t.Fatalf("checks = %+v", report.Checks)
		}
	})
}

func TestRunErrors(t *testing.T) {
	if _, err := Run("missing.yaml", "missing.yaml"); err == nil {
		t.Fatal("expected error")
	}
}

func runTest(t *testing.T, config string) *Report {
	t.Helper()
	dir := t.TempDir()
	rulesPath := filepath.Join(dir, "rules.yaml")
	if err := os.WriteFile(rulesPath, []byte("- "+testRules[0]+"\n- "+testRules[1]+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(configPath, []byte(config), 0o600); err != nil {
		t.Fatal(err)
	}
	report, err := Run(configPath, rulesPath)
	if err != nil {
		t.Fatal(err)
	}
	return report
}

func hasCheck(report *Report, status Status, message string) bool {
	for _, check := range report.Checks {
		if check.Status == status && strings.Contains(check.Message, message) {
			return true
		}
	}
	return false
}
