package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Tchirek/blanc/internal/engine"
	"github.com/Tchirek/blanc/internal/render"
)

func run(args ...string) (int, string, string) {
	var stdout, stderr bytes.Buffer
	code := Run(args, &stdout, &stderr)
	return code, stdout.String(), stderr.String()
}

// 小さき枝
// 大樹に寄せて
// 花を咲す
func TestHelp(t *testing.T) {
	code, stdout, stderr := run()
	if code != 0 || stderr != "" {
		t.Fatalf("code=%d stderr=%q", code, stderr)
	}
	for _, want := range []string{"anti-telescreen", "blanc compile", "blanc doctor", "app-scoped"} {
		if !strings.Contains(stdout, want) {
			t.Fatalf("help missing %q:\n%s", want, stdout)
		}
	}
}

func TestInitAndCompile(t *testing.T) {
	dir := t.TempDir()
	policyPath := filepath.Join(dir, "blanc.yaml")
	outPath := filepath.Join(dir, "blanc-out")

	if code, _, stderr := run("init", "--out", policyPath); code != 0 {
		t.Fatalf("init code=%d stderr=%s", code, stderr)
	}
	data, err := os.ReadFile(policyPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "apps:") || !strings.Contains(string(data), "version: 2") {
		t.Fatalf("policy:\n%s", data)
	}

	reportPath := filepath.Join("..", "..", "testdata", "report.json")
	code, stdout, stderr := run("compile", "--report", reportPath, "--policy", policyPath, "--out", outPath)
	if code != 0 {
		t.Fatalf("compile code=%d stderr=%s", code, stderr)
	}
	for _, want := range []string{"Pixel 7", "5 for every app", "mihomo.rules.yaml", "blanc doctor"} {
		if !strings.Contains(stdout, want) {
			t.Fatalf("stdout missing %q:\n%s", want, stdout)
		}
	}
	for _, name := range []string{
		render.FileMihomo, render.FileSingbox, render.FileSingboxRoute,
		render.FileManifest, render.FileSummary,
	} {
		if _, err := os.Stat(filepath.Join(outPath, name)); err != nil {
			t.Fatalf("missing %s: %v", name, err)
		}
	}
	for _, gone := range []string{"adguard.txt", "hosts.txt", "quarantine.sh", "decisions.json"} {
		if _, err := os.Stat(filepath.Join(outPath, gone)); !os.IsNotExist(err) {
			t.Fatalf("unexpected %s", gone)
		}
	}
	raw, err := os.ReadFile(filepath.Join(outPath, render.FileManifest))
	if err != nil {
		t.Fatal(err)
	}
	var manifest struct {
		Stats engine.Stats `json:"stats"`
	}
	if err := json.Unmarshal(raw, &manifest); err != nil {
		t.Fatal(err)
	}
	if manifest.Stats.Apps != 5 || manifest.Stats.Endpoints != 20 || manifest.Stats.GlobalRules != 5 {
		t.Fatalf("stats = %+v", manifest.Stats)
	}
	var route struct {
		Route struct {
			RuleSet []struct {
				Path string `json:"path"`
			} `json:"rule_set"`
		} `json:"route"`
	}
	routeRaw, err := os.ReadFile(filepath.Join(outPath, render.FileSingboxRoute))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(routeRaw, &route); err != nil {
		t.Fatal(err)
	}
	wantPath := filepath.ToSlash(filepath.Join(outPath, render.FileSingbox))
	if route.Route.RuleSet[0].Path != wantPath {
		t.Fatalf("route path = %q, want %q", route.Route.RuleSet[0].Path, wantPath)
	}
}

func TestSingboxRuleSetPath(t *testing.T) {
	if got := singboxRuleSetPath("blanc-out"); got != "./blanc-out/singbox.json" {
		t.Fatalf("relative path = %q", got)
	}
	if got := singboxRuleSetPath("."); got != "./singbox.json" {
		t.Fatalf("dot path = %q", got)
	}
	abs := filepath.Join(t.TempDir(), "out")
	want := filepath.ToSlash(filepath.Join(abs, render.FileSingbox))
	if got := singboxRuleSetPath(abs); got != want {
		t.Fatalf("absolute path = %q, want %q", got, want)
	}
}

func TestCompileMissingDomains(t *testing.T) {
	dir := t.TempDir()
	raw, err := os.ReadFile(filepath.Join("..", "..", "testdata", "report.json"))
	if err != nil {
		t.Fatal(err)
	}
	reportPath := filepath.Join(dir, "report.json")
	if err := os.WriteFile(reportPath, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	code, _, stderr := run("compile", "--report", reportPath, "--out", filepath.Join(dir, "out"))
	if code != 1 || !strings.Contains(stderr, "missing NOIR domain export") {
		t.Fatalf("code=%d stderr=%s", code, stderr)
	}
}

func TestCompileRejectsEmptyInputs(t *testing.T) {
	dir := t.TempDir()
	reportPath := filepath.Join(dir, "report.json")
	if err := os.WriteFile(reportPath, []byte(`{"device":{"serial":"X","model":"Y"},"apps":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if code, _, stderr := run("compile", "--report", reportPath, "--out", filepath.Join(dir, "out")); code != 1 || !strings.Contains(stderr, "0 apps") {
		t.Fatalf("code=%d stderr=%s", code, stderr)
	}
}

func TestCompileRejectsVersionOnePolicy(t *testing.T) {
	dir := t.TempDir()
	policyPath := filepath.Join(dir, "blanc.yaml")
	policy := "version: 1\nsensitive:\n  data_types: [calls]\n  categories: []\n"
	if err := os.WriteFile(policyPath, []byte(policy), 0o600); err != nil {
		t.Fatal(err)
	}
	code, _, stderr := run("compile", "--report", filepath.Join("..", "..", "testdata", "report.json"), "--policy", policyPath, "--out", filepath.Join(dir, "out"))
	if code != 1 || !strings.Contains(stderr, "version 1 is no longer supported") {
		t.Fatalf("code=%d stderr=%s", code, stderr)
	}
}

func TestDoctor(t *testing.T) {
	dir := t.TempDir()
	rulesPath := filepath.Join(dir, "rules.yaml")
	rules := "- AND,((PROCESS-NAME,com.a),(DOMAIN-SUFFIX,tracker.a)),REJECT\n" +
		"- AND,((PROCESS-NAME,com.b),(DOMAIN-SUFFIX,tracker.b)),REJECT\n"
	if err := os.WriteFile(rulesPath, []byte(rules), 0o600); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(dir, "mihomo.yaml")
	good := "find-process-mode: always\ntun:\n  enable: true\nrules:\n  - AND,((PROCESS-NAME,com.a),(DOMAIN-SUFFIX,tracker.a)),REJECT\n  - AND,((PROCESS-NAME,com.b),(DOMAIN-SUFFIX,tracker.b)),REJECT\n  - MATCH,DIRECT\n"
	if err := os.WriteFile(configPath, []byte(good), 0o600); err != nil {
		t.Fatal(err)
	}
	code, stdout, stderr := run("doctor", "--config", configPath, "--rules", rulesPath)
	if code != 0 {
		t.Fatalf("code=%d stderr=%s stdout=%s", code, stderr, stdout)
	}
	if !strings.Contains(stdout, "result  0 fail") {
		t.Fatalf("stdout:\n%s", stdout)
	}

	shadowed := "find-process-mode: always\ntun:\n  enable: true\nrules:\n  - GEOSITE,cn,DIRECT\n  - AND,((PROCESS-NAME,com.a),(DOMAIN-SUFFIX,tracker.a)),REJECT\n  - AND,((PROCESS-NAME,com.b),(DOMAIN-SUFFIX,tracker.b)),REJECT\n"
	if err := os.WriteFile(configPath, []byte(shadowed), 0o600); err != nil {
		t.Fatal(err)
	}
	code, stdout, stderr = run("doctor", "--config", configPath, "--rules", rulesPath)
	if code != 1 || !strings.Contains(stdout, "GEOSITE,cn") || !strings.Contains(stdout, "fail") {
		t.Fatalf("code=%d stderr=%s stdout=%s", code, stderr, stdout)
	}
	if code, _, stderr := run("doctor"); code != 2 || !strings.Contains(stderr, "usage") {
		t.Fatalf("code=%d stderr=%s", code, stderr)
	}
}

func TestInitExistingAndErrors(t *testing.T) {
	path := filepath.Join(t.TempDir(), "blanc.yaml")
	if code, _, _ := run("init", "--out", path); code != 0 {
		t.Fatal("first init failed")
	}
	if code, _, stderr := run("init", "--out", path); code == 0 || !strings.Contains(stderr, "--force") {
		t.Fatalf("code=%d stderr=%s", code, stderr)
	}
	if code, _, stderr := run("init", "--out", path, "--force"); code != 0 {
		t.Fatalf("force init code=%d stderr=%s", code, stderr)
	}
	if code, _, stderr := run("compile"); code != 2 || !strings.Contains(stderr, "usage") {
		t.Fatalf("code=%d stderr=%s", code, stderr)
	}
	if code, _, stderr := run("compile", "--report", "missing.json"); code != 1 || !strings.Contains(stderr, "read report") {
		t.Fatalf("code=%d stderr=%s", code, stderr)
	}
	if code, _, stderr := run("wat"); code != 2 || !strings.Contains(stderr, "unknown command") {
		t.Fatalf("code=%d stderr=%s", code, stderr)
	}
}

func TestVersion(t *testing.T) {
	code, stdout, _ := run("version")
	if code != 0 || !strings.Contains(stdout, "BLANC dev") {
		t.Fatalf("code=%d stdout=%q", code, stdout)
	}
}
