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

func testdata(t *testing.T) string {
	t.Helper()
	abs, err := filepath.Abs(filepath.Join("..", "..", "testdata"))
	if err != nil {
		t.Fatal(err)
	}
	return abs
}

func write(t *testing.T, path, content string) string {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// 小さき枝
// 大樹に寄せて
// 花を咲す
func TestHelp(t *testing.T) {
	code, stdout, stderr := run()
	if code != 0 || stderr != "" {
		t.Fatalf("code=%d stderr=%q", code, stderr)
	}
	for _, want := range []string{"anti-telescreen", "blanc compile", "blanc doctor", "every app"} {
		if !strings.Contains(stdout, want) {
			t.Fatalf("help missing %q:\n%s", want, stdout)
		}
	}
}

// 何も書かず
// 置けば揃うを
// 良しとせり
func TestCompileWithDefaults(t *testing.T) {
	data := testdata(t)
	work := t.TempDir()
	t.Chdir(work)

	code, _, stderr := run("compile")
	if code != 1 || !strings.Contains(stderr, "noir scan --out noir-out") {
		t.Fatalf("missing noir-out must explain itself: code=%d stderr=%s", code, stderr)
	}

	if code, stdout, stderr := run("init"); code != 0 || !strings.Contains(stdout, "blanc compile") {
		t.Fatalf("init code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	write(t, "blanc.yaml", "version: 2\napps:\n  jp.quietreader.app: allow\n")
	code, stdout, stderr := run("compile", "--noir", data)
	if code != 0 {
		t.Fatalf("compile code=%d stderr=%s", code, stderr)
	}
	for _, want := range []string{"Pixel 7", "policy    blanc.yaml", "5 for every app", "5 exceptions", filepath.Join("blanc-out", "mihomo.rules.yaml"), "blanc doctor"} {
		if !strings.Contains(stdout, want) {
			t.Fatalf("stdout missing %q:\n%s", want, stdout)
		}
	}
	for _, name := range []string{render.FileMihomo, render.FileSingbox, render.FileSingboxRoute, render.FileManifest, render.FileSummary} {
		if _, err := os.Stat(filepath.Join("blanc-out", name)); err != nil {
			t.Fatalf("missing %s: %v", name, err)
		}
	}
	raw, err := os.ReadFile(filepath.Join("blanc-out", render.FileManifest))
	if err != nil {
		t.Fatal(err)
	}
	var manifest struct {
		Stats engine.Stats `json:"stats"`
	}
	if err := json.Unmarshal(raw, &manifest); err != nil {
		t.Fatal(err)
	}
	if manifest.Stats.Apps != 5 || manifest.Stats.GlobalRules != 5 || manifest.Stats.Exceptions != 5 {
		t.Fatalf("stats = %+v", manifest.Stats)
	}
	route, err := os.ReadFile(filepath.Join("blanc-out", render.FileSingboxRoute))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(route), `"./blanc-out/singbox.json"`) {
		t.Fatalf("route:\n%s", route)
	}
}

func TestCompileWithoutReport(t *testing.T) {
	data := testdata(t)
	noir := filepath.Join(t.TempDir(), "noir-out")
	for _, name := range []string{"domains-trackers.txt", "domains-functional.txt", "domains-other.txt"} {
		raw, err := os.ReadFile(filepath.Join(data, name))
		if err != nil {
			t.Fatal(err)
		}
		write(t, filepath.Join(noir, name), string(raw)+"%s.umeng.com\n")
	}
	out := filepath.Join(t.TempDir(), "out")
	code, stdout, stderr := run("compile", "--noir", noir, "--out", out)
	if code != 0 {
		t.Fatalf("code=%d stderr=%s", code, stderr)
	}
	for _, want := range []string{"report    none", "built-in", "junk rows skipped", "5 for every app"} {
		if !strings.Contains(stdout, want) {
			t.Fatalf("stdout missing %q:\n%s", want, stdout)
		}
	}
}

func TestCompileErrors(t *testing.T) {
	dir := t.TempDir()
	report := write(t, filepath.Join(dir, "report.json"), `{"device":{"serial":"X","model":"Y"},"apps":[]}`)
	if code, _, stderr := run("compile", "--report", report, "--domains", testdata(t), "--out", filepath.Join(dir, "out")); code != 1 || !strings.Contains(stderr, "0 apps") {
		t.Fatalf("code=%d stderr=%s", code, stderr)
	}
	v1 := write(t, filepath.Join(dir, "v1.yaml"), "version: 1\nsensitive:\n  data_types: [calls]\n")
	if code, _, stderr := run("compile", "--noir", testdata(t), "--policy", v1, "--out", filepath.Join(dir, "out")); code != 1 || !strings.Contains(stderr, "version 1 is no longer supported") {
		t.Fatalf("code=%d stderr=%s", code, stderr)
	}
	if code, _, stderr := run("compile", "--report", filepath.Join(dir, "missing.json")); code != 1 || !strings.Contains(stderr, "read report") {
		t.Fatalf("code=%d stderr=%s", code, stderr)
	}
	if code, _, stderr := run("compile", "noir-out"); code != 2 || !strings.Contains(stderr, "--noir") {
		t.Fatalf("code=%d stderr=%s", code, stderr)
	}
	shared := write(t, filepath.Join(dir, "shared.yaml"), "version: 2\napps:\n  com.vendorwatch.telemetry: allow\n")
	code, _, stderr := run("compile", "--noir", testdata(t), "--policy", shared, "--out", filepath.Join(dir, "out2"))
	if code != 0 || !strings.Contains(stderr, "warning: apps.com.vendorwatch.telemetry") {
		t.Fatalf("code=%d stderr=%s", code, stderr)
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

func TestDoctor(t *testing.T) {
	dir := t.TempDir()
	rules := "- DOMAIN-SUFFIX,tracker.a,REJECT\n- AND,((DOMAIN-SUFFIX,tracker.b),(PROCESS-NAME,com.b)),REJECT\n"
	write(t, filepath.Join(dir, "blanc-out", "mihomo.rules.yaml"), rules)
	sniffer := "sniffer:\n  enable: true\n  parse-pure-ip: true\n  sniff:\n    TLS: {ports: [443]}\n    QUIC: {ports: [443]}\n"
	configPath := write(t, filepath.Join(dir, "mihomo.yaml"), "tun:\n  enable: true\n"+sniffer+"rules:\n  - DOMAIN-SUFFIX,tracker.a,REJECT\n  - AND,((DOMAIN-SUFFIX,tracker.b),(PROCESS-NAME,com.b)),REJECT\n  - MATCH,DIRECT\n")
	out := filepath.Join(dir, "blanc-out")
	code, stdout, stderr := run("doctor", configPath, "--out", out)
	if code != 0 || !strings.Contains(stdout, "BLANC doctor (mihomo)") || !strings.Contains(stdout, "result  0 fail") {
		t.Fatalf("code=%d stderr=%s stdout=%s", code, stderr, stdout)
	}

	write(t, configPath, "tun:\n  enable: true\n"+sniffer+"rules:\n  - GEOSITE,cn,DIRECT\n  - DOMAIN-SUFFIX,tracker.a,REJECT\n  - AND,((DOMAIN-SUFFIX,tracker.b),(PROCESS-NAME,com.b)),REJECT\n")
	code, stdout, stderr = run("doctor", "--config", configPath, "--out", out)
	if code != 1 || !strings.Contains(stdout, "GEOSITE,cn") || !strings.Contains(stdout, "fail") {
		t.Fatalf("code=%d stderr=%s stdout=%s", code, stderr, stdout)
	}
	if code, _, stderr := run("doctor"); code != 2 || !strings.Contains(stderr, "usage") {
		t.Fatalf("code=%d stderr=%s", code, stderr)
	}
}

func TestInitExisting(t *testing.T) {
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
