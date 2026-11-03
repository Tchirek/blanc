package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/blanc-sh/blanc/internal/engine"
	"github.com/blanc-sh/blanc/internal/render"
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
	if !strings.Contains(stdout, "anti-telescreen") || !strings.Contains(stdout, "blanc compile") {
		t.Fatalf("help:\n%s", stdout)
	}
}

func TestInitAndCompile(t *testing.T) {
	dir := t.TempDir()
	policyPath := filepath.Join(dir, "blanc.yaml")
	outPath := filepath.Join(dir, "blanc")

	if code, _, stderr := run("init", "--out", policyPath); code != 0 {
		t.Fatalf("init code=%d stderr=%s", code, stderr)
	}
	data, err := os.ReadFile(policyPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "compile:") || !strings.Contains(string(data), "version: 1") {
		t.Fatalf("policy:\n%s", data)
	}

	reportPath := filepath.Join("..", "..", "testdata", "report.json")
	code, stdout, stderr := run("compile", "--report", reportPath, "--policy", policyPath, "--out", outPath)
	if code != 0 {
		t.Fatalf("compile code=%d stderr=%s", code, stderr)
	}
	for _, want := range []string{"Pixel 7", "blocked", "16 files"} {
		if !strings.Contains(stdout, want) {
			t.Fatalf("stdout missing %q:\n%s", want, stdout)
		}
	}
	for _, name := range []string{
		render.FileSingbox, render.FileMihomoRules, render.FileManifest,
		render.FileQuarantineScript, render.FileRollbackScript, render.FileHosts,
		render.FileAdGuard,
	} {
		if _, err := os.Stat(filepath.Join(outPath, name)); err != nil {
			t.Fatalf("missing %s: %v", name, err)
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
	if manifest.Stats.Blocked != 5 || manifest.Stats.Quarantine != 2 {
		t.Fatalf("stats = %+v", manifest.Stats)
	}
}

func TestCompileGlobalize(t *testing.T) {
	dir := t.TempDir()
	policyPath := filepath.Join(dir, "blanc.yaml")
	if err := os.WriteFile(policyPath, []byte("version: 1\ncompile:\n  globalize: trackers\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	outPath := filepath.Join(dir, "blanc")
	code, _, stderr := run("compile", "--report", filepath.Join("..", "..", "testdata", "report.json"), "--policy", policyPath, "--out", outPath)
	if code != 0 {
		t.Fatalf("code=%d stderr=%s", code, stderr)
	}
	hosts, err := os.ReadFile(filepath.Join(outPath, render.FileHosts))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(hosts), "0.0.0.0 alog.umeng.com") {
		t.Fatalf("hosts:\n%s", hosts)
	}
	adguard, err := os.ReadFile(filepath.Join(outPath, render.FileAdGuard))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(adguard), "||alog.umeng.com^") {
		t.Fatalf("adguard:\n%s", adguard)
	}
}

func TestCompileDecisions(t *testing.T) {
	dir := t.TempDir()
	outPath := filepath.Join(dir, "blanc")
	decisionsPath := filepath.Join(dir, "decisions.json")
	if err := os.WriteFile(decisionsPath, []byte(`{"version":1,"decisions":{"com.nightmarket.shop|alog.umeng.com":"allow"}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	code, _, stderr := run("compile", "--report", filepath.Join("..", "..", "testdata", "report.json"), "--out", outPath, "--decisions", decisionsPath)
	if code != 0 {
		t.Fatalf("code=%d stderr=%s", code, stderr)
	}
	rules, err := os.ReadFile(filepath.Join(outPath, render.FileMihomoRules))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(rules), "alog.umeng.com") {
		t.Fatalf("allow decision was not applied:\n%s", rules)
	}
	written, err := os.ReadFile(filepath.Join(outPath, render.FileDecisions))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(written), "com.nightmarket.shop|alog.umeng.com") {
		t.Fatalf("decisions:\n%s", written)
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
}

func TestCompileErrors(t *testing.T) {
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
	if code != 0 || !strings.Contains(stdout, "BLANC") {
		t.Fatalf("code=%d stdout=%q", code, stdout)
	}
}
