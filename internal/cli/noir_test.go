package cli

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type fakeNoir struct {
	calls [][]string
	code  int
	write bool
	data  string
}

// 偽の隣
// 呼べば帳を
// 置いてゆく
func useFakeEnv(t *testing.T, found bool, interactive bool, stdin string, fake *fakeNoir) {
	t.Helper()
	old := env
	t.Cleanup(func() { env = old })
	env = environment{
		stdin:       strings.NewReader(stdin),
		interactive: func() bool { return interactive },
		lookPath: func(name string) (string, error) {
			if !found {
				return "", errors.New("not found")
			}
			return "/opt/noir/bin/" + name, nil
		},
		run: func(bin string, args []string, stdin io.Reader, stdout, stderr io.Writer) (int, error) {
			fake.calls = append(fake.calls, append([]string{bin}, args...))
			if fake.write {
				out := args[2]
				for _, name := range []string{"report.json", "domains-trackers.txt", "domains-functional.txt", "domains-other.txt"} {
					raw, err := os.ReadFile(filepath.Join(fake.data, name))
					if err != nil {
						t.Fatal(err)
					}
					write(t, filepath.Join(out, name), string(raw))
				}
			}
			return fake.code, nil
		},
	}
}

func TestScanRunsNoirThenCompiles(t *testing.T) {
	fake := &fakeNoir{write: true, data: testdata(t)}
	useFakeEnv(t, true, false, "", fake)
	t.Chdir(t.TempDir())

	code, stdout, stderr := run("scan", "--serial", "abc123", "--", "--only", `com\.miui\.`)
	if code != 0 {
		t.Fatalf("code=%d stderr=%s", code, stderr)
	}
	want := []string{"/opt/noir/bin/noir", "scan", "--out", "noir-out", "--serial", "abc123", "--only", `com\.miui\.`}
	if len(fake.calls) != 1 || strings.Join(fake.calls[0], " ") != strings.Join(want, " ") {
		t.Fatalf("calls = %q", fake.calls)
	}
	if !strings.Contains(stderr, "blanc: running /opt/noir/bin/noir scan --out noir-out") {
		t.Fatalf("stderr = %s", stderr)
	}
	if !strings.Contains(stdout, "5 for every app") {
		t.Fatalf("stdout = %s", stdout)
	}
	if _, err := os.Stat(filepath.Join("blanc-out", "mihomo.rules.yaml")); err != nil {
		t.Fatal(err)
	}
}

// 隣なく
// 頼れぬ時は
// 道を告ぐ
func TestScanFailures(t *testing.T) {
	t.Chdir(t.TempDir())

	useFakeEnv(t, false, false, "", &fakeNoir{})
	if code, _, stderr := run("scan"); code != 1 || !strings.Contains(stderr, noirReleases) || !strings.Contains(stderr, "--noir-bin") {
		t.Fatalf("missing noir: code=%d stderr=%s", code, stderr)
	}

	failing := &fakeNoir{code: 3}
	useFakeEnv(t, true, false, "", failing)
	if code, _, stderr := run("scan"); code != 1 || !strings.Contains(stderr, "exited with code 3") {
		t.Fatalf("failing noir: code=%d stderr=%s", code, stderr)
	}
	if _, err := os.Stat("blanc-out"); !os.IsNotExist(err) {
		t.Fatal("compile must not run after a failed scan")
	}

	if code, _, stderr := run("scan", "--noir-bin", filepath.Join("nope", "noir")); code != 1 || !strings.Contains(stderr, "--noir-bin") {
		t.Fatalf("bad --noir-bin: code=%d stderr=%s", code, stderr)
	}
	if code, _, stderr := run("scan", "stray"); code != 2 || !strings.Contains(stderr, "after --") {
		t.Fatalf("stray argument: code=%d stderr=%s", code, stderr)
	}
}

func TestScanExplicitBinary(t *testing.T) {
	fake := &fakeNoir{write: true, data: testdata(t)}
	useFakeEnv(t, false, false, "", fake)
	dir := t.TempDir()
	t.Chdir(dir)
	write(t, filepath.Join(dir, "tools", "noir.bat"), "@echo off\n")
	if code, _, stderr := run("scan", "--noir-bin", "tools/noir.bat", "--noir", "scan-out", "--out", "rules"); code != 0 {
		t.Fatalf("code=%d stderr=%s", code, stderr)
	}
	got := fake.calls[0][0]
	if !filepath.IsAbs(got) || got != filepath.Clean(got) || filepath.Base(got) != "noir.bat" || fake.calls[0][3] != "scan-out" {
		t.Fatalf("--noir-bin must become a clean absolute path (cmd.exe cannot run tools/noir.bat): %q", fake.calls)
	}
	if _, err := os.Stat(filepath.Join("rules", "singbox.json")); err != nil {
		t.Fatal(err)
	}
}

// 子を起こし
// 戻る印を
// 受け取れり
func TestRunCommandExitCode(t *testing.T) {
	if os.Getenv("BLANC_HELPER_EXIT") != "" {
		return
	}
	t.Setenv("BLANC_HELPER_EXIT", "7")
	var out strings.Builder
	code, err := runCommand(os.Args[0], []string{"-test.run=^TestHelperProcess$"}, strings.NewReader(""), &out, io.Discard)
	if err != nil || code != 7 || !strings.Contains(out.String(), "helper scan") {
		t.Fatalf("code=%d err=%v out=%q", code, err, out.String())
	}
	if _, err := runCommand(filepath.Join(t.TempDir(), "missing-noir"), nil, nil, io.Discard, io.Discard); err == nil {
		t.Fatal("missing binary must be an error")
	}
}

func TestHelperProcess(t *testing.T) {
	if os.Getenv("BLANC_HELPER_EXIT") == "" {
		return
	}
	os.Stdout.WriteString("helper scan\n")
	os.Exit(7)
}

// 無き帳を
// 問われ頷き
// 測りけり
func TestCompileOffersScan(t *testing.T) {
	data := testdata(t)
	t.Chdir(t.TempDir())

	accept := &fakeNoir{write: true, data: data}
	useFakeEnv(t, true, true, "y\n", accept)
	code, stdout, stderr := run("compile")
	if code != 0 || len(accept.calls) != 1 || !strings.Contains(stderr, `Run "noir scan --out noir-out" now? [y/N]`) {
		t.Fatalf("accept: code=%d calls=%q stderr=%s", code, accept.calls, stderr)
	}
	if !strings.Contains(stdout, "Pixel 7") {
		t.Fatalf("the fresh report.json must be read: %s", stdout)
	}
	if err := os.RemoveAll("noir-out"); err != nil {
		t.Fatal(err)
	}

	decline := &fakeNoir{}
	useFakeEnv(t, true, true, "\n", decline)
	code, _, stderr = run("compile")
	if code != 1 || len(decline.calls) != 0 || !strings.Contains(stderr, `run "blanc scan" to scan and compile`) {
		t.Fatalf("decline: code=%d calls=%q stderr=%s", code, decline.calls, stderr)
	}

	piped := &fakeNoir{}
	useFakeEnv(t, true, false, "y\n", piped)
	code, _, stderr = run("compile", "--noir", "elsewhere")
	if code != 1 || len(piped.calls) != 0 || strings.Contains(stderr, "[y/N]") || !strings.Contains(stderr, `"blanc scan --noir elsewhere"`) {
		t.Fatalf("non-interactive: code=%d calls=%q stderr=%s", code, piped.calls, stderr)
	}

	failing := &fakeNoir{code: 1}
	useFakeEnv(t, true, true, "yes\n", failing)
	if code, _, stderr := run("compile"); code != 1 || !strings.Contains(stderr, "exited with code 1") {
		t.Fatalf("failing scan: code=%d stderr=%s", code, stderr)
	}

	useFakeEnv(t, false, true, "y\n", &fakeNoir{})
	if code, _, stderr := run("compile"); code != 1 || strings.Contains(stderr, "[y/N]") || !strings.Contains(stderr, noirReleases) {
		t.Fatalf("no noir: code=%d stderr=%s", code, stderr)
	}

	explicit := &fakeNoir{}
	useFakeEnv(t, true, true, "y\n", explicit)
	if code, _, _ := run("compile", "--domains", "missing"); code != 1 || len(explicit.calls) != 0 {
		t.Fatalf("an explicit --domains must not trigger a scan: calls=%q", explicit.calls)
	}
	if code, _, _ := run("explain", "alog.umeng.com"); code != 1 || len(explicit.calls) != 0 {
		t.Fatalf("explain must not scan: calls=%q", explicit.calls)
	}
}

func TestReadLineStopsAtNewline(t *testing.T) {
	r := strings.NewReader("y\nrest")
	if got := readLine(r); got != "y" {
		t.Fatalf("got %q", got)
	}
	if rest, _ := io.ReadAll(r); string(rest) != "rest" {
		t.Fatalf("readLine consumed too much: %q", rest)
	}
	if got := readLine(strings.NewReader("no newline")); got != "no newline" {
		t.Fatalf("got %q", got)
	}
}
