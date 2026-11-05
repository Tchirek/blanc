package cli

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

const noirReleases = "https://github.com/Verlintas/NOIR/releases"

// 外の世と
// 繋ぐ糸をば
// 差し替えり
type environment struct {
	stdin       io.Reader
	interactive func() bool
	lookPath    func(string) (string, error)
	run         func(bin string, args []string, stdin io.Reader, stdout, stderr io.Writer) (int, error)
}

var env = defaultEnvironment()

func defaultEnvironment() environment {
	return environment{
		stdin:       os.Stdin,
		interactive: stdinIsTerminal,
		lookPath:    exec.LookPath,
		run:         runCommand,
	}
}

func stdinIsTerminal() bool {
	info, err := os.Stdin.Stat()
	return err == nil && info.Mode()&os.ModeCharDevice != 0
}

func runCommand(bin string, args []string, stdin io.Reader, stdout, stderr io.Writer) (int, error) {
	cmd := exec.Command(bin, args...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = stdin, stdout, stderr
	err := cmd.Run()
	var exit *exec.ExitError
	if errors.As(err, &exit) {
		return exit.ExitCode(), nil
	}
	if err != nil {
		return -1, err
	}
	return 0, nil
}

// 隣人の
// 住まいを探し
// 名を問えり
func findNoir(explicit string) (string, error) {
	if explicit != "" {
		if _, err := os.Stat(explicit); err != nil {
			return "", fmt.Errorf("--noir-bin %s: %w", explicit, err)
		}
		abs, err := filepath.Abs(explicit)
		if err != nil {
			return "", fmt.Errorf("--noir-bin %s: %w", explicit, err)
		}
		return abs, nil
	}
	path, err := env.lookPath("noir")
	if err != nil {
		return "", fmt.Errorf("noir is not on PATH; install NOIR from %s, or pass --noir-bin <path>", noirReleases)
	}
	return path, nil
}

// 走らせて
// 帰りの声を
// 確かめる
func runNoirScan(bin, dir string, extra []string, stdout, stderr io.Writer) error {
	args := append([]string{"scan", "--out", dir}, extra...)
	fmt.Fprintf(stderr, "blanc: running %s %s\n", bin, strings.Join(args, " "))
	code, err := env.run(bin, args, env.stdin, stdout, stderr)
	if err != nil {
		return fmt.Errorf("could not start %s: %w", bin, err)
	}
	if code != 0 {
		return fmt.Errorf("noir scan exited with code %d", code)
	}
	return nil
}

// 一息に
// 測りて網を
// 編みにけり
func runScan(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	fs.SetOutput(stderr)
	noirDir := fs.String("noir", "noir-out", "where noir writes its scan")
	policyPath := fs.String("policy", "", "policy file (default: ./blanc.yaml if present, else built-in)")
	outPath := fs.String("out", "blanc-out", "output directory for the rules")
	noirBin := fs.String("noir-bin", "", "path to the noir launcher (default: noir on PATH)")
	serial := fs.String("serial", "", "device serial, passed to noir")
	fs.Usage = func() {
		fmt.Fprintln(stderr, "usage: blanc scan [--noir noir-out] [--policy blanc.yaml] [--out blanc-out] [--serial <id>] [-- <more noir scan arguments>]")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return 0
		}
		return 2
	}
	extra := fs.Args()
	if len(extra) > 0 && !containsArg(args, "--") {
		fmt.Fprintf(stderr, "blanc scan: unexpected argument %q; pass noir arguments after --\n", extra[0])
		return 2
	}
	if *noirDir == "" || *outPath == "" {
		fmt.Fprintln(stderr, "blanc scan: --noir and --out cannot be empty")
		return 2
	}
	if *serial != "" {
		extra = append([]string{"--serial", *serial}, extra...)
	}
	bin, err := findNoir(*noirBin)
	if err != nil {
		fmt.Fprintf(stderr, "blanc scan: %v\n", err)
		return 1
	}
	if err := runNoirScan(bin, *noirDir, extra, stdout, stderr); err != nil {
		fmt.Fprintf(stderr, "blanc scan: %v\n", err)
		return 1
	}
	empty := ""
	return compileAndWrite(inputFlags{noir: noirDir, report: &empty, domains: &empty, policy: policyPath}, *outPath, stdout, stderr)
}

func containsArg(args []string, want string) bool {
	for _, arg := range args {
		if arg == want {
			return true
		}
	}
	return false
}

// 無き帳を
// 今測らんかと
// 問いかける
func offerNoirScan(dir string, stdout, stderr io.Writer) (bool, error) {
	bin, err := env.lookPath("noir")
	if err != nil || !env.interactive() {
		return false, nil
	}
	fmt.Fprintf(stderr, "%s not found. Run \"noir scan --out %s\" now? [y/N] ", dir, dir)
	answer := strings.ToLower(strings.TrimSpace(readLine(env.stdin)))
	if answer != "y" && answer != "yes" {
		return false, nil
	}
	if err := runNoirScan(bin, dir, nil, stdout, stderr); err != nil {
		return false, err
	}
	return true, nil
}

// 道しるべ
// 在るか無きかで
// 書き分ける
func missingNoirError(dir string) error {
	scan := "blanc scan"
	if dir != "noir-out" {
		scan += " --noir " + dir
	}
	if _, err := env.lookPath("noir"); err == nil {
		return fmt.Errorf("NOIR output %s not found; run \"%s\" to scan and compile in one step, or \"noir scan --out %s\" first", dir, scan, dir)
	}
	return fmt.Errorf("NOIR output %s not found and noir is not on PATH; install NOIR from %s, then run \"%s\" (or \"noir scan --out %s\" and compile again)", dir, noirReleases, scan, dir)
}

func readLine(r io.Reader) string {
	var b strings.Builder
	buf := make([]byte, 1)
	for {
		n, err := r.Read(buf)
		if n > 0 {
			if buf[0] == '\n' {
				break
			}
			b.WriteByte(buf[0])
		}
		if err != nil {
			break
		}
	}
	return b.String()
}
