package audit

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// 名を呼べば
// 闇の名簿が
// 応えけり
func TestLoadDomains(t *testing.T) {
	set, err := LoadDomains("../../testdata")
	if err != nil {
		t.Fatal(err)
	}
	if got := set.Count(ClassTracker); got != 5 {
		t.Fatalf("trackers = %d", got)
	}
	if got := set.Count(ClassFunctional); got != 5 {
		t.Fatalf("functional = %d", got)
	}
	if got := set.Count(ClassReview); got != 5 {
		t.Fatalf("review = %d", got)
	}
	if class, ok := set.Class("alog.umeng.com"); !ok || class != ClassTracker {
		t.Fatalf("alog class = %q %v", class, ok)
	}
	if class, ok := set.Class("login.nightpass.cn"); !ok || class != ClassFunctional {
		t.Fatalf("login class = %q %v", class, ok)
	}
	if class, ok := set.Class("api.nightmarket.cn"); !ok || class != ClassReview {
		t.Fatalf("api class = %q %v", class, ok)
	}
	if _, ok := set.Class("staging.telemetry.nightsight.io"); ok {
		t.Fatal("unclassified host found")
	}
	if len(set.Hashes) != 3 {
		t.Fatalf("hashes = %v", set.Hashes)
	}
	for name, hash := range set.Hashes {
		if len(hash) != 64 {
			t.Fatalf("%s hash = %q", name, hash)
		}
	}
}

func TestLoadDomainsErrors(t *testing.T) {
	if _, err := LoadDomains(""); err == nil {
		t.Fatal("expected empty directory error")
	}
	if _, err := LoadDomains(t.TempDir()); err == nil || !strings.Contains(err.Error(), "missing NOIR domain export") {
		t.Fatalf("err = %v", err)
	}
	dir := t.TempDir()
	writeDomainFiles(t, dir, "ok.example.cn", "login.example.cn", "api.example.cn")
	if err := os.Remove(filepath.Join(dir, "domains-other.txt")); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadDomains(dir); err == nil || !strings.Contains(err.Error(), "domains-other.txt") {
		t.Fatalf("err = %v", err)
	}
}

func TestLoadDomainsSkipsIPs(t *testing.T) {
	dir := t.TempDir()
	writeDomainFiles(t, dir, "100.69.165.28\ntracker.example.cn\n", "", "api.example.cn")
	set, err := LoadDomains(dir)
	if err != nil {
		t.Fatal(err)
	}
	if set.SkippedIPs != 1 {
		t.Fatalf("skipped = %d", set.SkippedIPs)
	}
	if _, ok := set.Class("100.69.165.28"); ok {
		t.Fatal("IP was classified")
	}
}

// 屑の名も
// 捨てて残りを
// 守りけり
func TestLoadDomainsSurvivesNoirJunk(t *testing.T) {
	dir := t.TempDir()
	trackers := strings.Join([]string{
		"%s.umeng.com",
		"*.adsight.io",
		"{region}.log.example.cn",
		"collect.example.cn?x=1",
		"user@track.example.cn",
		"beacon.example.cn)",
		"stat.example.cn#frag",
		"bad host",
		"STATS.Example.CN.",
		"alog.umeng.com",
	}, "\n")
	writeDomainFiles(t, dir, trackers, "login.example.cn", "api.example.cn")
	set, err := LoadDomains(dir)
	if err != nil {
		t.Fatalf("junk lines must not abort the compile: %v", err)
	}
	for _, host := range []string{
		"collect.example.cn", "track.example.cn", "beacon.example.cn",
		"stat.example.cn", "stats.example.cn", "alog.umeng.com",
	} {
		if class, ok := set.Class(host); !ok || class != ClassTracker {
			t.Fatalf("%s: class=%q ok=%v", host, class, ok)
		}
	}
	if got := len(set.Skipped); got != 4 {
		t.Fatalf("skipped = %d: %+v", got, set.Skipped)
	}
	if got := len(set.Repaired); got != 4 {
		t.Fatalf("repaired = %d: %+v", got, set.Repaired)
	}
	for _, issue := range set.Skipped {
		if issue.File != "domains-trackers.txt" || issue.Line == 0 || issue.Reason == "" {
			t.Fatalf("issue lacks location: %+v", issue)
		}
	}
}

// 二つ名は
// 壊さぬ側へ
// 傾けり
func TestLoadDomainsConflictPrefersFunctional(t *testing.T) {
	dir := t.TempDir()
	writeDomainFiles(t, dir, "same.example.cn\nboth.example.cn", "same.example.cn", "both.example.cn")
	set, err := LoadDomains(dir)
	if err != nil {
		t.Fatal(err)
	}
	if class, _ := set.Class("same.example.cn"); class != ClassFunctional {
		t.Fatalf("same = %q, want functional", class)
	}
	if class, _ := set.Class("both.example.cn"); class != ClassTracker {
		t.Fatalf("both = %q, want tracker", class)
	}
	if len(set.Conflicts) != 2 || set.Conflicts[0].Host != "both.example.cn" || set.Conflicts[1].Kept != ClassFunctional {
		t.Fatalf("conflicts = %+v", set.Conflicts)
	}
}

// 手の中の
// 紙も同じく
// 読みにけり
func TestParseDomainsInMemory(t *testing.T) {
	files := map[string][]byte{
		"domains-trackers.txt":   []byte("alog.umeng.com\n%s.x.cn\n"),
		"domains-functional.txt": []byte("login.example.cn\n"),
		"domains-other.txt":      []byte(""),
	}
	set, err := ParseDomains("upload", files)
	if err != nil {
		t.Fatal(err)
	}
	if set.Dir != "upload" || set.Count(ClassTracker) != 1 || len(set.Skipped) != 1 || len(set.Hashes) != 3 {
		t.Fatalf("set = %+v", set)
	}
	delete(files, "domains-other.txt")
	if _, err := ParseDomains("upload", files); err == nil || !strings.Contains(err.Error(), "domains-other.txt") {
		t.Fatalf("err = %v", err)
	}
	if got := strings.Join(DomainFiles(), ","); got != "domains-trackers.txt,domains-functional.txt,domains-other.txt" {
		t.Fatalf("files = %s", got)
	}
}

func TestLoadDomainsRejectsNothingButMissingFiles(t *testing.T) {
	t.Run("comments and blanks", func(t *testing.T) {
		dir := t.TempDir()
		writeDomainFiles(t, dir, "\n# comment\ntracker.example.cn\n", "", "api.example.cn")
		set, err := LoadDomains(dir)
		if err != nil {
			t.Fatal(err)
		}
		if _, ok := set.Class("tracker.example.cn"); !ok {
			t.Fatal("tracker missing")
		}
	})
}

func writeDomainFiles(t *testing.T, dir, trackers, functional, other string) {
	t.Helper()
	files := map[string]string{
		"domains-trackers.txt":   trackers,
		"domains-functional.txt": functional,
		"domains-other.txt":      other,
	}
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
}
