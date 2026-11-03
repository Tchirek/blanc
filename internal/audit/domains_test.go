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
	if !strings.HasSuffix(set.Sources[ClassTracker], "domains-trackers.txt") {
		t.Fatalf("source = %q", set.Sources[ClassTracker])
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

func TestLoadDomainsRejectsInvalidAndDuplicate(t *testing.T) {
	t.Run("invalid", func(t *testing.T) {
		dir := t.TempDir()
		writeDomainFiles(t, dir, "bad host", "login.example.cn", "api.example.cn")
		if _, err := LoadDomains(dir); err == nil || !strings.Contains(err.Error(), "invalid host") {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("duplicate", func(t *testing.T) {
		dir := t.TempDir()
		writeDomainFiles(t, dir, "same.example.cn", "same.example.cn", "api.example.cn")
		if _, err := LoadDomains(dir); err == nil || !strings.Contains(err.Error(), "classified as both") {
			t.Fatalf("err = %v", err)
		}
	})
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
