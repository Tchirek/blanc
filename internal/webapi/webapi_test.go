package webapi

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Tchirek/blanc/internal/render"
)

var now = time.Date(2026, 11, 6, 0, 0, 0, 0, time.UTC)

func uploads(t *testing.T, prefix string, names ...string) map[string][]byte {
	t.Helper()
	out := make(map[string][]byte)
	for _, name := range names {
		raw, err := os.ReadFile(filepath.Join("..", "..", "testdata", name))
		if err != nil {
			t.Fatal(err)
		}
		out[prefix+name] = raw
	}
	return out
}

var all = []string{"report.json", "domains-trackers.txt", "domains-functional.txt", "domains-other.txt"}

// 窓の中
// 帳を受け取り
// 網を返す
func TestCompileFolderUpload(t *testing.T) {
	files := uploads(t, "noir-out/", all...)
	files["noir-out/report.md"] = []byte("# NOIR")
	files["noir-out/plan.txt"] = []byte("")
	result, err := Compile(files, "", now)
	if err != nil {
		t.Fatal(err)
	}
	if !result.HasReport || result.Device.Model != "Pixel 7" || result.Policy != "built-in" {
		t.Fatalf("result = %+v", result)
	}
	if result.Stats.GlobalRules != 5 || len(result.Files) != 5 || len(result.Order) != 5 {
		t.Fatalf("stats = %+v files = %d", result.Stats, len(result.Files))
	}
	for _, name := range result.Order {
		if result.Files[name] == "" {
			t.Fatalf("%s is empty", name)
		}
	}
	if !strings.Contains(result.Files[render.FileMihomo], "DOMAIN-SUFFIX,alog.umeng.com,REJECT") {
		t.Fatalf("mihomo:\n%s", result.Files[render.FileMihomo])
	}
	if strings.Join(result.Unused, ",") != "noir-out/plan.txt,noir-out/report.md" {
		t.Fatalf("unused = %v", result.Unused)
	}
	if !strings.Contains(result.Files[render.FileManifest], "2026-11-06T00:00:00Z") {
		t.Fatal("manifest must carry the given time")
	}
}

// 札の文
// 貼られし方を
// 先に読む
func TestCompilePolicySources(t *testing.T) {
	files := uploads(t, `C:\scan\`, all...)
	files[`C:\scan\blanc.yaml`] = []byte("version: 2\napps:\n  jp.quietreader.app: allow\n")
	result, err := Compile(files, "", now)
	if err != nil {
		t.Fatal(err)
	}
	if result.Policy != "blanc.yaml" || result.Stats.Exceptions != 5 {
		t.Fatalf("uploaded policy: %+v", result)
	}
	result, err = Compile(files, "version: 2\nallow: [umeng.com]\n", now)
	if err != nil {
		t.Fatal(err)
	}
	if result.Policy != "pasted" || result.Stats.GlobalRules != 4 {
		t.Fatalf("pasted policy must win: %+v", result.Stats)
	}
	if _, err := Compile(files, "version: 1\n", now); err == nil || !strings.Contains(err.Error(), "policy (pasted)") {
		t.Fatalf("err = %v", err)
	}
}

func TestCompileErrors(t *testing.T) {
	if _, err := Compile(uploads(t, "", "report.json", "domains-trackers.txt"), "", now); err == nil ||
		!strings.Contains(err.Error(), "domains-functional.txt, domains-other.txt") || !strings.Contains(err.Error(), "noir-out") {
		t.Fatalf("err = %v", err)
	}
	files := uploads(t, "", all...)
	files["report.json"] = []byte("{")
	if _, err := Compile(files, "", now); err == nil || !strings.Contains(err.Error(), "report.json") {
		t.Fatalf("err = %v", err)
	}
	files["report.json"] = []byte(`{"apps":[]}`)
	if _, err := Compile(files, "", now); err == nil || !strings.Contains(err.Error(), "0 apps") {
		t.Fatalf("err = %v", err)
	}
	delete(files, "report.json")
	result, err := Compile(files, "", now)
	if err != nil || result.HasReport {
		t.Fatalf("report.json is optional: %v %+v", err, result)
	}
}
