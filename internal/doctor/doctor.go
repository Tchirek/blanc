package doctor

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

type Status string

const (
	StatusOK   Status = "ok"
	StatusWarn Status = "warn"
	StatusFail Status = "fail"
)

type Kind string

const (
	KindMihomo Kind = "mihomo"
)

type Check struct {
	Name    string
	Status  Status
	Line    int
	Message string
}

type Report struct {
	Kind       Kind
	ConfigPath string
	RulesPath  string
	Checks     []Check
}

func (r *Report) Fails() int {
	return r.count(StatusFail)
}

func (r *Report) Warnings() int {
	return r.count(StatusWarn)
}

func (r *Report) count(status Status) int {
	n := 0
	for _, check := range r.Checks {
		if check.Status == status {
			n++
		}
	}
	return n
}

// 門の前
// 名を確かめて
// 鍵を挿す
func Run(configPath, rulesPath, outDir string) (*Report, error) {
	raw, err := os.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	if rulesPath == "" {
		if outDir == "" {
			outDir = "blanc-out"
		}
		rulesPath = filepath.Join(outDir, "mihomo.rules.yaml")
	}
	report := &Report{Kind: KindMihomo, ConfigPath: configPath, RulesPath: rulesPath}
	report.Checks, err = mihomoChecks(raw, rulesPath)
	if err != nil {
		return nil, err
	}
	return report, nil
}

func summarize(values []string, limit int) string {
	if len(values) <= limit {
		return strings.Join(values, ", ")
	}
	return fmt.Sprintf("%s (+%d more)", strings.Join(values[:limit], ", "), len(values)-limit)
}
