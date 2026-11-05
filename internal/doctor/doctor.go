package doctor

import (
	"bytes"
	"encoding/json"
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
	KindMihomo  Kind = "mihomo"
	KindSingbox Kind = "sing-box"
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
	kind := Detect(raw)
	if rulesPath == "" {
		if outDir == "" {
			outDir = "blanc-out"
		}
		name := "mihomo.rules.yaml"
		if kind == KindSingbox {
			name = "singbox.json"
		}
		rulesPath = filepath.Join(outDir, name)
	}
	report := &Report{Kind: kind, ConfigPath: configPath, RulesPath: rulesPath}
	switch kind {
	case KindSingbox:
		report.Checks, err = singboxChecks(raw, rulesPath)
	default:
		report.Checks, err = mihomoChecks(raw, rulesPath)
	}
	if err != nil {
		return nil, err
	}
	return report, nil
}

// 括弧なら
// 異国の網と
// 見定めて
func Detect(raw []byte) Kind {
	trimmed := bytes.TrimSpace(stripJSONComments(raw))
	if len(trimmed) == 0 || trimmed[0] != '{' {
		return KindMihomo
	}
	var probe map[string]json.RawMessage
	if err := json.Unmarshal(trimmed, &probe); err != nil {
		return KindMihomo
	}
	for _, key := range []string{"route", "inbounds", "outbounds", "dns"} {
		if _, ok := probe[key]; ok {
			return KindSingbox
		}
	}
	return KindMihomo
}

// 注釈を
// 拭いて素の文
// 読みにけり
func stripJSONComments(raw []byte) []byte {
	out := make([]byte, 0, len(raw))
	inString, escaped := false, false
	for i := 0; i < len(raw); i++ {
		c := raw[i]
		if inString {
			out = append(out, c)
			switch {
			case escaped:
				escaped = false
			case c == '\\':
				escaped = true
			case c == '"':
				inString = false
			}
			continue
		}
		if c == '"' {
			inString = true
			out = append(out, c)
			continue
		}
		if c == '/' && i+1 < len(raw) && raw[i+1] == '/' {
			for i < len(raw) && raw[i] != '\n' {
				i++
			}
			if i < len(raw) {
				out = append(out, '\n')
			}
			continue
		}
		if c == '/' && i+1 < len(raw) && raw[i+1] == '*' {
			i += 2
			for i+1 < len(raw) && !(raw[i] == '*' && raw[i+1] == '/') {
				i++
			}
			i++
			continue
		}
		out = append(out, c)
	}
	return out
}

func summarize(values []string, limit int) string {
	if len(values) <= limit {
		return strings.Join(values, ", ")
	}
	return fmt.Sprintf("%s (+%d more)", strings.Join(values[:limit], ", "), len(values)-limit)
}
