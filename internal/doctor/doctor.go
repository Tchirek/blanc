package doctor

import (
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

type Status string

const (
	StatusOK   Status = "ok"
	StatusWarn Status = "warn"
	StatusFail Status = "fail"
)

type Check struct {
	Name    string
	Status  Status
	Line    int
	Message string
}

type Report struct {
	ConfigPath string
	RulesPath  string
	Checks     []Check
}

func (r *Report) Fails() int {
	count := 0
	for _, check := range r.Checks {
		if check.Status == StatusFail {
			count++
		}
	}
	return count
}

func (r *Report) Warnings() int {
	count := 0
	for _, check := range r.Checks {
		if check.Status == StatusWarn {
			count++
		}
	}
	return count
}

type config struct {
	FindMode     string
	FindModeLine int
	TunEnable    bool
	TunFound     bool
	TunLine      int
	Rules        []rule
}

type rule struct {
	Value string
	Line  int
}

var generatedPattern = regexp.MustCompile(`^AND,\(\(PROCESS-NAME,([^)]+)\),\(DOMAIN-SUFFIX,([^)]+)\)\),REJECT$`)

// 門の前
// 名を確かめて
// 鍵を挿す
func Run(configPath, rulesPath string) (*Report, error) {
	rules, err := loadRules(rulesPath)
	if err != nil {
		return nil, err
	}
	cfg, err := loadConfig(configPath)
	if err != nil {
		return nil, err
	}

	report := &Report{ConfigPath: configPath, RulesPath: rulesPath}
	report.Checks = append(report.Checks, checkProcessMode(cfg))
	report.Checks = append(report.Checks, checkTun(cfg))
	report.Checks = append(report.Checks, checkPresence(cfg, rules))
	report.Checks = append(report.Checks, checkOrder(cfg, rules)...)
	return report, nil
}

func loadRules(path string) ([]string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read BLANC rules: %w", err)
	}
	var rules []string
	if err := yaml.Unmarshal(raw, &rules); err != nil {
		return nil, fmt.Errorf("parse BLANC rules: %w", err)
	}
	out := make([]string, 0, len(rules))
	for _, rule := range rules {
		rule = strings.TrimSpace(rule)
		if rule != "" {
			out = append(out, rule)
		}
	}
	return out, nil
}

func loadConfig(path string) (*config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	var root yaml.Node
	if err := yaml.Unmarshal(raw, &root); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	if len(root.Content) == 0 {
		return nil, fmt.Errorf("config is empty")
	}
	top := root.Content[0]
	if top.Kind != yaml.MappingNode {
		return nil, fmt.Errorf("config root is not a mapping")
	}

	cfg := &config{}
	for i := 0; i < len(top.Content); i += 2 {
		key, value := top.Content[i], top.Content[i+1]
		switch key.Value {
		case "find-process-mode":
			cfg.FindMode = scalar(value)
			cfg.FindModeLine = key.Line
		case "tun":
			readTun(cfg, value)
		case "rules":
			readRules(cfg, value)
		}
	}
	return cfg, nil
}

func readTun(cfg *config, node *yaml.Node) {
	node = resolve(node)
	if node.Kind != yaml.MappingNode {
		return
	}
	for i := 0; i < len(node.Content); i += 2 {
		key, value := node.Content[i], node.Content[i+1]
		if key.Value != "enable" {
			continue
		}
		cfg.TunFound = true
		cfg.TunLine = key.Line
		parsed, err := strconv.ParseBool(scalar(value))
		if err == nil {
			cfg.TunEnable = parsed
		}
	}
}

func readRules(cfg *config, node *yaml.Node) {
	node = resolve(node)
	if node.Kind != yaml.SequenceNode {
		return
	}
	for _, item := range node.Content {
		ruleValue := scalar(item)
		cfg.Rules = append(cfg.Rules, rule{Value: strings.TrimSpace(ruleValue), Line: item.Line})
	}
}

func scalar(node *yaml.Node) string {
	node = resolve(node)
	if node == nil || node.Kind != yaml.ScalarNode {
		return ""
	}
	return strings.TrimSpace(node.Value)
}

func resolve(node *yaml.Node) *yaml.Node {
	for node != nil && node.Kind == yaml.AliasNode {
		node = node.Alias
	}
	return node
}

func checkProcessMode(cfg *config) Check {
	check := Check{Name: "process mode", Line: cfg.FindModeLine}
	switch strings.ToLower(cfg.FindMode) {
	case "always":
		check.Status = StatusOK
		check.Message = "find-process-mode: always"
	case "strict":
		check.Status = StatusWarn
		check.Message = "find-process-mode: strict; prefer always so UDP/QUIC is attributed too"
	case "", "off":
		check.Status = StatusFail
		check.Message = "find-process-mode is off; PROCESS-NAME rules cannot match Android apps"
	default:
		check.Status = StatusWarn
		check.Message = "unknown find-process-mode: " + cfg.FindMode
	}
	return check
}

func checkTun(cfg *config) Check {
	check := Check{Name: "tun", Line: cfg.TunLine}
	switch {
	case !cfg.TunFound:
		check.Status = StatusFail
		check.Message = "tun.enable is missing; Android app matching needs TUN"
	case !cfg.TunEnable:
		check.Status = StatusFail
		check.Message = "tun.enable is false; Android app matching needs TUN"
	default:
		check.Status = StatusOK
		check.Message = "tun.enable: true"
	}
	return check
}

func checkPresence(cfg *config, rules []string) Check {
	check := Check{Name: "BLANC rules"}
	if len(rules) == 0 {
		check.Status = StatusFail
		check.Message = "BLANC rules file is empty; run blanc compile first"
		return check
	}
	if len(cfg.Rules) == 0 {
		check.Status = StatusFail
		check.Message = "config has no rules list"
		return check
	}

	want := make(map[string]string, len(rules))
	for _, rule := range rules {
		want[normalizeRule(rule)] = rule
	}
	matched := make(map[string]struct{}, len(rules))
	firstLine := 0
	for _, item := range cfg.Rules {
		normalized := normalizeRule(item.Value)
		if _, ok := want[normalized]; ok {
			matched[normalized] = struct{}{}
			if firstLine == 0 {
				firstLine = item.Line
			}
		}
	}
	found := len(matched)
	check.Line = firstLine
	switch {
	case found == 0:
		check.Status = StatusFail
		check.Message = fmt.Sprintf("BLANC rules not found (0/%d)", len(rules))
	case found < len(rules):
		missing := make([]string, 0, len(rules)-found)
		for _, rule := range rules {
			if _, ok := matched[normalizeRule(rule)]; !ok {
				missing = append(missing, rule)
			}
		}
		check.Status = StatusFail
		check.Message = fmt.Sprintf("only %d/%d BLANC rules found; missing %s", found, len(rules), summarizeRules(missing, 2))
	default:
		check.Status = StatusOK
		check.Message = fmt.Sprintf("%d/%d BLANC rules present", found, len(rules))
	}
	return check
}

func checkOrder(cfg *config, rules []string) []Check {
	if len(rules) == 0 || len(cfg.Rules) == 0 {
		return nil
	}
	want := make(map[string]struct{}, len(rules))
	for _, rule := range rules {
		want[normalizeRule(rule)] = struct{}{}
	}
	first := -1
	for i, item := range cfg.Rules {
		if _, ok := want[normalizeRule(item.Value)]; ok {
			first = i
			break
		}
	}

	limit := len(cfg.Rules)
	if first >= 0 {
		limit = first
	}
	packages, domains := generatedTargets(rules)
	checks := make([]Check, 0)
	for i := 0; i < limit; i++ {
		item := cfg.Rules[i]
		kind, value := splitRule(item.Value)
		switch kind {
		case "MATCH":
			checks = append(checks, Check{
				Name: "rule order", Status: StatusFail, Line: item.Line,
				Message: "MATCH swallows all later rules",
			})
		case "GEOSITE":
			status := StatusWarn
			message := "GEOSITE may shadow matching domains"
			if strings.EqualFold(value, "cn") {
				status = StatusFail
				message = "GEOSITE,cn shadows Chinese tracker domains"
			}
			checks = append(checks, Check{Name: "rule order", Status: status, Line: item.Line, Message: message})
		case "GEOIP":
			status := StatusWarn
			message := "GEOIP may shadow matching destinations"
			if strings.EqualFold(value, "cn") {
				status = StatusFail
				message = "GEOIP,CN shadows Chinese destinations"
			}
			checks = append(checks, Check{Name: "rule order", Status: status, Line: item.Line, Message: message})
		case "DOMAIN-SUFFIX":
			if check := checkSuffix(item, value, domains); check.Status != "" {
				checks = append(checks, check)
			}
		case "DOMAIN":
			if contains(domains, strings.ToLower(strings.TrimPrefix(value, "."))) {
				checks = append(checks, Check{
					Name: "rule order", Status: StatusFail, Line: item.Line,
					Message: "DOMAIN shadows a BLANC domain: " + value,
				})
			}
		case "DOMAIN-KEYWORD":
			shadowed := false
			for _, domain := range domains {
				if strings.Contains(domain, strings.ToLower(value)) {
					shadowed = true
					break
				}
			}
			status := StatusWarn
			message := "DOMAIN-KEYWORD may shadow matching domains"
			if shadowed {
				status = StatusFail
				message = "DOMAIN-KEYWORD shadows a BLANC domain: " + value
			}
			checks = append(checks, Check{Name: "rule order", Status: status, Line: item.Line, Message: message})
		case "PROCESS-NAME":
			if contains(packages, value) {
				checks = append(checks, Check{
					Name: "rule order", Status: StatusFail, Line: item.Line,
					Message: "PROCESS-NAME matches a BLANC app: " + value,
				})
			}
		case "PROCESS-NAME-WILDCARD", "PROCESS-NAME-REGEX", "PROCESS-PATH", "PROCESS-PATH-REGEX", "UID":
			checks = append(checks, Check{
				Name: "rule order", Status: StatusWarn, Line: item.Line,
				Message: kind + " may swallow the app; verify",
			})
		case "RULE-SET", "SUB-RULE":
			checks = append(checks, Check{
				Name: "rule order", Status: StatusWarn, Line: item.Line,
				Message: kind + " may shadow; doctor does not expand it",
			})
		case "AND", "OR", "NOT":
			checks = append(checks, Check{
				Name: "rule order", Status: StatusWarn, Line: item.Line,
				Message: "logical rule may shadow; verify",
			})
		}
	}

	for i := range checks {
		if first < 0 {
			checks[i].Message = "BLANC rules are not in the config yet; paste before this rule: " + checks[i].Message
		} else {
			checks[i].Message = "before BLANC: " + checks[i].Message
		}
	}
	if first < 0 {
		if len(checks) == 0 {
			checks = append(checks, Check{
				Name: "rule order", Status: StatusWarn,
				Message: "BLANC rules are not in the config yet; no known shadowing rule found",
			})
		}
	} else if len(checks) == 0 {
		checks = append(checks, Check{
			Name: "rule order", Status: StatusOK, Line: cfg.Rules[first].Line,
			Message: "no obvious shadowing rule before BLANC",
		})
	}
	return checks
}

func checkSuffix(item rule, value string, domains []string) Check {
	host := strings.ToLower(strings.TrimPrefix(strings.TrimSpace(value), "."))
	if host == "" {
		return Check{Name: "rule order", Status: StatusWarn, Line: item.Line, Message: "empty DOMAIN-SUFFIX"}
	}
	if !strings.Contains(host, ".") {
		return Check{
			Name: "rule order", Status: StatusFail, Line: item.Line,
			Message: "TLD-wide DOMAIN-SUFFIX: " + value,
		}
	}
	for _, domain := range domains {
		if host == domain || strings.HasSuffix(domain, "."+host) {
			return Check{
				Name: "rule order", Status: StatusFail, Line: item.Line,
				Message: "DOMAIN-SUFFIX shadows a BLANC domain: " + value,
			}
		}
	}
	return Check{}
}

func generatedTargets(rules []string) ([]string, []string) {
	packages := make([]string, 0)
	domains := make([]string, 0)
	for _, rule := range rules {
		match := generatedPattern.FindStringSubmatch(normalizeRule(rule))
		if match == nil {
			continue
		}
		packages = append(packages, match[1])
		domains = append(domains, match[2])
	}
	return packages, domains
}

func normalizeRule(value string) string {
	return strings.Map(func(r rune) rune {
		switch r {
		case ' ', '\t', '\r', '\n':
			return -1
		default:
			return r
		}
	}, value)
}

func summarizeRules(rules []string, limit int) string {
	if len(rules) == 0 {
		return ""
	}
	if len(rules) <= limit {
		return strings.Join(rules, "; ")
	}
	return fmt.Sprintf("%s (+%d more)", strings.Join(rules[:limit], "; "), len(rules)-limit)
}

func splitRule(value string) (string, string) {
	parts := strings.SplitN(value, ",", 3)
	if len(parts) < 2 {
		return "", ""
	}
	kind := strings.ToUpper(strings.TrimSpace(parts[0]))
	arg := ""
	if len(parts) > 1 {
		arg = strings.TrimSpace(parts[1])
	}
	return kind, arg
}

func contains(values []string, value string) bool {
	for _, candidate := range values {
		if candidate == value {
			return true
		}
	}
	return false
}
