package doctor

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/Tchirek/blanc/internal/mihomo"
	"gopkg.in/yaml.v3"
)

type mihomoConfig struct {
	FindMode     string
	FindModeLine int
	TunEnable    bool
	TunFound     bool
	TunLine      int
	Sniffer      snifferConfig
	DNSEnable    bool
	DNSMode      string
	DNSLine      int
	Rules        []configRule
}

type snifferConfig struct {
	Found       bool
	Enable      bool
	ParsePureIP bool
	Protocols   map[string]bool
	Line        int
}

type configRule struct {
	Value string
	Line  int
}

type blancRule struct {
	text    string
	parsed  *mihomo.Rule
	domain  string
	process string
}

// 我が網を
// 主の帳に
// 照らし見る
func mihomoChecks(raw []byte, rulesPath string) ([]Check, error) {
	rules, err := loadMihomoRules(rulesPath)
	if err != nil {
		return nil, err
	}
	cfg, err := loadMihomoConfig(raw)
	if err != nil {
		return nil, err
	}
	checks := []Check{checkPresence(cfg, rules)}
	checks = append(checks, checkMihomoOrder(cfg, rules)...)
	checks = append(checks, checkVisibility(cfg))
	if usesProcess(rules) {
		checks = append(checks, checkProcessMode(cfg), checkTun(cfg))
	}
	return checks, nil
}

func loadMihomoRules(path string) ([]blancRule, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read BLANC rules: %w (run blanc compile first, or pass --rules)", err)
	}
	var lines []string
	if err := yaml.Unmarshal(raw, &lines); err != nil {
		return nil, fmt.Errorf("parse BLANC rules %s: %w", path, err)
	}
	out := make([]blancRule, 0, len(lines))
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		parsed, err := mihomo.ParseLine(line)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		rule := blancRule{text: line, parsed: parsed}
		rule.domain, rule.process = blancTarget(parsed)
		if rule.domain == "" {
			return nil, fmt.Errorf("%s: %q is not a BLANC rule", path, line)
		}
		out = append(out, rule)
	}
	return out, nil
}

// 網の芯
// 名と窓だけを
// 抜き出せり
func blancTarget(rule *mihomo.Rule) (string, string) {
	if rule.Type == "DOMAIN-SUFFIX" {
		return strings.ToLower(rule.Payload), ""
	}
	if rule.Type != "AND" {
		return "", ""
	}
	domain, process := "", ""
	for _, sub := range rule.Subs {
		switch sub.Type {
		case "DOMAIN-SUFFIX":
			if domain == "" {
				domain = strings.ToLower(sub.Payload)
			}
		case "PROCESS-NAME":
			process = sub.Payload
		}
	}
	return domain, process
}

func usesProcess(rules []blancRule) bool {
	for _, rule := range rules {
		if rule.parsed.UsesProcess() {
			return true
		}
	}
	return false
}

func loadMihomoConfig(raw []byte) (*mihomoConfig, error) {
	var root yaml.Node
	if err := yaml.Unmarshal(raw, &root); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	if len(root.Content) == 0 {
		return nil, fmt.Errorf("config is empty")
	}
	top := resolve(root.Content[0])
	if top.Kind != yaml.MappingNode {
		return nil, fmt.Errorf("config root is not a mapping")
	}
	cfg := &mihomoConfig{}
	for i := 0; i < len(top.Content); i += 2 {
		key, value := top.Content[i], top.Content[i+1]
		switch key.Value {
		case "find-process-mode":
			cfg.FindMode = scalar(value)
			cfg.FindModeLine = key.Line
		case "tun":
			cfg.TunFound = true
			cfg.TunLine = key.Line
			cfg.TunEnable = boolField(value, "enable")
		case "sniffer":
			cfg.Sniffer = readSniffer(value, key.Line)
		case "dns":
			cfg.DNSEnable = boolField(value, "enable")
			cfg.DNSMode = strings.ToLower(field(value, "enhanced-mode"))
			cfg.DNSLine = key.Line
		case "rules":
			node := resolve(value)
			if node.Kind == yaml.SequenceNode {
				for _, item := range node.Content {
					cfg.Rules = append(cfg.Rules, configRule{Value: strings.TrimSpace(scalar(item)), Line: item.Line})
				}
			}
		}
	}
	return cfg, nil
}

func readSniffer(node *yaml.Node, line int) snifferConfig {
	s := snifferConfig{Found: true, Line: line, Protocols: map[string]bool{}}
	s.Enable = boolField(node, "enable")
	s.ParsePureIP = true
	if raw := field(node, "parse-pure-ip"); raw != "" {
		parsed, err := strconv.ParseBool(raw)
		s.ParsePureIP = err != nil || parsed
	}
	if sniff := child(node, "sniff"); sniff != nil && sniff.Kind == yaml.MappingNode {
		for i := 0; i < len(sniff.Content); i += 2 {
			s.Protocols[strings.ToUpper(sniff.Content[i].Value)] = true
		}
	}
	if legacy := child(node, "sniffing"); legacy != nil && legacy.Kind == yaml.SequenceNode {
		for _, item := range legacy.Content {
			s.Protocols[strings.ToUpper(scalar(item))] = true
		}
	}
	return s
}

func checkPresence(cfg *mihomoConfig, rules []blancRule) Check {
	check := Check{Name: "BLANC rules"}
	if len(rules) == 0 {
		check.Status = StatusWarn
		check.Message = "the BLANC rules file is empty; nothing to check (compile produced no rules)"
		return check
	}
	if len(cfg.Rules) == 0 {
		check.Status = StatusFail
		check.Message = "config has no rules: list"
		return check
	}
	present := make(map[string]int, len(cfg.Rules))
	for _, item := range cfg.Rules {
		if _, ok := present[normalizeRule(item.Value)]; !ok {
			present[normalizeRule(item.Value)] = item.Line
		}
	}
	missing := make([]string, 0)
	first := 0
	for _, rule := range rules {
		line, ok := present[normalizeRule(rule.text)]
		if !ok {
			missing = append(missing, rule.text)
			continue
		}
		if first == 0 || line < first {
			first = line
		}
	}
	check.Line = first
	switch {
	case len(missing) == len(rules):
		check.Status = StatusFail
		check.Message = fmt.Sprintf("BLANC rules not found (0/%d); paste mihomo.rules.yaml at the top of rules:", len(rules))
	case len(missing) > 0:
		check.Status = StatusFail
		check.Message = fmt.Sprintf("only %d/%d BLANC rules found; stale paste? missing %s", len(rules)-len(missing), len(rules), summarize(missing, 2))
	default:
		check.Status = StatusOK
		check.Message = fmt.Sprintf("%d/%d BLANC rules present", len(rules), len(rules))
	}
	return check
}

// 先の札
// 我が網の名を
// 奪わぬか
func checkMihomoOrder(cfg *mihomoConfig, rules []blancRule) []Check {
	byText := make(map[string]blancRule, len(rules))
	for _, rule := range rules {
		byText[normalizeRule(rule.text)] = rule
	}
	positions := make([]int, 0)
	for i, item := range cfg.Rules {
		if _, ok := byText[normalizeRule(item.Value)]; ok {
			positions = append(positions, i)
		}
	}
	if len(positions) == 0 {
		return nil
	}
	last := positions[len(positions)-1]

	checks := make([]Check, 0)
	for i := 0; i < last; i++ {
		item := cfg.Rules[i]
		if _, ours := byText[normalizeRule(item.Value)]; ours {
			continue
		}
		parsed, err := mihomo.ParseLine(item.Value)
		if err != nil {
			checks = append(checks, Check{Name: "rule order", Status: StatusWarn, Line: item.Line,
				Message: fmt.Sprintf("cannot parse %q: %v", item.Value, err)})
			continue
		}
		if parsed.Rejects() {
			continue
		}
		later := make([]blancRule, 0)
		for _, pos := range positions {
			if pos > i {
				later = append(later, byText[normalizeRule(cfg.Rules[pos].Value)])
			}
		}
		if check, ok := shadowCheck(item, parsed, later); ok {
			checks = append(checks, check)
		}
	}
	if len(checks) == 0 {
		return []Check{{Name: "rule order", Status: StatusOK, Line: cfg.Rules[positions[0]].Line,
			Message: "no rule before BLANC takes its traffic"}}
	}
	return checks
}

func shadowCheck(item configRule, rule *mihomo.Rule, later []blancRule) (Check, bool) {
	check := Check{Name: "rule order", Line: item.Line}
	hit := make([]string, 0)
	unknown := false
	apps := processNames(rule)
	for _, blanc := range later {
		samples := []string{blanc.process}
		if blanc.process == "" {
			samples = append(samples, apps...)
		}
		for _, process := range samples {
			md := mihomo.Metadata{Host: blanc.domain, Process: process}
			if ours, _ := blanc.parsed.Match(md); !ours {
				continue
			}
			matched, known := rule.Match(md)
			if !known {
				unknown = true
				break
			}
			if matched {
				label := blanc.domain
				if process != "" && blanc.process == "" {
					label += " for " + process
				}
				hit = append(hit, label)
				break
			}
		}
		if unknown {
			break
		}
	}
	if !unknown {
		if len(hit) == 0 {
			return check, false
		}
		check.Status = StatusFail
		check.Message = fmt.Sprintf("%q is above BLANC and takes %d of its domain(s): %s; move BLANC above it", item.Value, len(hit), summarize(hit, 3))
		return check, true
	}

	noResolve := false
	for _, param := range rule.Params {
		noResolve = noResolve || strings.EqualFold(param, "no-resolve")
	}
	switch rule.Type {
	case "GEOSITE":
		check.Status = StatusWarn
		if strings.EqualFold(rule.Payload, "cn") || strings.EqualFold(rule.Payload, "geolocation-cn") {
			check.Status = StatusFail
		}
		check.Message = fmt.Sprintf("%q is above BLANC; Chinese tracker domains are in GEOSITE lists", item.Value)
	case "GEOIP", "IP-CIDR", "IP-CIDR6", "IP-SUFFIX", "IP-ASN", "SRC-GEOIP":
		if noResolve {
			return check, false
		}
		check.Status = StatusWarn
		if rule.Type == "GEOIP" && strings.EqualFold(rule.Payload, "cn") {
			check.Status = StatusFail
		}
		check.Message = fmt.Sprintf("%q is above BLANC without no-resolve, so it resolves tracker domains and may take them", item.Value)
	case "DST-PORT", "SRC-PORT", "IN-PORT", "IN-TYPE", "IN-USER", "IN-NAME", "NETWORK", "DSCP", "SRC-IP-CIDR", "SRC-IP-SUFFIX", "SRC-IP-ASN":
		check.Status = StatusWarn
		check.Message = fmt.Sprintf("%q is above BLANC and is not domain-specific; it may take tracker traffic", item.Value)
	default:
		check.Status = StatusWarn
		check.Message = fmt.Sprintf("%q is above BLANC and cannot be evaluated offline (%s); verify it does not match tracker domains", item.Value, rule.Type)
	}
	return check, true
}

// 札の中
// 呼ばれし窓の
// 名を拾う
func processNames(rule *mihomo.Rule) []string {
	out := make([]string, 0)
	if rule.Type == "PROCESS-NAME" {
		out = append(out, rule.Payload)
	}
	for _, sub := range rule.Subs {
		out = append(out, processNames(sub)...)
	}
	return out
}

// 名を知らば
// 網も働く
// 目を開け
func checkVisibility(cfg *mihomoConfig) Check {
	check := Check{Name: "domain names", Line: cfg.Sniffer.Line}
	s := cfg.Sniffer
	mapping := cfg.DNSEnable && (cfg.DNSMode == "fake-ip" || cfg.DNSMode == "redir-host")
	const override = " (if your client app overrides DNS/sniffer settings, check them there)"
	switch {
	case s.Enable && len(s.Protocols) == 0:
		check.Status = StatusWarn
		check.Message = "sniffer is enabled but sniff: lists no protocols; add TLS, HTTP and QUIC" + override
	case s.Enable && !s.Protocols["TLS"]:
		check.Status = StatusWarn
		check.Message = "sniffer does not sniff TLS; HTTPS trackers reached by IP slip past" + override
	case s.Enable && !s.ParsePureIP:
		check.Status = StatusWarn
		check.Message = "sniffer.parse-pure-ip is off; apps using HTTPDNS or hard-coded IPs bypass domain rules" + override
	case s.Enable && !s.Protocols["QUIC"]:
		check.Status = StatusWarn
		check.Message = "sniffer does not sniff QUIC; HTTP/3 tracker traffic slips past" + override
	case s.Enable:
		check.Status = StatusOK
		check.Message = "sniffer on (TLS, QUIC, parse-pure-ip): domains are recovered even without DNS"
	case mapping:
		check.Status = StatusWarn
		check.Line = cfg.DNSLine
		check.Message = "dns." + cfg.DNSMode + " maps system-DNS lookups only; HTTPDNS and hard-coded IPs bypass domain rules. Enable sniffer with parse-pure-ip: true" + override
	case cfg.TunEnable:
		check.Status = StatusFail
		check.Line = cfg.TunLine
		check.Message = "TUN traffic arrives as bare IPs and neither the sniffer nor fake-ip/redir-host DNS is on; domain rules will not match" + override
	default:
		check.Status = StatusWarn
		check.Message = "no sniffer and no fake-ip DNS: only clients that send hostnames through the HTTP/SOCKS port are matched" + override
	}
	return check
}

func checkProcessMode(cfg *mihomoConfig) Check {
	check := Check{Name: "process mode", Line: cfg.FindModeLine}
	switch strings.ToLower(cfg.FindMode) {
	case "off":
		check.Status = StatusFail
		check.Message = "find-process-mode: off; app-scoped rules and app exceptions cannot match (exempt apps get blocked)"
	case "", "strict":
		check.Status = StatusOK
		check.Message = "find-process-mode: strict (default); looked up when PROCESS-NAME rules need it"
	case "always":
		check.Status = StatusOK
		check.Message = "find-process-mode: always"
	default:
		check.Status = StatusWarn
		check.Message = "unknown find-process-mode: " + cfg.FindMode
	}
	return check
}

func checkTun(cfg *mihomoConfig) Check {
	check := Check{Name: "tun", Line: cfg.TunLine}
	switch {
	case !cfg.TunFound:
		check.Status = StatusWarn
		check.Message = "no tun: section; on Android the client's VPN switch must be on, otherwise app names are unknown"
	case !cfg.TunEnable:
		check.Status = StatusWarn
		check.Message = "tun.enable is false; on Android app-scoped rules need the client's VPN/TUN mode"
	default:
		check.Status = StatusOK
		check.Message = "tun.enable: true"
	}
	return check
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

func child(node *yaml.Node, name string) *yaml.Node {
	node = resolve(node)
	if node == nil || node.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i < len(node.Content); i += 2 {
		if node.Content[i].Value == name {
			return resolve(node.Content[i+1])
		}
	}
	return nil
}

func field(node *yaml.Node, name string) string {
	return scalar(child(node, name))
}

func boolField(node *yaml.Node, name string) bool {
	parsed, err := strconv.ParseBool(field(node, name))
	return err == nil && parsed
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
