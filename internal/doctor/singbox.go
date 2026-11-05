package doctor

import (
	"encoding/json"
	"fmt"
	"os"
	"path"
	"sort"
	"strings"
)

type sbConfig struct {
	Inbounds []map[string]json.RawMessage `json:"inbounds"`
	DNS      struct {
		Servers []map[string]json.RawMessage `json:"servers"`
		FakeIP  *struct {
			Enabled bool `json:"enabled"`
		} `json:"fakeip"`
	} `json:"dns"`
	Route struct {
		RuleSet []struct {
			Tag  string `json:"tag"`
			Type string `json:"type"`
			Path string `json:"path"`
			URL  string `json:"url"`
		} `json:"rule_set"`
		Rules []map[string]json.RawMessage `json:"rules"`
	} `json:"route"`
}

type sbRuleSet struct {
	Rules []json.RawMessage `json:"rules"`
}

// 異国の
// 門の順をも
// 改める
func singboxChecks(raw []byte, rulesPath string) ([]Check, error) {
	var cfg sbConfig
	if err := json.Unmarshal(stripJSONComments(raw), &cfg); err != nil {
		return nil, fmt.Errorf("parse sing-box config: %w", err)
	}
	setRaw, err := os.ReadFile(rulesPath)
	if err != nil {
		return nil, fmt.Errorf("read BLANC rule set: %w (run blanc compile first, or pass --rules)", err)
	}
	var set sbRuleSet
	if err := json.Unmarshal(setRaw, &set); err != nil {
		return nil, fmt.Errorf("parse BLANC rule set %s: %w", rulesPath, err)
	}
	scoped := strings.Contains(string(setRaw), `"package_name"`)

	checks := make([]Check, 0)
	tag, check := checkRuleSetRef(cfg, rulesPath)
	checks = append(checks, check)
	if tag == "" {
		return checks, nil
	}
	index, check := checkRejectRule(cfg, tag)
	checks = append(checks, check)
	if index < 0 {
		return checks, nil
	}
	checks = append(checks, checkSingboxVisibility(cfg, index))
	checks = append(checks, checkSingboxOrder(cfg, index)...)
	if scoped {
		checks = append(checks, checkSingboxTun(cfg))
	}
	if len(set.Rules) == 0 {
		checks = append(checks, Check{Name: "BLANC rules", Status: StatusWarn,
			Message: "the BLANC rule set is empty; nothing will be rejected"})
	}
	return checks, nil
}

func checkRuleSetRef(cfg sbConfig, rulesPath string) (string, Check) {
	check := Check{Name: "rule set"}
	base := path.Base(strings.ReplaceAll(rulesPath, `\`, "/"))
	for _, ref := range cfg.Route.RuleSet {
		refBase := path.Base(strings.ReplaceAll(ref.Path, `\`, "/"))
		if ref.Tag == "blanc" || (ref.Path != "" && refBase == base) {
			check.Status = StatusOK
			check.Message = fmt.Sprintf("route.rule_set %q -> %s", ref.Tag, ref.Path)
			if ref.Type == "remote" {
				check.Message = fmt.Sprintf("route.rule_set %q -> %s (remote: re-upload after every compile)", ref.Tag, ref.URL)
			}
			return ref.Tag, check
		}
	}
	check.Status = StatusFail
	check.Message = "no route.rule_set entry for BLANC; merge singbox-route.json into route"
	return "", check
}

func checkRejectRule(cfg sbConfig, tag string) (int, Check) {
	check := Check{Name: "BLANC rule"}
	for i, rule := range cfg.Route.Rules {
		if !referencesTag(rule["rule_set"], tag) {
			continue
		}
		action := stringField(rule, "action")
		outbound := stringField(rule, "outbound")
		switch {
		case action == "reject":
			check.Status = StatusOK
			check.Message = fmt.Sprintf("route.rules[%d] rejects rule_set %q", i, tag)
			return i, check
		case action == "" && outbound != "":
			check.Status = StatusFail
			check.Message = fmt.Sprintf("route.rules[%d] routes rule_set %q to outbound %q; use \"action\": \"reject\" (sing-box 1.11+)", i, tag, outbound)
			return -1, check
		default:
			check.Status = StatusFail
			check.Message = fmt.Sprintf("route.rules[%d] uses rule_set %q with action %q, not reject", i, tag, action)
			return -1, check
		}
	}
	check.Status = StatusFail
	check.Message = fmt.Sprintf("no route rule rejects rule_set %q; add {\"rule_set\": %q, \"action\": \"reject\"}", tag, tag)
	return -1, check
}

// 嗅ぐ前に
// 閉ざす門には
// 名も届かず
func checkSingboxVisibility(cfg sbConfig, blanc int) Check {
	check := Check{Name: "domain names"}
	for i, rule := range cfg.Route.Rules {
		if stringField(rule, "action") != "sniff" {
			continue
		}
		if i < blanc {
			check.Status = StatusOK
			check.Message = fmt.Sprintf("route.rules[%d] sniffs before BLANC at route.rules[%d]", i, blanc)
			return check
		}
		check.Status = StatusFail
		check.Message = fmt.Sprintf("the sniff rule route.rules[%d] comes after BLANC at route.rules[%d]; BLANC sees no domain names. Move BLANC below it", i, blanc)
		return check
	}
	for _, inbound := range cfg.Inbounds {
		if boolValue(inbound["sniff"]) {
			check.Status = StatusWarn
			check.Message = "only inbound \"sniff\": true is set (deprecated, removed in sing-box 1.13); add {\"action\": \"sniff\"} before BLANC"
			return check
		}
	}
	if fakeIP(cfg) {
		check.Status = StatusWarn
		check.Message = "no sniff rule: fake-ip recovers domains only for system-DNS lookups; HTTPDNS and hard-coded IPs bypass BLANC. Add {\"action\": \"sniff\"} before BLANC"
		return check
	}
	check.Status = StatusFail
	check.Message = "no {\"action\": \"sniff\"} rule before BLANC and no fake-ip DNS; TUN traffic arrives as bare IPs and BLANC never matches"
	return check
}

var benignKeys = map[string]bool{
	"ip_is_private": true, "protocol": true, "port": true, "port_range": true,
	"ip_cidr": true, "source_ip_cidr": true, "source_ip_is_private": true,
}

var catchAllKeys = map[string]bool{"inbound": true, "network": true, "ip_version": true, "auth_user": true}

func checkSingboxOrder(cfg sbConfig, blanc int) []Check {
	checks := make([]Check, 0)
	for i := 0; i < blanc; i++ {
		rule := cfg.Route.Rules[i]
		action := stringField(rule, "action")
		if action == "" && stringField(rule, "outbound") != "" {
			action = "route"
		}
		if action != "route" && action != "bypass" {
			continue
		}
		keys := matchKeys(rule)
		if stringField(rule, "type") == "logical" {
			checks = append(checks, Check{Name: "rule order", Status: StatusWarn,
				Message: fmt.Sprintf("route.rules[%d] is a logical rule that routes traffic before BLANC; verify it cannot match tracker domains", i)})
			continue
		}
		if allIn(keys, catchAllKeys) {
			checks = append(checks, Check{Name: "rule order", Status: StatusFail,
				Message: fmt.Sprintf("route.rules[%d] (%s) routes all matching traffic before BLANC; move BLANC above it", i, describeKeys(keys))})
			continue
		}
		if allIn(keys, benignKeys) {
			continue
		}
		checks = append(checks, Check{Name: "rule order", Status: StatusWarn,
			Message: fmt.Sprintf("route.rules[%d] (%s) routes traffic before BLANC; tracker domains it matches skip BLANC", i, describeKeys(keys))})
	}
	if len(checks) == 0 {
		checks = append(checks, Check{Name: "rule order", Status: StatusOK, Message: "no route rule before BLANC takes its traffic"})
	}
	return checks
}

func checkSingboxTun(cfg sbConfig) Check {
	for _, inbound := range cfg.Inbounds {
		if stringField(inbound, "type") == "tun" {
			return Check{Name: "tun", Status: StatusOK, Message: "tun inbound present; package_name matches on Android"}
		}
	}
	return Check{Name: "tun", Status: StatusWarn,
		Message: "the rule set names Android packages but there is no tun inbound; package_name only matches through the Android VPN (tun)"}
}

func fakeIP(cfg sbConfig) bool {
	if cfg.DNS.FakeIP != nil && cfg.DNS.FakeIP.Enabled {
		return true
	}
	for _, server := range cfg.DNS.Servers {
		if stringField(server, "type") == "fakeip" || stringField(server, "address") == "fakeip" {
			return true
		}
	}
	return false
}

func referencesTag(raw json.RawMessage, tag string) bool {
	if len(raw) == 0 {
		return false
	}
	var single string
	if json.Unmarshal(raw, &single) == nil {
		return single == tag
	}
	var many []string
	if json.Unmarshal(raw, &many) == nil {
		for _, candidate := range many {
			if candidate == tag {
				return true
			}
		}
	}
	return false
}

func stringField(m map[string]json.RawMessage, key string) string {
	var value string
	if raw, ok := m[key]; ok && json.Unmarshal(raw, &value) == nil {
		return value
	}
	return ""
}

func boolValue(raw json.RawMessage) bool {
	var value bool
	return len(raw) > 0 && json.Unmarshal(raw, &value) == nil && value
}

func matchKeys(rule map[string]json.RawMessage) []string {
	out := make([]string, 0, len(rule))
	for key := range rule {
		switch key {
		case "action", "outbound", "invert", "type", "mode", "override_address", "override_port", "network_strategy", "fallback_delay", "udp_disable_domain_unmapping", "udp_connect", "udp_timeout", "tls_fragment", "tls_record_fragment":
			continue
		}
		out = append(out, key)
	}
	sort.Strings(out)
	return out
}

func allIn(keys []string, set map[string]bool) bool {
	for _, key := range keys {
		if !set[key] {
			return false
		}
	}
	return true
}

func describeKeys(keys []string) string {
	if len(keys) == 0 {
		return "no conditions"
	}
	return strings.Join(keys, ", ")
}
