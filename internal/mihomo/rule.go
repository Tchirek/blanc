package mihomo

import (
	"fmt"
	"strings"
)

type Rule struct {
	Type    string
	Payload string
	Target  string
	Params  []string
	Subs    []*Rule
}

var logicTypes = map[string]bool{"AND": true, "OR": true, "NOT": true}

// 括弧の
// 入れ子を解きて
// 意を読む
func ParseLine(line string) (*Rule, error) {
	return parse(strings.TrimSpace(line), true)
}

func parse(text string, withTarget bool) (*Rule, error) {
	comma := strings.IndexByte(text, ',')
	if comma < 0 {
		if strings.EqualFold(text, "MATCH") && !withTarget {
			return &Rule{Type: "MATCH"}, nil
		}
		return nil, fmt.Errorf("rule %q has no type", text)
	}
	rule := &Rule{Type: strings.ToUpper(strings.TrimSpace(text[:comma]))}
	rest := text[comma+1:]

	if rule.Type == "MATCH" {
		rule.Target = strings.TrimSpace(rest)
		return rule, nil
	}
	if logicTypes[rule.Type] || rule.Type == "SUB-RULE" {
		end, err := closing(rest)
		if err != nil {
			return nil, fmt.Errorf("rule %q: %w", text, err)
		}
		rule.Payload = rest[:end+1]
		tail := strings.TrimPrefix(strings.TrimSpace(rest[end+1:]), ",")
		if logicTypes[rule.Type] {
			subs, err := splitSubs(rule.Payload)
			if err != nil {
				return nil, fmt.Errorf("rule %q: %w", text, err)
			}
			for _, sub := range subs {
				parsed, err := parse(sub, false)
				if err != nil {
					return nil, err
				}
				rule.Subs = append(rule.Subs, parsed)
			}
			if rule.Type == "NOT" && len(rule.Subs) != 1 {
				return nil, fmt.Errorf("rule %q: NOT takes exactly one rule", text)
			}
		}
		rule.Target, rule.Params = targetAndParams(tail)
		if withTarget && rule.Target == "" {
			return nil, fmt.Errorf("rule %q has no target", text)
		}
		return rule, nil
	}

	parts := strings.Split(rest, ",")
	rule.Payload = strings.TrimSpace(parts[0])
	if len(parts) > 1 {
		rule.Target, rule.Params = targetAndParams(strings.Join(parts[1:], ","))
	}
	if withTarget && rule.Target == "" {
		return nil, fmt.Errorf("rule %q has no target", text)
	}
	return rule, nil
}

func targetAndParams(tail string) (string, []string) {
	if strings.TrimSpace(tail) == "" {
		return "", nil
	}
	parts := strings.Split(tail, ",")
	params := make([]string, 0, len(parts)-1)
	for _, part := range parts[1:] {
		params = append(params, strings.TrimSpace(part))
	}
	return strings.TrimSpace(parts[0]), params
}

func closing(text string) (int, error) {
	if !strings.HasPrefix(text, "(") {
		return 0, fmt.Errorf("logic payload must start with '('")
	}
	depth := 0
	for i, r := range text {
		switch r {
		case '(':
			depth++
		case ')':
			depth--
			if depth == 0 {
				return i, nil
			}
		}
	}
	return 0, fmt.Errorf("unbalanced parentheses")
}

func splitSubs(payload string) ([]string, error) {
	inner := strings.TrimSpace(payload[1 : len(payload)-1])
	out := make([]string, 0)
	for inner != "" {
		end, err := closing(inner)
		if err != nil {
			return nil, err
		}
		out = append(out, strings.TrimSpace(inner[1:end]))
		inner = strings.TrimPrefix(strings.TrimSpace(inner[end+1:]), ",")
		inner = strings.TrimSpace(inner)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("empty logic rule")
	}
	return out, nil
}

type Metadata struct {
	Host    string
	Process string
}

// 知る型は
// 確かに答え
// 他は黙す
func (r *Rule) Match(md Metadata) (matched bool, known bool) {
	host := strings.ToLower(md.Host)
	payload := strings.ToLower(r.Payload)
	switch r.Type {
	case "MATCH":
		return true, true
	case "DOMAIN":
		return host == payload, true
	case "DOMAIN-SUFFIX":
		return host == payload || strings.HasSuffix(host, "."+payload), true
	case "DOMAIN-KEYWORD":
		return strings.Contains(host, payload), true
	case "PROCESS-NAME":
		return md.Process != "" && md.Process == r.Payload, true
	case "AND":
		for _, sub := range r.Subs {
			ok, known := sub.Match(md)
			if !known {
				return false, false
			}
			if !ok {
				return false, true
			}
		}
		return true, true
	case "OR":
		for _, sub := range r.Subs {
			ok, known := sub.Match(md)
			if !known {
				return false, false
			}
			if ok {
				return true, true
			}
		}
		return false, true
	case "NOT":
		ok, known := r.Subs[0].Match(md)
		return !ok, known
	}
	return false, false
}

// 鍵を待つ
// 名の札ありや
// 探しけり
func (r *Rule) UsesProcess() bool {
	if strings.HasPrefix(r.Type, "PROCESS-") || r.Type == "UID" {
		return true
	}
	for _, sub := range r.Subs {
		if sub.UsesProcess() {
			return true
		}
	}
	return false
}

func (r *Rule) Rejects() bool {
	return strings.HasPrefix(strings.ToUpper(r.Target), "REJECT")
}
