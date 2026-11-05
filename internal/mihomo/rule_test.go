package mihomo

import "testing"

// 入れ子にも
// 迷わず意味を
// 汲みとれり
func TestParseAndMatch(t *testing.T) {
	cases := []struct {
		line    string
		md      Metadata
		matched bool
		known   bool
	}{
		{"DOMAIN-SUFFIX,umeng.com,REJECT", Metadata{Host: "alog.umeng.com"}, true, true},
		{"DOMAIN-SUFFIX,umeng.com,REJECT", Metadata{Host: "notumeng.com"}, false, true},
		{"DOMAIN,umeng.com,DIRECT", Metadata{Host: "a.umeng.com"}, false, true},
		{"DOMAIN-KEYWORD,umeng,DIRECT", Metadata{Host: "x.umengcloud.com"}, true, true},
		{"AND,((PROCESS-NAME,com.a.b),(DOMAIN-SUFFIX,x.cn)),REJECT", Metadata{Host: "x.cn", Process: "com.a.b"}, true, true},
		{"AND,((PROCESS-NAME,com.a.b),(DOMAIN-SUFFIX,x.cn)),REJECT", Metadata{Host: "x.cn", Process: "com.c.d"}, false, true},
		{"AND,((DOMAIN-SUFFIX,x.cn),(NOT,((PROCESS-NAME,com.a.b)))),REJECT", Metadata{Host: "x.cn"}, true, true},
		{"AND,((DOMAIN-SUFFIX,x.cn),(NOT,((PROCESS-NAME,com.a.b)))),REJECT", Metadata{Host: "x.cn", Process: "com.a.b"}, false, true},
		{"AND,((DOMAIN-SUFFIX,x.cn),(NOT,((AND,((PROCESS-NAME,p.q),(DOMAIN-SUFFIX,y.x.cn)))))),REJECT", Metadata{Host: "z.y.x.cn", Process: "p.q"}, false, true},
		{"AND,((DOMAIN-SUFFIX,x.cn),(NOT,((AND,((PROCESS-NAME,p.q),(DOMAIN-SUFFIX,y.x.cn)))))),REJECT", Metadata{Host: "z.x.cn", Process: "p.q"}, true, true},
		{"OR,((DOMAIN,a.cn),(DOMAIN,b.cn)),DIRECT", Metadata{Host: "b.cn"}, true, true},
		{"GEOSITE,cn,DIRECT", Metadata{Host: "a.cn"}, false, false},
		{"MATCH,DIRECT", Metadata{Host: "a.cn"}, true, true},
	}
	for _, tc := range cases {
		rule, err := ParseLine(tc.line)
		if err != nil {
			t.Fatalf("%s: %v", tc.line, err)
		}
		matched, known := rule.Match(tc.md)
		if matched != tc.matched || known != tc.known {
			t.Fatalf("%s %+v: got (%v,%v), want (%v,%v)", tc.line, tc.md, matched, known, tc.matched, tc.known)
		}
	}
}

func TestParseTargetsAndParams(t *testing.T) {
	rule, err := ParseLine("GEOIP,CN,DIRECT,no-resolve")
	if err != nil {
		t.Fatal(err)
	}
	if rule.Type != "GEOIP" || rule.Payload != "CN" || rule.Target != "DIRECT" || len(rule.Params) != 1 || rule.Params[0] != "no-resolve" {
		t.Fatalf("rule = %+v", rule)
	}
	logic, err := ParseLine("AND,((DOMAIN,a.cn),(PROCESS-NAME,x.y)),REJECT-DROP")
	if err != nil {
		t.Fatal(err)
	}
	if !logic.Rejects() || !logic.UsesProcess() || len(logic.Subs) != 2 {
		t.Fatalf("logic = %+v", logic)
	}
	match, err := ParseLine("MATCH,PROXY")
	if err != nil || match.Target != "PROXY" {
		t.Fatalf("match = %+v %v", match, err)
	}
}

func TestParseErrors(t *testing.T) {
	for _, line := range []string{
		"",
		"DOMAIN-SUFFIX,a.cn",
		"AND,((DOMAIN,a.cn),(DOMAIN,b.cn),REJECT",
		"NOT,((DOMAIN,a.cn),(DOMAIN,b.cn)),REJECT",
		"AND,(),REJECT",
		"AND,DOMAIN,REJECT",
	} {
		if _, err := ParseLine(line); err == nil {
			t.Fatalf("expected error for %q", line)
		}
	}
}
