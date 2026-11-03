package audit

import (
	"errors"
	"net"
	"net/url"
	"regexp"
	"strings"
)

var (
	ErrInvalidHost = errors.New("invalid host")
	ErrIPLiteral   = errors.New("ip literal")
	ErrLocalHost   = errors.New("local host")
	ErrTestHost    = errors.New("test or staging host")
	ErrDocsHost    = errors.New("documentation or infrastructure host")
)

type Endpoint struct {
	Raw  string
	Host string
	Path string
}

var labelPattern = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9_-]{0,61}[a-z0-9])?$`)

var ignoredHosts = map[string]struct{}{
	"schemas.android.com":     {},
	"w3.org":                  {},
	"www.w3.org":              {},
	"xmlpull.org":             {},
	"jakarta.apache.org":      {},
	"apache.org":              {},
	"ns.adobe.com":            {},
	"xml.apache.org":          {},
	"java.sun.com":            {},
	"www.bea.com":             {},
	"github.com":              {},
	"githubusercontent.com":   {},
	"codeberg.org":            {},
	"schemas.microsoft.com":   {},
	"developer.android.com":   {},
	"issuetracker.google.com": {},
	"youtrack.jetbrains.com":  {},
	"example.com":             {},
	"example.net":             {},
	"example.org":             {},
}

var testLabels = map[string]struct{}{
	"test": {}, "testing": {}, "staging": {}, "stg": {}, "dev": {},
	"daily": {}, "preview": {}, "sandbox": {},
}

var trimCut = " \t\r\n\"'`<>()[]{},;"

// 霧の中
// 見えぬ港の
// 灯を探る
func ParseEndpoint(raw string) (Endpoint, error) {
	clean := strings.Trim(strings.TrimSpace(strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, raw)), trimCut)
	if clean == "" {
		return Endpoint{}, ErrInvalidHost
	}
	if fields := strings.Fields(clean); len(fields) > 0 {
		clean = fields[0]
	}

	candidate := clean
	if strings.HasPrefix(candidate, "//") {
		candidate = "https:" + candidate
	} else if !strings.Contains(candidate, "://") {
		candidate = "https://" + candidate
	}

	parsed, err := url.Parse(candidate)
	if err != nil {
		return Endpoint{}, ErrInvalidHost
	}
	switch strings.ToLower(parsed.Scheme) {
	case "http", "https", "ws", "wss":
	default:
		return Endpoint{}, ErrInvalidHost
	}

	host := strings.ToLower(strings.TrimSuffix(parsed.Hostname(), "."))
	if host == "" {
		return Endpoint{}, ErrInvalidHost
	}
	if net.ParseIP(host) != nil {
		return Endpoint{}, ErrIPLiteral
	}
	if host == "localhost" || strings.HasSuffix(host, ".localhost") || strings.HasSuffix(host, ".local") {
		return Endpoint{}, ErrLocalHost
	}
	if _, ok := ignoredHosts[host]; ok {
		return Endpoint{}, ErrDocsHost
	}
	if !ValidDomain(host) {
		return Endpoint{}, ErrInvalidHost
	}
	for _, label := range strings.Split(host, ".") {
		if _, ok := testLabels[label]; ok {
			return Endpoint{}, ErrTestHost
		}
	}

	path := parsed.EscapedPath()
	if path == "" {
		path = "/"
	}
	return Endpoint{Raw: clean, Host: host, Path: path}, nil
}

func ValidDomain(host string) bool {
	host = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
	if host == "" || strings.ContainsAny(host, "*/:@ ") || net.ParseIP(host) != nil {
		return false
	}
	labels := strings.Split(host, ".")
	if len(labels) < 2 {
		return false
	}
	for _, label := range labels {
		if !labelPattern.MatchString(label) {
			return false
		}
	}
	return true
}

func NormalizeDomain(value string) (string, error) {
	host := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(value), "."))
	if !ValidDomain(host) {
		return "", ErrInvalidHost
	}
	return host, nil
}
