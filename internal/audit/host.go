package audit

import (
	"errors"
	"net/netip"
	"net/url"
	"regexp"
	"strings"
)

var (
	ErrInvalidHost = errors.New("invalid host")
	ErrIPLiteral   = errors.New("ip literal")
)

type Endpoint struct {
	Raw  string
	Host string
}

var labelPattern = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9_-]{0,61}[a-z0-9])?$`)

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
	if isIP(host) {
		return Endpoint{}, ErrIPLiteral
	}
	if !ValidDomain(host) {
		return Endpoint{}, ErrInvalidHost
	}

	return Endpoint{Raw: clean, Host: host}, nil
}

func ValidDomain(host string) bool {
	host = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
	if host == "" || strings.ContainsAny(host, "*/:@ ") || isIP(host) {
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

// 大き名の
// 枝葉の先まで
// 影は及ぶ
func Covers(parent, host string) bool {
	return host == parent || strings.HasSuffix(host, "."+parent)
}

func NormalizeDomain(value string) (string, error) {
	host := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(value), "."))
	if !ValidDomain(host) {
		return "", ErrInvalidHost
	}
	return host, nil
}

// 数の名は
// 港に非ずと
// 見分けけり
func isIP(host string) bool {
	_, err := netip.ParseAddr(host)
	return err == nil
}
