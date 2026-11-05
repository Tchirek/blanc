package audit

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

type DomainClass string

const (
	ClassTracker    DomainClass = "tracker"
	ClassFunctional DomainClass = "functional"
	ClassReview     DomainClass = "review"
	ClassUnknown    DomainClass = "unknown"
)

type DomainSet struct {
	Classes    map[string]DomainClass
	Hashes     map[string]string
	Dir        string
	SkippedIPs int
	Skipped    []LineIssue
	Repaired   []LineIssue
	Conflicts  []Conflict
}

type LineIssue struct {
	File   string `json:"file"`
	Line   int    `json:"line"`
	Raw    string `json:"raw"`
	Host   string `json:"host,omitempty"`
	Reason string `json:"reason"`
}

type Conflict struct {
	Host    string        `json:"host"`
	Classes []DomainClass `json:"classes"`
	Kept    DomainClass   `json:"kept"`
}

var domainSpecs = []struct {
	file  string
	class DomainClass
}{
	{file: "domains-trackers.txt", class: ClassTracker},
	{file: "domains-functional.txt", class: ClassFunctional},
	{file: "domains-other.txt", class: ClassReview},
}

// 壊れずに
// 守る順位を
// 決めておく
var classRank = map[DomainClass]int{
	ClassFunctional: 3,
	ClassTracker:    2,
	ClassReview:     1,
}

// 砂の名を
// 人の言葉に
// 置き換える
func LoadDomains(dir string) (*DomainSet, error) {
	if strings.TrimSpace(dir) == "" {
		return nil, fmt.Errorf("domain export directory is empty")
	}
	set := &DomainSet{
		Classes: make(map[string]DomainClass),
		Hashes:  make(map[string]string),
		Dir:     dir,
	}
	seen := make(map[string]map[DomainClass]struct{})

	for _, spec := range domainSpecs {
		path := filepath.Join(dir, spec.file)
		raw, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("missing NOIR domain export %s: %w", path, err)
		}
		sum := sha256.Sum256(raw)
		set.Hashes[spec.file] = hex.EncodeToString(sum[:])

		for lineNo, line := range strings.Split(string(raw), "\n") {
			text := strings.TrimSpace(line)
			if text == "" || strings.HasPrefix(text, "#") {
				continue
			}
			host, issue := salvageHost(text)
			if issue == errSkipIP {
				set.SkippedIPs++
				continue
			}
			if issue != nil {
				set.Skipped = append(set.Skipped, LineIssue{
					File: spec.file, Line: lineNo + 1, Raw: text, Reason: issue.Error(),
				})
				continue
			}
			if host != strings.ToLower(strings.TrimSuffix(text, ".")) {
				set.Repaired = append(set.Repaired, LineIssue{
					File: spec.file, Line: lineNo + 1, Raw: text, Host: host,
					Reason: "URL noise around the host was removed",
				})
			}
			if seen[host] == nil {
				seen[host] = make(map[DomainClass]struct{})
			}
			seen[host][spec.class] = struct{}{}
			if existing, ok := set.Classes[host]; !ok || classRank[spec.class] > classRank[existing] {
				set.Classes[host] = spec.class
			}
		}
	}

	for host, classes := range seen {
		if len(classes) < 2 {
			continue
		}
		list := make([]DomainClass, 0, len(classes))
		for class := range classes {
			list = append(list, class)
		}
		sort.Slice(list, func(i, j int) bool { return classRank[list[i]] > classRank[list[j]] })
		set.Conflicts = append(set.Conflicts, Conflict{Host: host, Classes: list, Kept: set.Classes[host]})
	}
	sort.Slice(set.Conflicts, func(i, j int) bool { return set.Conflicts[i].Host < set.Conflicts[j].Host })
	return set, nil
}

var (
	errSkipIP       = errors.New("ip literal")
	errNotHostname  = errors.New("not a hostname (URL template or extraction junk)")
	errSingleLabel  = errors.New("single-label name")
	errUnsupportedS = errors.New("unsupported scheme")
)

// 霞む名の
// 芯だけ拾い
// 屑は捨つ
func salvageHost(text string) (string, error) {
	ep, err := ParseEndpoint(text)
	switch {
	case err == nil:
		return ep.Host, nil
	case errors.Is(err, ErrIPLiteral):
		return "", errSkipIP
	}
	lower := strings.ToLower(text)
	if strings.Contains(lower, "://") && !strings.HasPrefix(lower, "http") && !strings.HasPrefix(lower, "ws") {
		return "", errUnsupportedS
	}
	if !strings.ContainsAny(lower, ".%*{}$") {
		return "", errSingleLabel
	}
	return "", errNotHostname
}

func (d *DomainSet) Class(host string) (DomainClass, bool) {
	class, ok := d.Classes[host]
	return class, ok
}

func (d *DomainSet) Count(class DomainClass) int {
	count := 0
	for _, candidate := range d.Classes {
		if candidate == class {
			count++
		}
	}
	return count
}

// 名を並べ
// 一つの色に
// 揃えけり
func (d *DomainSet) Hosts(class DomainClass) []string {
	out := make([]string, 0)
	for host, candidate := range d.Classes {
		if candidate == class {
			out = append(out, host)
		}
	}
	sort.Strings(out)
	return out
}
