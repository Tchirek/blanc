package audit

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
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
	Classes map[string]DomainClass
	Sources map[DomainClass]string
	Hashes  map[string]string
	Dir     string
}

var domainSpecs = []struct {
	file  string
	class DomainClass
}{
	{file: "domains-trackers.txt", class: ClassTracker},
	{file: "domains-functional.txt", class: ClassFunctional},
	{file: "domains-other.txt", class: ClassReview},
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
		Sources: make(map[DomainClass]string),
		Hashes:  make(map[string]string),
		Dir:     dir,
	}

	for _, spec := range domainSpecs {
		path := filepath.Join(dir, spec.file)
		raw, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("missing NOIR domain export %s: %w", path, err)
		}
		sum := sha256.Sum256(raw)
		set.Hashes[spec.file] = hex.EncodeToString(sum[:])
		set.Sources[spec.class] = path

		for lineNo, line := range strings.Split(string(raw), "\n") {
			host := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(line), "."))
			if host == "" || strings.HasPrefix(host, "#") {
				continue
			}
			if !ValidDomain(host) {
				return nil, fmt.Errorf("%s:%d: invalid host %q", spec.file, lineNo+1, host)
			}
			if existing, ok := set.Classes[host]; ok && existing != spec.class {
				return nil, fmt.Errorf("%s:%d: %s classified as both %s and %s",
					spec.file, lineNo+1, host, existing, spec.class)
			}
			set.Classes[host] = spec.class
		}
	}
	return set, nil
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
