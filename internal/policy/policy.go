package policy

import (
	"bytes"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	"github.com/Tchirek/blanc/internal/audit"
	"gopkg.in/yaml.v3"
)

//go:embed default.yaml
var defaultYAML []byte

const Version = 2

type Policy struct {
	Version int            `yaml:"version"`
	Allow   []string       `yaml:"allow"`
	Block   []string       `yaml:"block"`
	Apps    map[string]App `yaml:"apps"`

	Hash string `yaml:"-"`
	Path string `yaml:"-"`
}

type App struct {
	AllowAll bool
	Allow    []string
	Block    []string
}

var ErrV1 = errors.New(`policy version 1 is no longer supported.
Version 1 blocked a tracker only inside apps that held "sensitive" permissions,
which left trackers open everywhere else. Version 2 blocks every NOIR tracker
for every app and keeps per-app exceptions. To migrate:
  - delete "sensitive" and "include_system";
  - an app with "mode: allow" becomes "<package>: allow";
  - keep per-app "allow:" / "block:" lists as they are;
  - set "version: 2" (or run: blanc init --force)`)

// 白き壁
// 越えぬ想いを
// 巡らせる
func Default() *Policy {
	return &Policy{Version: Version, Apps: map[string]App{}}
}

func Load(path string) (*Policy, error) {
	var raw []byte
	var err error
	if path == "" {
		raw = append([]byte(nil), defaultYAML...)
	} else {
		raw, err = os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read policy: %w", err)
		}
	}
	p, err := Parse(raw)
	if err != nil {
		if path != "" {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		return nil, err
	}
	p.Path = path
	return p, nil
}

// 札を読み
// 古き形は
// 道を告ぐ
func Parse(raw []byte) (*Policy, error) {
	var head struct {
		Version int `yaml:"version"`
	}
	if err := yaml.Unmarshal(raw, &head); err != nil {
		return nil, fmt.Errorf("parse policy: %w", err)
	}
	switch head.Version {
	case Version:
	case 1:
		return nil, ErrV1
	case 0:
		return nil, fmt.Errorf("policy: missing \"version: %d\"", Version)
	default:
		return nil, fmt.Errorf("policy: unsupported version %d (want %d)", head.Version, Version)
	}

	p := Default()
	decoder := yaml.NewDecoder(bytes.NewReader(raw))
	decoder.KnownFields(true)
	if err := decoder.Decode(p); err != nil && !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("parse policy: %w", err)
	}
	if err := p.normalize(); err != nil {
		return nil, err
	}
	sum := sha256.Sum256(raw)
	p.Hash = hex.EncodeToString(sum[:])
	return p, nil
}

func DefaultYAML() []byte {
	return append([]byte(nil), defaultYAML...)
}

func (p *Policy) normalize() error {
	allow, err := normalizeDomains(p.Allow)
	if err != nil {
		return fmt.Errorf("policy: allow: %w", err)
	}
	block, err := normalizeDomains(p.Block)
	if err != nil {
		return fmt.Errorf("policy: block: %w", err)
	}
	if err := disjoint(allow, block); err != nil {
		return fmt.Errorf("policy: %w", err)
	}
	p.Allow, p.Block = allow, block

	apps := make(map[string]App, len(p.Apps))
	for pkg, app := range p.Apps {
		name := strings.TrimSpace(pkg)
		if !audit.ValidPackage(name) {
			return fmt.Errorf("policy: invalid package %q", pkg)
		}
		if _, exists := apps[name]; exists {
			return fmt.Errorf("policy: duplicate package %q", name)
		}
		if app.Allow, err = normalizeDomains(app.Allow); err != nil {
			return fmt.Errorf("policy: apps.%s.allow: %w", name, err)
		}
		if app.Block, err = normalizeDomains(app.Block); err != nil {
			return fmt.Errorf("policy: apps.%s.block: %w", name, err)
		}
		if err := disjoint(app.Allow, app.Block); err != nil {
			return fmt.Errorf("policy: apps.%s: %w", name, err)
		}
		if app.AllowAll && len(app.Allow) > 0 {
			return fmt.Errorf("policy: apps.%s: \"allow: all\" already covers the listed hosts", name)
		}
		if !app.AllowAll && len(app.Allow) == 0 && len(app.Block) == 0 {
			return fmt.Errorf("policy: apps.%s: empty entry; use \"allow: all\", \"allow: [...]\" or \"block: [...]\"", name)
		}
		apps[name] = app
	}
	p.Apps = apps
	return nil
}

func disjoint(allow, block []string) error {
	set := make(map[string]struct{}, len(allow))
	for _, host := range allow {
		set[host] = struct{}{}
	}
	for _, host := range block {
		if _, ok := set[host]; ok {
			return fmt.Errorf("%q is in both allow and block", host)
		}
	}
	return nil
}

func normalizeDomains(values []string) ([]string, error) {
	set := make(map[string]struct{}, len(values))
	for _, value := range values {
		host, err := audit.NormalizeDomain(strings.TrimPrefix(strings.TrimSpace(value), "+."))
		if err != nil {
			return nil, fmt.Errorf("invalid domain %q", value)
		}
		set[host] = struct{}{}
	}
	out := make([]string, 0, len(set))
	for host := range set {
		out = append(out, host)
	}
	sort.Strings(out)
	return out, nil
}

// 一言か
// 束ねた札か
// 見極める
func (a *App) UnmarshalYAML(node *yaml.Node) error {
	switch node.Kind {
	case yaml.ScalarNode:
		if node.Value != "allow" {
			return fmt.Errorf("line %d: app shorthand must be \"allow\" (got %q)", node.Line, node.Value)
		}
		a.AllowAll = true
		return nil
	case yaml.MappingNode:
	default:
		return fmt.Errorf("line %d: app entry must be \"allow\" or a mapping with allow/block", node.Line)
	}
	for i := 0; i < len(node.Content); i += 2 {
		key, value := node.Content[i], node.Content[i+1]
		switch key.Value {
		case "allow":
			if value.Kind == yaml.ScalarNode {
				if value.Value != "all" {
					return fmt.Errorf("line %d: allow must be \"all\" or a list of domains", value.Line)
				}
				a.AllowAll = true
				continue
			}
			if err := value.Decode(&a.Allow); err != nil {
				return err
			}
		case "block":
			if err := value.Decode(&a.Block); err != nil {
				return err
			}
		case "mode":
			return fmt.Errorf("line %d: \"mode\" was removed in version 2; use \"allow: all\" or allow/block lists", key.Line)
		default:
			return fmt.Errorf("line %d: unknown app field %q", key.Line, key.Value)
		}
	}
	return nil
}

// 札の名を
// 順に並べて
// 示しけり
func (p *Policy) Packages() []string {
	out := make([]string, 0, len(p.Apps))
	for pkg := range p.Apps {
		out = append(out, pkg)
	}
	sort.Strings(out)
	return out
}
