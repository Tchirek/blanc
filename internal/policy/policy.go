package policy

import (
	"bytes"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/blanc-sh/blanc/internal/audit"
	"gopkg.in/yaml.v3"
)

//go:embed default.yaml
var defaultYAML []byte

type Policy struct {
	Version       int                    `yaml:"version"`
	Sensitive     Sensitive              `yaml:"sensitive"`
	IncludeSystem bool                   `yaml:"include_system"`
	Apps          map[string]AppOverride `yaml:"apps"`

	Hash string `yaml:"-"`
	Path string `yaml:"-"`
}

type Sensitive struct {
	DataTypes  []string `yaml:"data_types"`
	Categories []string `yaml:"categories"`
}

type AppOverride struct {
	Mode  string   `yaml:"mode"`
	Allow []string `yaml:"allow"`
	Block []string `yaml:"block"`
}

var allowedModes = map[string]struct{}{"auto": {}, "allow": {}, "review": {}, "block": {}}

// 白き壁
// 越えぬ想いを
// 巡らせる
func Default() *Policy {
	return &Policy{
		Version: 1,
		Sensitive: Sensitive{
			DataTypes:  audit.KnownDataTypes(),
			Categories: []string{"telemetry", "ads", "location", "security", "system"},
		},
		IncludeSystem: true,
		Apps:          map[string]AppOverride{},
	}
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

	p := Default()
	decoder := yaml.NewDecoder(bytes.NewReader(raw))
	decoder.KnownFields(true)
	if err := decoder.Decode(p); err != nil {
		return nil, fmt.Errorf("parse policy: %w", err)
	}
	if err := p.normalize(); err != nil {
		return nil, err
	}
	sum := sha256.Sum256(raw)
	p.Hash = hex.EncodeToString(sum[:])
	p.Path = path
	return p, nil
}

func DefaultYAML() []byte {
	return append([]byte(nil), defaultYAML...)
}

func (p *Policy) normalize() error {
	if p.Version != 1 {
		return fmt.Errorf("policy: unsupported version %d (want 1)", p.Version)
	}

	dataTypes, err := normalizeDataTypes(p.Sensitive.DataTypes)
	if err != nil {
		return err
	}
	categories, err := normalizeCategories(p.Sensitive.Categories)
	if err != nil {
		return err
	}
	if len(dataTypes) == 0 && len(categories) == 0 {
		return fmt.Errorf("policy: sensitive.data_types and sensitive.categories are both empty")
	}
	p.Sensitive.DataTypes = dataTypes
	p.Sensitive.Categories = categories

	if p.Apps == nil {
		p.Apps = map[string]AppOverride{}
	}
	apps := make(map[string]AppOverride, len(p.Apps))
	for pkg, override := range p.Apps {
		name := strings.TrimSpace(pkg)
		if !audit.ValidPackage(name) {
			return fmt.Errorf("policy: invalid package %q", pkg)
		}
		if _, exists := apps[name]; exists {
			return fmt.Errorf("policy: duplicate package %q", name)
		}
		if err := normalizeAppOverride(&override); err != nil {
			return fmt.Errorf("policy: apps.%s: %w", name, err)
		}
		apps[name] = override
	}
	p.Apps = apps
	return nil
}

func normalizeDataTypes(values []string) ([]string, error) {
	set := make(map[string]struct{}, len(values))
	for _, value := range values {
		slug, ok := audit.NormalizeDataType(value)
		if !ok {
			return nil, fmt.Errorf("policy: unknown data type %q", value)
		}
		set[slug] = struct{}{}
	}
	return audit.OrderedDataTypes(set), nil
}

func normalizeCategories(values []string) ([]string, error) {
	set := make(map[string]struct{}, len(values))
	for _, value := range values {
		slug, ok := audit.NormalizeCategory(value)
		if !ok {
			return nil, fmt.Errorf("policy: unknown category %q", value)
		}
		set[slug] = struct{}{}
	}
	out := make([]string, 0, len(set))
	for slug := range set {
		out = append(out, slug)
	}
	sort.Strings(out)
	return out, nil
}

func normalizeAppOverride(override *AppOverride) error {
	override.Mode = strings.ToLower(strings.TrimSpace(override.Mode))
	if override.Mode == "" {
		override.Mode = "auto"
	}
	if _, ok := allowedModes[override.Mode]; !ok {
		return fmt.Errorf("mode must be auto, allow, review or block")
	}
	allow, err := normalizeDomains(override.Allow)
	if err != nil {
		return fmt.Errorf("allow: %w", err)
	}
	block, err := normalizeDomains(override.Block)
	if err != nil {
		return fmt.Errorf("block: %w", err)
	}
	allowed := make(map[string]struct{}, len(allow))
	for _, host := range allow {
		allowed[host] = struct{}{}
	}
	for _, host := range block {
		if _, ok := allowed[host]; ok {
			return fmt.Errorf("domain %q is in both allow and block", host)
		}
	}
	override.Allow = allow
	override.Block = block
	return nil
}

func normalizeDomains(values []string) ([]string, error) {
	set := make(map[string]struct{}, len(values))
	for _, value := range values {
		host, err := audit.NormalizeDomain(value)
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

func (o *AppOverride) UnmarshalYAML(node *yaml.Node) error {
	if node.Kind == yaml.ScalarNode {
		o.Mode = node.Value
		return nil
	}
	if node.Kind != yaml.MappingNode {
		return fmt.Errorf("line %d: app override must be a string or mapping", node.Line)
	}
	for i := 0; i < len(node.Content); i += 2 {
		key, value := node.Content[i], node.Content[i+1]
		switch key.Value {
		case "mode":
			if err := value.Decode(&o.Mode); err != nil {
				return err
			}
		case "allow":
			if err := value.Decode(&o.Allow); err != nil {
				return err
			}
		case "block":
			if err := value.Decode(&o.Block); err != nil {
				return err
			}
		default:
			return fmt.Errorf("line %d: unknown app override field %q", key.Line, key.Value)
		}
	}
	return nil
}
