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
	Version    int                       `yaml:"version"`
	Compile    Compile                   `yaml:"compile"`
	Sensitive  Sensitive                 `yaml:"sensitive"`
	Apps       map[string]AppOverride    `yaml:"apps"`
	Domains    map[string]DomainOverride `yaml:"domains"`
	Quarantine Quarantine                `yaml:"quarantine"`

	Hash string `yaml:"-"`
	Path string `yaml:"-"`
}

type Compile struct {
	Globalize     string `yaml:"globalize"`
	IncludeSystem bool   `yaml:"include_system"`
}

type Sensitive struct {
	Require    bool     `yaml:"require"`
	DataTypes  []string `yaml:"data_types"`
	Categories []string `yaml:"categories"`
	MinScore   int      `yaml:"min_score"`
}

type AppOverride struct {
	Mode  string   `yaml:"mode"`
	Block []string `yaml:"block"`
	Allow []string `yaml:"allow"`
}

type DomainOverride struct {
	Action string `yaml:"action"`
}

type Quarantine struct {
	MinBlockedDomains  int  `yaml:"min_blocked_domains"`
	IncludeSystem      bool `yaml:"include_system"`
	IncludeSharedUID   bool `yaml:"include_shared_uid"`
	BackgroundRestrict bool `yaml:"background_restrict"`
	AppOpsBackground   bool `yaml:"appops_background"`
	ForceStop          bool `yaml:"force_stop"`
}

var allowedGlobalize = map[string]struct{}{"none": {}, "trackers": {}, "all": {}}
var allowedModes = map[string]struct{}{"auto": {}, "allow": {}, "block": {}, "review": {}}
var allowedActions = map[string]struct{}{"allow": {}, "block": {}, "review": {}}

// 線を引く
// 内と外との
// 境目に
func Default() *Policy {
	p := &Policy{
		Version: 1,
		Compile: Compile{
			Globalize:     "none",
			IncludeSystem: true,
		},
		Sensitive: Sensitive{
			Require:    true,
			DataTypes:  audit.KnownDataTypes(),
			Categories: []string{"telemetry", "ads", "location", "security", "system"},
			MinScore:   0,
		},
		Apps:    map[string]AppOverride{},
		Domains: map[string]DomainOverride{},
		Quarantine: Quarantine{
			MinBlockedDomains:  1,
			IncludeSystem:      false,
			IncludeSharedUID:   false,
			BackgroundRestrict: true,
			AppOpsBackground:   false,
			ForceStop:          true,
		},
	}
	return p
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
	p.Compile.Globalize = strings.ToLower(strings.TrimSpace(p.Compile.Globalize))
	if _, ok := allowedGlobalize[p.Compile.Globalize]; !ok {
		return fmt.Errorf("policy: compile.globalize must be none, trackers or all")
	}
	if p.Sensitive.MinScore < 0 {
		return fmt.Errorf("policy: sensitive.min_score must be >= 0")
	}
	if p.Sensitive.Require && len(p.Sensitive.DataTypes) == 0 {
		return fmt.Errorf("policy: sensitive.data_types is empty; list types or set sensitive.require to false")
	}

	dataTypes, err := normalizeDataTypes(p.Sensitive.DataTypes)
	if err != nil {
		return err
	}
	p.Sensitive.DataTypes = dataTypes

	categories, err := normalizeCategories(p.Sensitive.Categories)
	if err != nil {
		return err
	}
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

	if p.Domains == nil {
		p.Domains = map[string]DomainOverride{}
	}
	domains := make(map[string]DomainOverride, len(p.Domains))
	for domain, override := range p.Domains {
		host, err := audit.NormalizeDomain(domain)
		if err != nil {
			return fmt.Errorf("policy: invalid domain %q", domain)
		}
		if _, exists := domains[host]; exists {
			return fmt.Errorf("policy: duplicate domain %q", host)
		}
		if err := normalizeDomainOverride(&override); err != nil {
			return fmt.Errorf("policy: domains.%s: %w", host, err)
		}
		domains[host] = override
	}
	p.Domains = domains

	if p.Quarantine.MinBlockedDomains < 1 {
		return fmt.Errorf("policy: quarantine.min_blocked_domains must be >= 1")
	}
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
		return fmt.Errorf("mode must be auto, allow, block or review")
	}
	block, err := normalizeDomains(override.Block)
	if err != nil {
		return fmt.Errorf("block: %w", err)
	}
	allow, err := normalizeDomains(override.Allow)
	if err != nil {
		return fmt.Errorf("allow: %w", err)
	}
	seen := make(map[string]struct{}, len(block))
	for _, host := range block {
		seen[host] = struct{}{}
	}
	for _, host := range allow {
		if _, ok := seen[host]; ok {
			return fmt.Errorf("domain %q is in both block and allow", host)
		}
	}
	override.Block = block
	override.Allow = allow
	return nil
}

func normalizeDomainOverride(override *DomainOverride) error {
	override.Action = strings.ToLower(strings.TrimSpace(override.Action))
	if override.Action == "" {
		override.Action = "review"
	}
	if _, ok := allowedActions[override.Action]; !ok {
		return fmt.Errorf("action must be allow, block or review")
	}
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
		case "block":
			if err := value.Decode(&o.Block); err != nil {
				return err
			}
		case "allow":
			if err := value.Decode(&o.Allow); err != nil {
				return err
			}
		default:
			return fmt.Errorf("line %d: unknown app override field %q", key.Line, key.Value)
		}
	}
	return nil
}

func (o *DomainOverride) UnmarshalYAML(node *yaml.Node) error {
	if node.Kind == yaml.ScalarNode {
		o.Action = node.Value
		return nil
	}
	if node.Kind != yaml.MappingNode {
		return fmt.Errorf("line %d: domain override must be a string or mapping", node.Line)
	}
	for i := 0; i < len(node.Content); i += 2 {
		key, value := node.Content[i], node.Content[i+1]
		switch key.Value {
		case "action":
			if err := value.Decode(&o.Action); err != nil {
				return err
			}
		default:
			return fmt.Errorf("line %d: unknown domain override field %q", key.Line, key.Value)
		}
	}
	return nil
}
