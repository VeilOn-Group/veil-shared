// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Package inventory loads and checks veil-shared/data-inventory.yaml, the
// single source of truth for every piece of data VeilOn handles.
package inventory

import (
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/goccy/go-yaml"

	veilshared "github.com/veilon/veil-shared"
)

// Kinds of inventory entries.
const (
	KindDBTable      = "db_table"
	KindRedisKey     = "redis_key"
	KindLogFields    = "log_fields"
	KindMetricPolicy = "metric_policy"
	KindClientLocal  = "client_local"
	KindNodeLocal    = "node_local" // RAM-only node state
)

// Inventory is the parsed file.
type Inventory struct {
	Version                   string            `yaml:"version"`
	Updated                   string            `yaml:"updated"`
	Categories                map[string]string `yaml:"categories"`
	Forbidden                 []string          `yaml:"forbidden"`
	ForbiddenDBColumnPatterns []string          `yaml:"forbidden_db_column_patterns"`
	TimestampAllowedSchemas   []string          `yaml:"timestamp_allowed_schemas"`
	DBColumnAllowlist         []string          `yaml:"db_column_allowlist"`
	Entries                   []Entry           `yaml:"entries"`
	Processors                []Processor       `yaml:"processors"`
	PublicSummary             PublicSummary     `yaml:"public_summary"`

	forbiddenRe []*regexp.Regexp
}

// Entry describes one data item.
type Entry struct {
	ID              string   `yaml:"id"`
	Kind            string   `yaml:"kind"`
	Category        string   `yaml:"category"`
	Columns         []string `yaml:"columns"`
	PIIColumns      []string `yaml:"pii_columns"`
	Fields          []string `yaml:"fields"`
	Pattern         string   `yaml:"pattern"`
	TTLSecondsMax   int      `yaml:"ttl_seconds_max"`
	AllowedLabels   []string `yaml:"allowed_labels"`
	ForbiddenLabels []string `yaml:"forbidden_labels"`
	Purpose         string   `yaml:"purpose"`
	Retention       string   `yaml:"retention"`
	Access          []string `yaml:"access"`
	LegalBasis      string   `yaml:"legal_basis"`
	Exportable      bool     `yaml:"exportable"`
}

// Processor is an external sub-processor.
type Processor struct {
	ID                   string   `yaml:"id"`
	Purpose              string   `yaml:"purpose"`
	Data                 []string `yaml:"data"`
	Jurisdiction         string   `yaml:"jurisdiction"`
	RetentionAtProcessor string   `yaml:"retention_at_processor"`
	EnabledBy            string   `yaml:"enabled_by"`
}

// Localized is one language's text.
type Localized struct {
	Title string `yaml:"title" json:"title"`
	Text  string `yaml:"text" json:"text"`
}

// SummaryItem is one "what we store" line.
type SummaryItem struct {
	Category string    `yaml:"category" json:"category"`
	RU       Localized `yaml:"ru" json:"ru"`
	SR       Localized `yaml:"sr" json:"sr"`
	EN       Localized `yaml:"en" json:"en"`
}

// PublicSummary feeds the privacy screen and site page.
type PublicSummary struct {
	Stored    []SummaryItem       `yaml:"stored" json:"stored"`
	NotStored map[string][]string `yaml:"not_stored" json:"not_stored"`
}

// Parse parses and validates inventory YAML.
func Parse(data []byte) (*Inventory, error) {
	var inv Inventory
	if err := yaml.UnmarshalWithOptions(data, &inv, yaml.Strict()); err != nil {
		return nil, fmt.Errorf("inventory: %w", err)
	}
	if err := inv.validate(); err != nil {
		return nil, err
	}
	return &inv, nil
}

// Embedded returns the inventory compiled into the binary.
func Embedded() (*Inventory, error) { return Parse(veilshared.DataInventoryYAML) }

func (inv *Inventory) validate() error {
	var errs []error
	seen := map[string]bool{}
	for _, p := range inv.ForbiddenDBColumnPatterns {
		re, err := regexp.Compile(p)
		if err != nil {
			errs = append(errs, fmt.Errorf("forbidden pattern %q: %w", p, err))
			continue
		}
		inv.forbiddenRe = append(inv.forbiddenRe, re)
	}
	for _, e := range inv.Entries {
		if e.ID == "" || seen[e.ID] {
			errs = append(errs, fmt.Errorf("entry %q: empty or duplicate id", e.ID))
		}
		seen[e.ID] = true
		if _, ok := inv.Categories[e.Category]; !ok {
			errs = append(errs, fmt.Errorf("entry %q: unknown category %q", e.ID, e.Category))
		}
		if e.Purpose == "" {
			errs = append(errs, fmt.Errorf("entry %q: purpose is required", e.ID))
		}
		switch e.Kind {
		case KindDBTable:
			if len(e.Columns) == 0 || strings.Count(e.ID, ".") != 1 {
				errs = append(errs, fmt.Errorf("entry %q: db_table needs schema.table id and columns", e.ID))
			}
			if e.Retention == "" || e.LegalBasis == "" {
				errs = append(errs, fmt.Errorf("entry %q: retention and legal_basis required", e.ID))
			}
			for _, c := range e.Columns {
				if inv.ColumnForbidden(e.ID + "." + c) {
					errs = append(errs, fmt.Errorf("entry %q: column %q matches a forbidden pattern", e.ID, c))
				}
			}
		case KindRedisKey:
			if e.Pattern == "" || e.TTLSecondsMax <= 0 {
				errs = append(errs, fmt.Errorf("entry %q: redis keys need pattern and ttl_seconds_max > 0", e.ID))
			}
		case KindLogFields:
			if len(e.Fields) == 0 {
				errs = append(errs, fmt.Errorf("entry %q: log_fields needs fields", e.ID))
			}
		case KindMetricPolicy, KindClientLocal, KindNodeLocal:
		default:
			errs = append(errs, fmt.Errorf("entry %q: unknown kind %q", e.ID, e.Kind))
		}
	}
	for _, s := range inv.PublicSummary.Stored {
		if _, ok := inv.Categories[s.Category]; !ok {
			errs = append(errs, fmt.Errorf("public_summary: unknown category %q", s.Category))
		}
		for lang, l := range map[string]Localized{"ru": s.RU, "sr": s.SR, "en": s.EN} {
			if l.Title == "" || l.Text == "" {
				errs = append(errs, fmt.Errorf("public_summary %q: missing %s text", s.Category, lang))
			}
		}
	}
	for _, lang := range []string{"ru", "sr", "en"} {
		if len(inv.PublicSummary.NotStored[lang]) == 0 {
			errs = append(errs, fmt.Errorf("public_summary.not_stored: missing %s", lang))
		}
	}
	return errors.Join(errs...)
}

// ColumnForbidden reports whether schema.table.column matches a forbidden
// pattern and is not allowlisted.
func (inv *Inventory) ColumnForbidden(fq string) bool {
	for _, a := range inv.DBColumnAllowlist {
		if a == fq {
			return false
		}
	}
	col := fq[strings.LastIndexByte(fq, '.')+1:]
	for _, re := range inv.forbiddenRe {
		if re.MatchString(col) {
			return true
		}
	}
	return false
}

// TimestampAllowed reports whether exact timestamps may live in this schema.
func (inv *Inventory) TimestampAllowed(schema string) bool {
	for _, s := range inv.TimestampAllowedSchemas {
		if s == schema {
			return true
		}
	}
	return false
}

// Tables returns schema.table -> set of declared columns.
func (inv *Inventory) Tables() map[string]map[string]bool {
	out := map[string]map[string]bool{}
	for _, e := range inv.Entries {
		if e.Kind != KindDBTable {
			continue
		}
		cols := map[string]bool{}
		for _, c := range e.Columns {
			cols[c] = true
		}
		out[e.ID] = cols
	}
	return out
}

// RedisKey is a declared key pattern.
type RedisKey struct {
	Prefix string
	TTLMax int
}

// RedisKeys returns the literal prefixes (up to the first '{') with TTLs.
func (inv *Inventory) RedisKeys() []RedisKey {
	var out []RedisKey
	for _, e := range inv.Entries {
		if e.Kind != KindRedisKey {
			continue
		}
		p := e.Pattern
		if i := strings.IndexByte(p, '{'); i >= 0 {
			p = p[:i]
		}
		out = append(out, RedisKey{Prefix: p, TTLMax: e.TTLSecondsMax})
	}
	sort.Slice(out, func(i, j int) bool { return len(out[i].Prefix) > len(out[j].Prefix) })
	return out
}

// MatchRedisKey finds the declared pattern for a concrete key.
func (inv *Inventory) MatchRedisKey(key string) (RedisKey, bool) {
	for _, k := range inv.RedisKeys() {
		if strings.HasPrefix(key, k.Prefix) {
			return k, true
		}
	}
	return RedisKey{}, false
}

// MetricLabels returns the allowed and forbidden metric label sets.
func (inv *Inventory) MetricLabels() (allowed, forbidden map[string]bool) {
	allowed, forbidden = map[string]bool{}, map[string]bool{}
	for _, e := range inv.Entries {
		if e.Kind != KindMetricPolicy {
			continue
		}
		for _, l := range e.AllowedLabels {
			allowed[l] = true
		}
		for _, l := range e.ForbiddenLabels {
			forbidden[l] = true
		}
	}
	return allowed, forbidden
}

// LogFields returns the declared fields of a log stream.
func (inv *Inventory) LogFields(id string) (map[string]bool, bool) {
	for _, e := range inv.Entries {
		if e.ID == id && e.Kind == KindLogFields {
			m := map[string]bool{}
			for _, f := range e.Fields {
				m[f] = true
			}
			return m, true
		}
	}
	return nil, false
}
