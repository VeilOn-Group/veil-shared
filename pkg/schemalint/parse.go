// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Package schemalint checks SQL migrations (goose format) against the data
// inventory: no undeclared tables/columns, no forbidden
// columns (IP, user agent, session times...), no exact timestamps in
// user-data schemas.
package schemalint

import (
	"fmt"
	"regexp"
	"strings"
)

// Column is a column definition found in a migration.
type Column struct {
	Table string // schema.table
	Name  string
	Type  string // lowercased first type token(s)
	File  string
}

// Table is a table found in a migration.
type Table struct {
	Name    string
	File    string
	Columns []Column
}

var (
	reLineComment  = regexp.MustCompile(`--[^\n]*`)
	reBlockComment = regexp.MustCompile(`(?s)/\*.*?\*/`)
	reDollarQuoted = regexp.MustCompile(`(?s)\$([A-Za-z_]*)\$.*?\$([A-Za-z_]*)\$`)
	reCreateTable  = regexp.MustCompile(`(?is)\bcreate\s+(?:unlogged\s+)?table\s+(?:if\s+not\s+exists\s+)?([a-z_][a-z0-9_]*(?:\.[a-z_][a-z0-9_]*)?)\s*\(`)
	reAlterAdd     = regexp.MustCompile(`(?is)\balter\s+table\s+(?:if\s+exists\s+)?(?:only\s+)?([a-z_][a-z0-9_]*(?:\.[a-z_][a-z0-9_]*)?)\s+add\s+(?:column\s+)?(?:if\s+not\s+exists\s+)?([a-z_][a-z0-9_]*)\s+([a-z][a-z0-9_ ]*)`)
	reAlterRename  = regexp.MustCompile(`(?is)\balter\s+table\s+(?:if\s+exists\s+)?(?:only\s+)?([a-z_][a-z0-9_]*(?:\.[a-z_][a-z0-9_]*)?)\s+rename\s+column\s+([a-z_][a-z0-9_]*)\s+to\s+([a-z_][a-z0-9_]*)`)
	reGooseDown    = regexp.MustCompile(`(?m)^--\s*\+goose\s+Down\b`)
)

var constraintStarts = []string{"constraint", "primary", "unique", "foreign", "check", "exclude", "like"}

// ParseMigration extracts tables/columns from the Up section of one file.
func ParseMigration(file, sql string) ([]Table, []Column, error) {
	if loc := reGooseDown.FindStringIndex(sql); loc != nil {
		sql = sql[:loc[0]]
	}
	sql = reBlockComment.ReplaceAllString(sql, " ")
	sql = reDollarQuoted.ReplaceAllString(sql, " ")
	sql = reLineComment.ReplaceAllString(sql, " ")

	var tables []Table
	var added []Column
	for _, m := range reCreateTable.FindAllStringSubmatchIndex(sql, -1) {
		name := strings.ToLower(sql[m[2]:m[3]])
		if !strings.Contains(name, ".") {
			return nil, nil, fmt.Errorf("%s: table %q must be schema-qualified", file, name)
		}
		body, err := parenBody(sql, m[1]-1)
		if err != nil {
			return nil, nil, fmt.Errorf("%s: table %s: %w", file, name, err)
		}
		t := Table{Name: name, File: file}
		for _, item := range splitTopLevel(body) {
			fields := strings.Fields(strings.ToLower(item))
			if len(fields) < 2 || isConstraint(fields[0]) {
				continue
			}
			t.Columns = append(t.Columns, Column{Table: name, Name: strings.Trim(fields[0], `"`), Type: normType(fields[1:]), File: file})
		}
		tables = append(tables, t)
	}
	for _, m := range reAlterAdd.FindAllStringSubmatch(sql, -1) {
		name := strings.ToLower(m[1])
		if strings.EqualFold(m[2], "constraint") {
			continue
		}
		added = append(added, Column{Table: name, Name: strings.ToLower(m[2]), Type: normType(strings.Fields(strings.ToLower(m[3]))), File: file})
	}
	for _, m := range reAlterRename.FindAllStringSubmatch(sql, -1) {
		added = append(added, Column{Table: strings.ToLower(m[1]), Name: strings.ToLower(m[3]), Type: "renamed", File: file})
	}
	return tables, added, nil
}

func isConstraint(tok string) bool {
	for _, c := range constraintStarts {
		if tok == c {
			return true
		}
	}
	return false
}

func normType(f []string) string {
	if len(f) == 0 {
		return ""
	}
	t := f[0]
	if i := strings.IndexByte(t, '('); i >= 0 {
		t = t[:i]
	}
	if (t == "timestamp" || t == "time") && len(f) >= 3 && f[1] == "with" {
		return t + "tz"
	}
	return t
}

// IsTimestampType reports exact-time column types.
func IsTimestampType(t string) bool {
	switch t {
	case "timestamp", "timestamptz", "timestamptztz", "time", "timetz":
		return true
	}
	return false
}

func parenBody(s string, open int) (string, error) {
	depth := 0
	for i := open; i < len(s); i++ {
		switch s[i] {
		case '(':
			depth++
		case ')':
			depth--
			if depth == 0 {
				return s[open+1 : i], nil
			}
		}
	}
	return "", fmt.Errorf("unbalanced parentheses")
}

func splitTopLevel(body string) []string {
	var out []string
	depth, start := 0, 0
	inQuote := false
	for i := 0; i < len(body); i++ {
		switch c := body[i]; {
		case c == '\'':
			inQuote = !inQuote
		case inQuote:
		case c == '(':
			depth++
		case c == ')':
			depth--
		case c == ',' && depth == 0:
			out = append(out, strings.TrimSpace(body[start:i]))
			start = i + 1
		}
	}
	if tail := strings.TrimSpace(body[start:]); tail != "" {
		out = append(out, tail)
	}
	return out
}
