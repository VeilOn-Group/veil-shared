// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package schemalint

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/veilon/veil-shared/pkg/inventory"
)

const inv = `
version: 0.0.1
categories: {account: a, staff: s}
forbidden_db_column_patterns: ['(^|_)ip$', 'user_agent', 'connected_at']
timestamp_allowed_schemas: [staff_audit]
db_column_allowlist: [staff_audit.events.actor_ip]
entries:
  - {id: core.accounts, kind: db_table, category: account, columns: [id, email, created_on], purpose: p, retention: r, legal_basis: contract}
  - {id: staff_audit.events, kind: db_table, category: staff, columns: [id, actor_ip, created_at], purpose: p, retention: r, legal_basis: li}
public_summary: {stored: [], not_stored: {ru: [a], sr: [a], en: [a]}}
`

func lint(t *testing.T, sql map[string]string) []Finding {
	t.Helper()
	i, err := inventory.Parse([]byte(inv))
	if err != nil {
		t.Fatal(err)
	}
	f, err := Lint(i, sql)
	if err != nil {
		t.Fatal(err)
	}
	return f
}

const good = `-- +goose Up
CREATE TABLE core.accounts (
  id uuid PRIMARY KEY,
  email text NULL CHECK (email <> ''),
  created_on date NOT NULL DEFAULT current_date,
  CONSTRAINT x UNIQUE (email)
);
CREATE TABLE staff_audit.events (id bigserial PRIMARY KEY, actor_ip text, created_at timestamptz NOT NULL DEFAULT now());
CREATE FUNCTION staff_audit.f() RETURNS trigger AS $$ BEGIN CREATE TABLE core.hidden(ip text); END $$ LANGUAGE plpgsql;
-- +goose Down
DROP TABLE core.accounts;
CREATE TABLE core.ignored_in_down (ip text);
`

func TestSchemaLintClean(t *testing.T) {
	if f := lint(t, map[string]string{"0001.sql": good}); len(f) != 0 {
		t.Fatalf("unexpected findings: %v", f)
	}
}

func TestSchemaLintCatches(t *testing.T) {
	cases := map[string]string{
		"forbidden column": "ALTER TABLE core.accounts ADD COLUMN last_ip inet;",
		"user agent":       "ALTER TABLE core.accounts ADD user_agent text;",
		"undeclared col":   "ALTER TABLE core.accounts ADD COLUMN nickname text;",
		"undeclared table": "CREATE TABLE core.sessions (id uuid);",
		"timestamp":        "ALTER TABLE core.accounts ADD COLUMN created_on2 timestamp with time zone;",
		"rename to ip":     "ALTER TABLE core.accounts RENAME COLUMN email TO client_ip;",
		"unqualified":      "CREATE TABLE accounts (id uuid);",
	}
	for name, extra := range cases {
		t.Run(name, func(t *testing.T) {
			i, _ := inventory.Parse([]byte(inv))
			f, err := Lint(i, map[string]string{"0001.sql": good, "0002.sql": "-- +goose Up\n" + extra})
			if err == nil && len(f) == 0 {
				t.Fatalf("expected a finding for %q", extra)
			}
		})
	}
}

func TestSchemaLintDeclaredButMissing(t *testing.T) {
	f := lint(t, map[string]string{"0001.sql": "-- +goose Up\nCREATE TABLE core.accounts (id uuid, email text, created_on date);"})
	if len(f) != 1 || !strings.Contains(f[0].Message, "staff_audit.events is declared but not created") {
		t.Fatalf("want drift finding, got %v", f)
	}
}

func TestLintDir(t *testing.T) {
	i, err := inventory.Parse([]byte(inv))
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "0001.sql"), []byte(good), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "notes.txt"), []byte("CREATE TABLE core.x (ip text);"), 0o600); err != nil {
		t.Fatal(err)
	}
	f, err := LintDir(i, dir)
	if err != nil || len(f) != 0 {
		t.Fatalf("clean dir: %v %v", f, err)
	}
	if _, err := LintDir(i, "[["); err == nil {
		t.Fatal("bad glob pattern accepted")
	}
	if err := os.Mkdir(filepath.Join(dir, "0002.sql"), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := LintDir(i, dir); err == nil {
		t.Fatal("unreadable migration accepted")
	}
}

func TestParseMigrationEdgeCases(t *testing.T) {
	sql := `-- +goose Up
CREATE TABLE core.t (
  id uuid,
  note varchar(20) DEFAULT 'a, (b',
  at timestamp with time zone,
  t2 time with time zone,
  CONSTRAINT pk PRIMARY KEY (id),
  lonely
);
ALTER TABLE core.t ADD CONSTRAINT u UNIQUE (id);
ALTER TABLE core.t ADD COLUMN extra numeric(10,2);
`
	tables, added, err := ParseMigration("x.sql", sql)
	if err != nil {
		t.Fatal(err)
	}
	cols := map[string]string{}
	for _, c := range tables[0].Columns {
		cols[c.Name] = c.Type
	}
	want := map[string]string{"id": "uuid", "note": "varchar", "at": "timestamptz", "t2": "timetz"}
	for k, v := range want {
		if cols[k] != v {
			t.Errorf("column %s: %q, want %q (all: %v)", k, cols[k], v, cols)
		}
	}
	if len(cols) != len(want) {
		t.Errorf("unexpected columns: %v", cols)
	}
	if len(added) != 1 || added[0].Name != "extra" || added[0].Type != "numeric" {
		t.Errorf("added: %+v", added)
	}
	if _, _, err := ParseMigration("y.sql", "CREATE TABLE core.broken (id uuid"); err == nil || !strings.Contains(err.Error(), "unbalanced") {
		t.Fatalf("unbalanced: %v", err)
	}
	if normType(nil) != "" {
		t.Fatal("empty type")
	}
}
