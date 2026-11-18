// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package schemalint

import (
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
