// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package inventory

import (
	"strings"
	"testing"
)

func TestEmbeddedInventoryValid(t *testing.T) {
	inv, err := Embedded()
	if err != nil {
		t.Fatalf("data-inventory.yaml invalid: %v", err)
	}
	if len(inv.Tables()) == 0 || len(inv.RedisKeys()) == 0 {
		t.Fatal("expected tables and redis keys")
	}
}

func TestInventoryForbiddenColumns(t *testing.T) {
	inv, err := Embedded()
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []string{"core.accounts.ip", "core.devices.client_ip", "core.x.remote_addr", "core.x.user_agent", "core.x.last_login_at", "core.x.connected_at", "core.x.geo_country"} {
		if !inv.ColumnForbidden(c) {
			t.Errorf("%s must be forbidden", c)
		}
	}
	if inv.ColumnForbidden("staff_audit.events.actor_ip") {
		t.Error("allowlisted staff audit column rejected")
	}
	if inv.ColumnForbidden("core.accounts.description") {
		t.Error("false positive")
	}
}

func TestInventoryRejectsUndeclaredRedisTTL(t *testing.T) {
	bad := strings.Replace(string(minimal), "ttl_seconds_max: 60", "ttl_seconds_max: 0", 1)
	if _, err := Parse([]byte(bad)); err == nil {
		t.Fatal("redis key without TTL must be rejected")
	}
}

func TestInventoryRejectsForbiddenDeclaredColumn(t *testing.T) {
	bad := strings.Replace(string(minimal), "columns: [id]", "columns: [id, last_ip]", 1)
	if _, err := Parse([]byte(bad)); err == nil {
		t.Fatal("declaring a forbidden column must fail")
	}
}

func TestInventoryRedisMatch(t *testing.T) {
	inv, _ := Embedded()
	k, ok := inv.MatchRedisKey("rl:auth_login:abcdef")
	if !ok || k.TTLMax > 120 {
		t.Fatalf("rate limit key must be declared with TTL <= 120, got %+v %v", k, ok)
	}
	if _, ok := inv.MatchRedisKey("sessions:forever"); ok {
		t.Fatal("undeclared key matched")
	}
}

var minimal = []byte(`
version: 0.0.1
categories: {account: a, ephemeral: e}
forbidden_db_column_patterns: ['(^|_)ip$']
entries:
  - id: core.t
    kind: db_table
    category: account
    columns: [id]
    purpose: p
    retention: r
    legal_basis: contract
  - id: redis.x
    kind: redis_key
    category: ephemeral
    pattern: 'x:{id}'
    purpose: p
    ttl_seconds_max: 60
public_summary:
  stored: []
  not_stored: {ru: [a], sr: [a], en: [a]}
`)

func TestInventoryAccessors(t *testing.T) {
	inv, err := Embedded()
	if err != nil {
		t.Fatal(err)
	}
	if len(inv.TimestampAllowedSchemas) == 0 || !inv.TimestampAllowed(inv.TimestampAllowedSchemas[0]) {
		t.Fatal("declared schema not allowed")
	}
	if inv.TimestampAllowed("no_such_schema") {
		t.Fatal("unknown schema allowed")
	}
	allowed, forbidden := inv.MetricLabels()
	if len(allowed) == 0 || len(forbidden) == 0 {
		t.Fatalf("metric labels: %v / %v", allowed, forbidden)
	}
	for l := range allowed {
		if forbidden[l] {
			t.Errorf("label %q both allowed and forbidden", l)
		}
	}
	var logID string
	for _, e := range inv.Entries {
		if e.Kind == KindLogFields {
			logID = e.ID
			break
		}
	}
	fields, ok := inv.LogFields(logID)
	if !ok || len(fields) == 0 {
		t.Fatalf("log fields of %q: %v %v", logID, fields, ok)
	}
	if _, ok := inv.LogFields("no.such.stream"); ok {
		t.Fatal("unknown log stream found")
	}
}

func TestInventoryValidationErrors(t *testing.T) {
	doc := []byte(`
version: 1.0.0
updated: 2026-01-01
categories: {ops: Ops}
forbidden_db_column_patterns: ["(unclosed", "^ip$"]
entries:
  - {id: "", kind: db_table, category: ops, purpose: x}
  - {id: dup, kind: client_local, category: ops, purpose: x}
  - {id: dup, kind: client_local, category: nope, purpose: ""}
  - {id: core.t, kind: db_table, category: ops, purpose: x, columns: [ip]}
  - {id: k, kind: redis_key, category: ops, purpose: x}
  - {id: l, kind: log_fields, category: ops, purpose: x}
  - {id: m, kind: mystery, category: ops, purpose: x}
public_summary:
  stored:
    - {category: unknown, ru: {title: a, text: b}}
  not_stored: {ru: [a]}
`)
	_, err := Parse(doc)
	if err == nil {
		t.Fatal("invalid inventory accepted")
	}
	for _, want := range []string{
		"forbidden pattern", "empty or duplicate id", "unknown category \"nope\"", "purpose is required",
		"needs schema.table id", "retention and legal_basis", "matches a forbidden pattern",
		"redis keys need pattern", "log_fields needs fields", "unknown kind", "public_summary: unknown category",
		"missing sr text", "not_stored: missing en",
	} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("missing %q in:\n%v", want, err)
		}
	}
	if _, err := Parse([]byte("unknown_key: 1")); err == nil {
		t.Fatal("strict decoding should reject unknown keys")
	}
}

func TestColumnAllowlist(t *testing.T) {
	inv := &Inventory{DBColumnAllowlist: []string{"core.devices.ip"}}
	inv.ForbiddenDBColumnPatterns = []string{"^ip$"}
	if err := inv.validate(); err == nil {
		// validate only fails on missing summaries here; patterns are compiled.
		t.Log("validated")
	}
	if inv.ColumnForbidden("core.devices.ip") {
		t.Fatal("allowlisted column reported")
	}
	if !inv.ColumnForbidden("core.other.ip") {
		t.Fatal("forbidden column not reported")
	}
}
