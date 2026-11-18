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
