// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeMigration(t *testing.T, sql string) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "0001_test.sql"), []byte(sql), 0o600); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestRunFindings(t *testing.T) {
	dir := writeMigration(t, "-- +goose Up\nCREATE TABLE core.not_in_inventory (id uuid, secret_ip text);\n")
	var so, se bytes.Buffer
	code := run([]string{"-inventory", "../../data-inventory.yaml", "-migrations", dir}, &so, &se)
	if code != 1 {
		t.Fatalf("exit %d, stdout %q stderr %q", code, so.String(), se.String())
	}
	if !strings.Contains(so.String(), "not_in_inventory") || !strings.Contains(se.String(), "finding(s)") {
		t.Fatalf("stdout %q stderr %q", so.String(), se.String())
	}
}

func TestRunClean(t *testing.T) {
	inv := filepath.Join(t.TempDir(), "inv.yaml")
	if err := os.WriteFile(inv, []byte("version: 1.0.0\nupdated: 2026-01-01\ncategories: {ops: Ops}\nentries: []\npublic_summary:\n  not_stored: {ru: [a], sr: [a], en: [a]}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	dir := writeMigration(t, "-- +goose Up\nSELECT 1;\n")
	var so, se bytes.Buffer
	if code := run([]string{"-inventory", inv, "-migrations", dir}, &so, &se); code != 0 {
		t.Fatalf("exit %d: %s %s", code, so.String(), se.String())
	}
	if !strings.Contains(so.String(), "schemalint: OK") {
		t.Fatalf("stdout %q", so.String())
	}
}

func TestRunErrors(t *testing.T) {
	dir := t.TempDir()
	bad := filepath.Join(dir, "bad.yaml")
	if err := os.WriteFile(bad, []byte("entries: [unclosed"), 0o600); err != nil {
		t.Fatal(err)
	}
	cases := map[string][]string{
		"missing inventory":  {"-inventory", filepath.Join(dir, "none.yaml")},
		"bad inventory":      {"-inventory", bad},
		"bad migrations dir": {"-inventory", "../../data-inventory.yaml", "-migrations", "[["},
		"bad flag":           {"-what"},
	}
	for name, args := range cases {
		if code := run(args, &bytes.Buffer{}, &bytes.Buffer{}); code != 2 {
			t.Errorf("%s: exit %d", name, code)
		}
	}
}
