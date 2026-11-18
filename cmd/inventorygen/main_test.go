// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunGeneratesSummary(t *testing.T) {
	out := filepath.Join(t.TempDir(), "sub", "what.json")
	var so, se bytes.Buffer
	if code := run([]string{"-in", "../../data-inventory.yaml", "-out", out}, &so, &se); code != 0 {
		t.Fatalf("exit %d: %s", code, se.String())
	}
	if !strings.Contains(so.String(), "OK") {
		t.Fatalf("stdout %q", so.String())
	}
	var doc Output
	b, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	if doc.InventoryVersion == "" || len(doc.Retention) == 0 || len(doc.Processors) == 0 {
		t.Fatalf("incomplete document: %+v", doc)
	}
	for _, r := range doc.Retention {
		if r.Retention == "" {
			t.Fatalf("entry %s without retention", r.ID)
		}
	}
}

// The committed summary must match what the generator produces.
func TestCommittedSummaryUpToDate(t *testing.T) {
	out := filepath.Join(t.TempDir(), "w.json")
	if code := run([]string{"-in", "../../data-inventory.yaml", "-out", out}, &bytes.Buffer{}, &bytes.Buffer{}); code != 0 {
		t.Fatal("generation failed")
	}
	got, _ := os.ReadFile(out)
	want, err := os.ReadFile("../../design/dist/what-we-store.json")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatal("design/dist/what-we-store.json is stale: run make generate")
	}
}

func TestRunErrors(t *testing.T) {
	dir := t.TempDir()
	bad := filepath.Join(dir, "bad.yaml")
	if err := os.WriteFile(bad, []byte("version: [unclosed"), 0o600); err != nil {
		t.Fatal(err)
	}
	blocker := filepath.Join(dir, "file")
	if err := os.WriteFile(blocker, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	cases := map[string][]string{
		"missing input": {"-in", filepath.Join(dir, "nope.yaml")},
		"bad yaml":      {"-in", bad},
		"mkdir fails":   {"-in", "../../data-inventory.yaml", "-out", filepath.Join(blocker, "x", "y.json")},
		"write fails":   {"-in", "../../data-inventory.yaml", "-out", dir},
	}
	for name, args := range cases {
		var se bytes.Buffer
		if code := run(args, &bytes.Buffer{}, &se); code != 1 || !strings.Contains(se.String(), "inventorygen:") {
			t.Errorf("%s: exit %d, stderr %q", name, code, se.String())
		}
	}
	if code := run([]string{"-unknown"}, &bytes.Buffer{}, &bytes.Buffer{}); code != 2 {
		t.Errorf("bad flag: exit %d", code)
	}
}
