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

func TestRunWritesAllFiles(t *testing.T) {
	out := filepath.Join(t.TempDir(), "dist")
	var so, se bytes.Buffer
	if code := run([]string{"-in", "../../design-tokens.json", "-out", out}, &so, &se); code != 0 {
		t.Fatalf("exit %d: %s", code, se.String())
	}
	for _, name := range []string{"tokens.css", "tailwind.css", "VeilColors.kt", "tokens.json"} {
		got, err := os.ReadFile(filepath.Join(out, name))
		if err != nil || len(got) == 0 {
			t.Fatalf("%s: %v", name, err)
		}
		want, err := os.ReadFile(filepath.Join("../../design/dist", name))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, want) {
			t.Errorf("design/dist/%s is stale: run make generate", name)
		}
	}
}

func TestRunContrastViolation(t *testing.T) {
	in := filepath.Join(t.TempDir(), "t.json")
	doc := `{"theme":"dark","color":{"bg":"#FFFFFF","fg":"#FEFEFE"},"contrast":{"text":[["fg","bg"]]}}`
	if err := os.WriteFile(in, []byte(doc), 0o600); err != nil {
		t.Fatal(err)
	}
	var se bytes.Buffer
	if code := run([]string{"-in", in, "-out", t.TempDir()}, &bytes.Buffer{}, &se); code != 1 || !strings.Contains(se.String(), "contrast fg on bg") {
		t.Fatalf("exit %d, stderr %q", code, se.String())
	}
}

func TestRunErrors(t *testing.T) {
	dir := t.TempDir()
	write := func(name, s string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(s), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	bad := write("bad.json", "{")
	unknown := write("unknown.json", `{"theme":"dark","color":{"bg":"#000000"},"contrast":{"text":[["missing","bg"]]}}`)
	blocker := write("blocker", "")
	cases := map[string][]string{
		"missing input": {"-in", filepath.Join(dir, "none.json")},
		"bad json":      {"-in", bad},
		"unknown color": {"-in", unknown},
		"mkdir fails":   {"-in", "../../design-tokens.json", "-out", filepath.Join(blocker, "x")},
		"write fails":   {"-in", "../../design-tokens.json", "-out", write("dir-as-file", "")},
	}
	for name, args := range cases {
		var se bytes.Buffer
		if code := run(args, &bytes.Buffer{}, &se); code != 1 || !strings.Contains(se.String(), "tokensgen:") {
			t.Errorf("%s: exit %d, stderr %q", name, code, se.String())
		}
	}
	if code := run([]string{"-nope"}, &bytes.Buffer{}, &bytes.Buffer{}); code != 2 {
		t.Errorf("bad flag: exit %d", code)
	}
}
