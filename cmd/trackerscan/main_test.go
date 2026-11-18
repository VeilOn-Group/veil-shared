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

func tree(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	for name, body := range files {
		p := filepath.Join(root, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func TestRunClean(t *testing.T) {
	root := tree(t, map[string]string{
		"go.mod":                      "module x\nrequire github.com/goccy/go-yaml v1.0.0\n",
		"web/package.json":            `{"dependencies":{"react":"18"}}`,
		"node_modules/x/package.json": `{"name":"@sentry/browser"}`,
		"README.md":                   "we never use mixpanel",
	})
	var so bytes.Buffer
	if code := run([]string{"-root", root}, &so, &bytes.Buffer{}); code != 0 {
		t.Fatalf("exit %d: %s", code, so.String())
	}
	if !strings.Contains(so.String(), "trackerscan: OK") {
		t.Fatalf("stdout %q", so.String())
	}
}

func TestRunFindsTrackers(t *testing.T) {
	root := tree(t, map[string]string{
		"app/build.gradle.kts": "implementation(\"com.google.firebase:firebase-analytics:21.0.0\")\n",
		"web/package.json":     `{"dependencies":{"@Sentry/react":"7"}}`,
		".git/config":          "mixpanel",
	})
	var so bytes.Buffer
	if code := run([]string{"-root", root}, &so, &bytes.Buffer{}); code != 1 {
		t.Fatalf("exit %d", code)
	}
	out := so.String()
	for _, want := range []string{"firebase-analytics", "@sentry/", "build.gradle.kts:1"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in %q", want, out)
		}
	}
	if strings.Contains(out, ".git") {
		t.Error(".git must be skipped")
	}
}

func TestRunErrors(t *testing.T) {
	if code := run([]string{"-root", filepath.Join(t.TempDir(), "missing")}, &bytes.Buffer{}, &bytes.Buffer{}); code != 2 {
		t.Errorf("missing root: exit %d", code)
	}
	if code := run([]string{"-bogus"}, &bytes.Buffer{}, &bytes.Buffer{}); code != 2 {
		t.Errorf("bad flag: exit %d", code)
	}
	if os.Geteuid() != 0 {
		root := tree(t, map[string]string{"package.json": "{}"})
		if err := os.Chmod(filepath.Join(root, "package.json"), 0); err != nil {
			t.Fatal(err)
		}
		if code := run([]string{"-root", root}, &bytes.Buffer{}, &bytes.Buffer{}); code != 2 {
			t.Errorf("unreadable manifest: exit %d", code)
		}
	}
}

// This repository itself must stay clean.
func TestRepositoryHasNoTrackers(t *testing.T) {
	hits, err := scan("../..")
	if err != nil {
		t.Fatal(err)
	}
	if len(hits) > 0 {
		t.Fatalf("tracker dependencies: %v", hits)
	}
}
