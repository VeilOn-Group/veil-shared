// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package rulesets

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestCategoryRUPinned(t *testing.T) {
	b, err := CategoryRU()
	if err != nil {
		t.Fatal(err)
	}
	if len(b) < 1000 || !bytes.HasPrefix(b, []byte("SRS")) {
		t.Fatal("not a sing-box binary rule set")
	}
	p, err := WriteCategoryRU(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(p)
	if !bytes.Equal(got, b) {
		t.Fatal("written file differs")
	}
}

func TestTamperedRejected(t *testing.T) {
	orig := categoryRU
	defer func() { categoryRU = orig }()
	categoryRU = append([]byte(nil), orig...)
	categoryRU[len(categoryRU)-1] ^= 1
	if _, err := CategoryRU(); !errors.Is(err, ErrHash) {
		t.Fatalf("want ErrHash, got %v", err)
	}
}

func TestWriteCategoryRUErrors(t *testing.T) {
	if _, err := WriteCategoryRU(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Fatal("write into a missing directory succeeded")
	}
	// The target name is taken by a directory: the rename fails and the
	// temporary file is cleaned up.
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, CategoryRUFile, "x"), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := WriteCategoryRU(dir); err == nil {
		t.Fatal("rename over a directory succeeded")
	}
	if _, err := os.Stat(filepath.Join(dir, CategoryRUFile+".tmp")); !os.IsNotExist(err) {
		t.Fatal("temporary file left behind")
	}
	orig := categoryRU
	defer func() { categoryRU = orig }()
	categoryRU = []byte("tampered")
	if _, err := WriteCategoryRU(t.TempDir()); !errors.Is(err, ErrHash) {
		t.Fatalf("tampered set written: %v", err)
	}
}
