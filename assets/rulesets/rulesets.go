// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Package rulesets embeds the sing-box rule sets shipped with the clients.
// Clients write them next to the core config at start-up; no
// rule set is ever downloaded at run time.
package rulesets

import (
	"crypto/sha256"
	_ "embed" // rule set data
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
)

// CategoryRUTag is the rule set tag used in client configs.
const CategoryRUTag = "geosite-category-ru"

// CategoryRUFile is the file name written by WriteCategoryRU.
const CategoryRUFile = "geosite-category-ru.srs"

//go:embed geosite-category-ru.srs
var categoryRU []byte

//go:embed geosite-category-ru.srs.sha256
var categoryRUSum string

// ErrHash means the embedded data does not match its pinned hash (a broken
// build); the client then runs with the zone suffixes only.
var ErrHash = errors.New("rulesets: embedded rule set does not match its pinned SHA-256")

// CategoryRU returns the embedded geosite-category-ru rule set after
// checking it against the pinned SHA-256.
func CategoryRU() ([]byte, error) {
	sum := sha256.Sum256(categoryRU)
	want, _, _ := strings.Cut(strings.TrimSpace(categoryRUSum), " ")
	if hex.EncodeToString(sum[:]) != want {
		return nil, ErrHash
	}
	return categoryRU, nil
}

// WriteCategoryRU writes the rule set into dir (0600, atomically) and
// returns its path.
func WriteCategoryRU(dir string) (string, error) {
	b, err := CategoryRU()
	if err != nil {
		return "", err
	}
	p := filepath.Join(dir, CategoryRUFile)
	tmp := p + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return "", err
	}
	if err := os.Rename(tmp, p); err != nil {
		_ = os.Remove(tmp)
		return "", err
	}
	return p, nil
}
