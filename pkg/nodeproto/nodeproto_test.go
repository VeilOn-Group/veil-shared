// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package nodeproto

import (
	"slices"
	"testing"
)

func TestShortIDs(t *testing.T) {
	if got := (NodeParams{RealityShortID: "aa"}).ShortIDs(); !slices.Equal(got, []string{"aa"}) {
		t.Fatalf("single: %v", got)
	}
	p := NodeParams{RealityShortID: "aa", RealityShortIDs: []string{"bb", "aa"}}
	if got := p.ShortIDs(); !slices.Equal(got, []string{"bb", "aa"}) {
		t.Fatalf("list wins: %v", got)
	}
}

func TestHas(t *testing.T) {
	p := NodeParams{Transports: []string{"xhttp", "hysteria2"}}
	if !p.Has("xhttp") || !p.Has("hysteria2") || p.Has("naive") {
		t.Fatalf("Has wrong for %v", p.Transports)
	}
	if (NodeParams{}).Has("xhttp") {
		t.Fatal("empty node offers nothing")
	}
}
