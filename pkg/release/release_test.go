// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package release

import (
	"testing"
	"time"

	"github.com/veilon/veil-shared/pkg/sign"
)

func signer(t *testing.T, p sign.Purpose) *sign.Signer {
	seed, _ := sign.GenerateSeed()
	s, err := sign.NewSigner("k-"+string(p), p, seed)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestVerify(t *testing.T) {
	rel := signer(t, sign.PurposeRelease)
	prof := signer(t, sign.PurposeProfile)
	now := time.Now()
	ks := &sign.Keyset{Version: 1, Keys: []sign.PublicKey{
		{ID: rel.KeyID, Purpose: sign.PurposeRelease, Key: rel.PublicKey()},
		{ID: prof.KeyID, Purpose: sign.PurposeProfile, Key: prof.PublicKey()},
	}}
	m := Metadata{Platform: "linux-amd64", Channel: "stable", Version: "0.2.0", URL: "https://dl.veilon.example/veilon-0.2.0.tar.gz",
		SHA256: "aa00aa00aa00aa00aa00aa00aa00aa00aa00aa00aa00aa00aa00aa00aa00aa00", Size: 123, IssuedAt: now.Unix()}
	env, err := rel.Sign(m)
	if err != nil {
		t.Fatal(err)
	}
	got, err := Verify(ks, env, func() time.Time { return now })
	if err != nil || got.Version != "0.2.0" {
		t.Fatalf("verify: %v", err)
	}
	// A profile key must not be able to sign releases (domain separation).
	forged, _ := prof.Sign(m)
	if _, err := Verify(ks, forged, func() time.Time { return now }); err == nil {
		t.Fatal("release signed with a profile key accepted")
	}
	bad := m
	bad.URL = "http://dl.veilon.example/x"
	envBad, _ := rel.Sign(bad)
	if _, err := Verify(ks, envBad, func() time.Time { return now }); err == nil {
		t.Fatal("plain-HTTP download URL accepted")
	}
	if !Newer("0.1.9", "0.2.0") || Newer("0.2.0", "0.2.0") || Newer("1.0.0", "0.9.9") {
		t.Fatal("Newer")
	}
}
