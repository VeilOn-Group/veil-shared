// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package release

import (
	"errors"
	"slices"
	"strings"
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

func TestFormatOf(t *testing.T) {
	want := map[string]string{
		"linux-amd64-deb": "deb", "linux-arm64-deb": "deb", "linux-amd64-rpm": "rpm", "linux-arm64-rpm": "rpm", "windows-amd64": "msi", "windows-arm64": "msi",
		"darwin-universal": "pkg", "android": "apk", "linux-amd64": "tar", "linux-arm64": "tar",
	}
	for _, p := range Platforms {
		if _, ok := want[p]; !ok {
			t.Errorf("platform %q has no expected format in the test", p)
		}
	}
	for p, f := range want {
		if got := FormatOf(p); got != f {
			t.Errorf("FormatOf(%q) = %q, want %q", p, got, f)
		}
		if !slices.Contains(Formats, FormatOf(p)) {
			t.Errorf("format of %q not in Formats", p)
		}
	}
}

func TestValidateReportsEveryField(t *testing.T) {
	m := Metadata{Platform: "plan9", Channel: "nightly", Version: "x", URL: "ftp://h/x", SHA256: "AB", Size: 0,
		Notes: strings.Repeat("n", 4001), IssuedAt: 0}
	err := m.Validate()
	if !errors.Is(err, ErrInvalid) {
		t.Fatalf("want ErrInvalid, got %v", err)
	}
	for _, f := range []string{"platform", "channel", "version", "url (https)", "sha256", "size", "notes", "issued_at"} {
		if !strings.Contains(err.Error(), f) {
			t.Errorf("missing %q in %v", f, err)
		}
	}
	for _, u := range []string{"https://", "%zz"} {
		m := Metadata{Platform: "android", Channel: "beta", Version: "1.0.0", URL: u,
			SHA256: strings.Repeat("a", 64), Size: 1, IssuedAt: 1}
		if err := m.Validate(); err == nil || !strings.Contains(err.Error(), "url") {
			t.Errorf("URL %q accepted: %v", u, err)
		}
	}
	big := Metadata{Platform: "android", Channel: "beta", Version: "1.0.0", URL: "https://h/x",
		SHA256: strings.Repeat("a", 64), Size: 3 << 30, IssuedAt: 1}
	if err := big.Validate(); err == nil || !strings.Contains(err.Error(), "size") {
		t.Errorf("oversized artifact accepted: %v", err)
	}
}

func TestNewerWithInvalidVersions(t *testing.T) {
	if Newer("bad", "1.0.0") || Newer("1.0.0", "bad") {
		t.Fatal("invalid versions must never be newer")
	}
}
