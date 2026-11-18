// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package sign

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"testing"
	"time"
)

func newTestSigner(t *testing.T, id string, p Purpose) *Signer {
	t.Helper()
	seed, err := GenerateSeed()
	if err != nil {
		t.Fatal(err)
	}
	s, err := NewSigner(id, p, seed)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func verifierFor(s *Signer, now time.Time) *Verifier {
	return NewVerifier([]PublicKey{{ID: s.KeyID, Purpose: s.Purpose, Key: s.PublicKey()}}, func() time.Time { return now })
}

type doc struct {
	B string `json:"b"`
	A int    `json:"a"`
}

func TestRoundTrip(t *testing.T) {
	s := newTestSigner(t, "k1", PurposeProfile)
	env, err := s.Sign(doc{B: "x", A: 1})
	if err != nil {
		t.Fatal(err)
	}
	var out doc
	if err := verifierFor(s, time.Now()).VerifyInto(env, PurposeProfile, &out); err != nil {
		t.Fatal(err)
	}
	if out.A != 1 || out.B != "x" {
		t.Fatalf("payload mismatch: %+v", out)
	}
}

func TestKeyOrderIndependent(t *testing.T) {
	s := newTestSigner(t, "k1", PurposeProfile)
	env, _ := s.Sign(doc{B: "x", A: 1})
	env.Payload = json.RawMessage(`{ "b": "x",  "a": 1 }`) // reordered + whitespace
	if _, err := verifierFor(s, time.Now()).Verify(env, PurposeProfile); err != nil {
		t.Fatalf("JCS must make key order irrelevant: %v", err)
	}
}

func TestRejects(t *testing.T) {
	s := newTestSigner(t, "k1", PurposeProfile)
	other := newTestSigner(t, "k1", PurposeProfile) // same id, different key
	now := time.Now()
	cases := map[string]struct {
		mut  func(*Envelope)
		v    *Verifier
		want Purpose
		err  error
	}{
		"tampered payload": {func(e *Envelope) { e.Payload = json.RawMessage(`{"a":2,"b":"x"}`) }, verifierFor(s, now), PurposeProfile, ErrBadSignature},
		"wrong key":        {func(e *Envelope) {}, verifierFor(other, now), PurposeProfile, ErrBadSignature},
		"unknown key id":   {func(e *Envelope) { e.KeyID = "nope" }, verifierFor(s, now), PurposeProfile, ErrUnknownKey},
		"purpose swap":     {func(e *Envelope) {}, verifierFor(s, now), PurposeRelease, ErrPurposeMismatch},
		"bad canon":        {func(e *Envelope) { e.Canon = "protobuf" }, verifierFor(s, now), PurposeProfile, ErrUnsupported},
		"garbage sig":      {func(e *Envelope) { e.Sig = "!!" }, verifierFor(s, now), PurposeProfile, ErrBadSignature},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			env, _ := s.Sign(doc{B: "x", A: 1})
			tc.mut(env)
			if _, err := tc.v.Verify(env, tc.want); !errors.Is(err, tc.err) {
				t.Fatalf("want %v, got %v", tc.err, err)
			}
		})
	}
}

func TestKeyValidityWindow(t *testing.T) {
	s := newTestSigner(t, "k1", PurposeProfile)
	env, _ := s.Sign(doc{A: 1})
	now := time.Unix(2_000_000_000, 0)
	v := NewVerifier([]PublicKey{{ID: "k1", Purpose: PurposeProfile, Key: s.PublicKey(), NotAfter: now.Unix() - 1}}, func() time.Time { return now })
	if _, err := v.Verify(env, PurposeProfile); !errors.Is(err, ErrKeyExpired) {
		t.Fatalf("want expired, got %v", err)
	}
}

func TestKeysetRotationAndDowngrade(t *testing.T) {
	root := newTestSigner(t, "root-1", PurposeKeyset)
	next := newTestSigner(t, "prof-2", PurposeProfile)
	ksEnv, err := root.Sign(Keyset{Version: 7, Keys: []PublicKey{{ID: next.KeyID, Purpose: PurposeProfile, Key: next.PublicKey()}}})
	if err != nil {
		t.Fatal(err)
	}
	rv := verifierFor(root, time.Now())
	ks, err := VerifyKeyset(rv, ksEnv, 7)
	if err != nil {
		t.Fatal(err)
	}
	profEnv, _ := next.Sign(doc{A: 3})
	if _, err := VerifierFromKeyset(ks, nil).Verify(profEnv, PurposeProfile); err != nil {
		t.Fatalf("rotated key must verify: %v", err)
	}
	if _, err := VerifyKeyset(rv, ksEnv, 8); !errors.Is(err, ErrKeysetDowngrade) {
		t.Fatalf("want downgrade error, got %v", err)
	}
	bad, _ := root.Sign(Keyset{Version: 9, Keys: []PublicKey{{ID: "r2", Purpose: PurposeKeyset, Key: next.PublicKey()}}})
	if _, err := VerifyKeyset(rv, bad, 0); err == nil {
		t.Fatal("keyset must not introduce root keys")
	}
}

// TestJCSVectors runs the shared cross-language vectors (Go/Kotlin/TS read the
// same file, ADR-0005).
func TestJCSVectors(t *testing.T) {
	raw, err := os.ReadFile("testdata/jcs-vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var vectors []struct {
		Name   string `json:"name"`
		Input  string `json:"input_raw"`
		Output string `json:"output"`
	}
	if err := json.Unmarshal(raw, &vectors); err != nil {
		t.Fatal(err)
	}
	for _, v := range vectors {
		got, err := Canonicalize([]byte(v.Input))
		if err != nil {
			t.Fatalf("%s: %v", v.Name, err)
		}
		if !bytes.Equal(got, []byte(v.Output)) {
			t.Errorf("%s:\n got %s\nwant %s", v.Name, got, v.Output)
		}
	}
}
