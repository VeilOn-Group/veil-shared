// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package apitypes

import (
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"testing"
)

func TestDeviceSignatureRoundTrip(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if got := string(DeviceAuthMessage("n1")); got != DeviceAuthDomain+"n1" {
		t.Fatalf("message %q", got)
	}
	enc := EncodeKey(pub)
	if strings.ContainsAny(enc, "=+/") {
		t.Fatalf("not raw url base64: %q", enc)
	}
	dec, err := DecodePublicKey(enc)
	if err != nil || !dec.Equal(pub) {
		t.Fatalf("decode: %v", err)
	}
	sig := EncodeKey(ed25519.Sign(priv, DeviceAuthMessage("nonce")))
	if !VerifyDeviceSignature(pub, "nonce", sig) {
		t.Fatal("valid signature rejected")
	}
	if VerifyDeviceSignature(pub, "other", sig) {
		t.Fatal("signature over another nonce accepted")
	}
	// A signature without the domain prefix must not verify.
	raw := EncodeKey(ed25519.Sign(priv, []byte("nonce")))
	if VerifyDeviceSignature(pub, "nonce", raw) {
		t.Fatal("undomained signature accepted")
	}
	for _, bad := range []string{"!!", EncodeKey([]byte("short"))} {
		if VerifyDeviceSignature(pub, "nonce", bad) {
			t.Fatalf("malformed signature %q accepted", bad)
		}
	}
}

func TestDecodePublicKeyRejects(t *testing.T) {
	for _, s := range []string{"", "***", EncodeKey(make([]byte, 31)), EncodeKey(make([]byte, 33))} {
		if _, err := DecodePublicKey(s); err == nil {
			t.Errorf("%q accepted", s)
		}
	}
}
