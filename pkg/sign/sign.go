// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Package sign implements signed envelopes (ADR-0005): the payload is
// canonicalized with JCS (RFC 8785) and signed with Ed25519. The same
// envelope format is used for profiles, keysets and release metadata, with
// distinct key purposes so a key for one purpose cannot sign another.
package sign

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/gowebpki/jcs"
)

const (
	CanonJCS   = "jcs-rfc8785"
	AlgEd25519 = "ed25519"
)

// Purpose binds a signature to a document type (domain separation).
type Purpose string

const (
	PurposeProfile Purpose = "veilon.profile.v1"
	PurposeKeyset  Purpose = "veilon.keyset.v1"
	PurposeRelease Purpose = "veilon.release.v1"
)

var (
	ErrUnknownKey      = errors.New("sign: unknown key id")
	ErrBadSignature    = errors.New("sign: signature verification failed")
	ErrUnsupported     = errors.New("sign: unsupported canonicalization or algorithm")
	ErrKeyExpired      = errors.New("sign: key not valid at this time")
	ErrPurposeMismatch = errors.New("sign: key purpose mismatch")
)

// Envelope is the wire format. Payload is the original JSON; the signature is
// computed over Purpose || 0x00 || JCS(payload).
type Envelope struct {
	Payload json.RawMessage `json:"payload"`
	Purpose Purpose         `json:"purpose"`
	Canon   string          `json:"canon"`
	SigAlg  string          `json:"sig_alg"`
	KeyID   string          `json:"key_id"`
	Sig     string          `json:"sig"` // base64url without padding
}

// Signer holds a private key. Construct from secret material loaded from
// env/secret manager only (see server config).
type Signer struct {
	KeyID   string
	Purpose Purpose
	priv    ed25519.PrivateKey
}

// NewSigner builds a signer from a 32-byte Ed25519 seed.
func NewSigner(keyID string, purpose Purpose, seed []byte) (*Signer, error) {
	if len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("sign: seed must be %d bytes", ed25519.SeedSize)
	}
	if keyID == "" {
		return nil, errors.New("sign: empty key id")
	}
	return &Signer{KeyID: keyID, Purpose: purpose, priv: ed25519.NewKeyFromSeed(seed)}, nil
}

// GenerateSeed returns a fresh random seed (for key generation tooling and tests).
func GenerateSeed() ([]byte, error) {
	seed := make([]byte, ed25519.SeedSize)
	_, err := rand.Read(seed)
	return seed, err
}

// PublicKey returns the verification key.
func (s *Signer) PublicKey() ed25519.PublicKey { return s.priv.Public().(ed25519.PublicKey) }

// Canonicalize returns JCS bytes of arbitrary JSON.
func Canonicalize(raw []byte) ([]byte, error) { return jcs.Transform(raw) }

func signingInput(p Purpose, canon []byte) []byte {
	out := make([]byte, 0, len(p)+1+len(canon))
	out = append(out, p...)
	out = append(out, 0)
	return append(out, canon...)
}

// Sign marshals v, canonicalizes and signs it.
func (s *Signer) Sign(v any) (*Envelope, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("sign: marshal: %w", err)
	}
	canon, err := Canonicalize(raw)
	if err != nil {
		return nil, fmt.Errorf("sign: canonicalize: %w", err)
	}
	sig := ed25519.Sign(s.priv, signingInput(s.Purpose, canon))
	return &Envelope{
		Payload: canon, Purpose: s.Purpose, Canon: CanonJCS, SigAlg: AlgEd25519,
		KeyID: s.KeyID, Sig: base64.RawURLEncoding.EncodeToString(sig),
	}, nil
}

// PublicKey is a verification key with validity window.
type PublicKey struct {
	ID        string            `json:"id"`
	Purpose   Purpose           `json:"purpose"`
	Key       ed25519.PublicKey `json:"key"` // base64 in JSON
	NotBefore int64             `json:"not_before"`
	NotAfter  int64             `json:"not_after"` // 0 = no expiry
}

// KeyFingerprint is a short, stable identifier for display/pinning.
func KeyFingerprint(k ed25519.PublicKey) string {
	h := sha256.Sum256(k)
	return base64.RawURLEncoding.EncodeToString(h[:12])
}

// Verifier verifies envelopes against a set of trusted keys.
type Verifier struct {
	keys map[string]PublicKey
	now  func() time.Time
}

// NewVerifier creates a verifier. now may be nil (time.Now).
func NewVerifier(keys []PublicKey, now func() time.Time) *Verifier {
	m := make(map[string]PublicKey, len(keys))
	for _, k := range keys {
		m[k.ID] = k
	}
	if now == nil {
		now = time.Now
	}
	return &Verifier{keys: m, now: now}
}

// Verify checks the envelope and returns the canonical payload bytes. Callers
// must unmarshal ONLY the returned bytes, never env.Payload directly.
func (v *Verifier) Verify(env *Envelope, want Purpose) ([]byte, error) {
	if env.Canon != CanonJCS || env.SigAlg != AlgEd25519 {
		return nil, ErrUnsupported
	}
	if env.Purpose != want {
		return nil, ErrPurposeMismatch
	}
	k, ok := v.keys[env.KeyID]
	if !ok {
		return nil, ErrUnknownKey
	}
	if k.Purpose != want {
		return nil, ErrPurposeMismatch
	}
	now := v.now().Unix()
	if now < k.NotBefore || (k.NotAfter != 0 && now > k.NotAfter) {
		return nil, ErrKeyExpired
	}
	sig, err := base64.RawURLEncoding.DecodeString(env.Sig)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return nil, ErrBadSignature
	}
	canon, err := Canonicalize(env.Payload)
	if err != nil {
		return nil, ErrBadSignature
	}
	if !ed25519.Verify(k.Key, signingInput(want, canon), sig) {
		return nil, ErrBadSignature
	}
	return canon, nil
}

// VerifyInto verifies and unmarshals the payload into out.
func (v *Verifier) VerifyInto(env *Envelope, want Purpose, out any) error {
	canon, err := v.Verify(env, want)
	if err != nil {
		return err
	}
	return json.Unmarshal(canon, out)
}
