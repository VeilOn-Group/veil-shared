// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Package apitypes holds the REST DTOs shared by veilon-api and its clients
// (veilond, Android, admin). Field names are the wire contract (OpenAPI:
// server/api/openapi.yaml).
package apitypes

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
)

// DeviceAuthDomain prefixes every device proof-of-possession signature.
const DeviceAuthDomain = "veilon-device-auth:v1:"

// DeviceAuthMessage is what the device key signs for a server nonce.
func DeviceAuthMessage(nonce string) []byte { return []byte(DeviceAuthDomain + nonce) }

// EncodeKey / DecodeKey use base64url without padding.
func EncodeKey(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// DecodePublicKey parses an Ed25519 public key.
func DecodePublicKey(s string) (ed25519.PublicKey, error) {
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil || len(b) != ed25519.PublicKeySize {
		return nil, errors.New("apitypes: invalid device public key")
	}
	return ed25519.PublicKey(b), nil
}

// VerifyDeviceSignature checks a proof-of-possession signature.
func VerifyDeviceSignature(pub ed25519.PublicKey, nonce, sigB64 string) bool {
	sig, err := base64.RawURLEncoding.DecodeString(sigB64)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return false
	}
	return ed25519.Verify(pub, DeviceAuthMessage(nonce), sig)
}

// ChallengeResponse carries a single-use nonce (TTL <= 120 s, Redis).
type ChallengeResponse struct {
	Nonce     string `json:"nonce"`
	ExpiresIn int    `json:"expires_in"`
}

// DeviceProof proves possession of the device key.
type DeviceProof struct {
	DevicePublicKey string `json:"device_public_key"`
	Nonce           string `json:"nonce"`
	Signature       string `json:"signature"`
}

// RegisterRequest creates an anonymous account (no email).
type RegisterRequest struct {
	DeviceProof
	DeviceLabel string `json:"device_label,omitempty"`
}

// LoginRequest logs in with an account number.
type LoginRequest struct {
	AccountNumber string `json:"account_number"`
	DeviceProof
	DeviceLabel string `json:"device_label,omitempty"`
}

// RefreshRequest rotates tokens; the device proves key possession again.
type RefreshRequest struct {
	RefreshToken string `json:"refresh_token"`
	DeviceProof
}

// TokenResponse is returned by register/login/refresh.
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int    `json:"expires_in"`
	// AccountNumber is returned ONLY by register, exactly once.
	AccountNumber string `json:"account_number,omitempty"`
}

// MeResponse describes the authenticated account (no PII by default).
type MeResponse struct {
	Status       string `json:"status"`
	HasEmail     bool   `json:"has_email"`
	Plan         string `json:"plan"`
	EndsOn       string `json:"ends_on"`
	DeviceLimit  int    `json:"device_limit"`
	DevicesInUse int    `json:"devices_in_use"`
}

// Error is the uniform error body.
type Error struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// Error codes.
const (
	CodeBadRequest     = "bad_request"
	CodeUnauthorized   = "unauthorized"
	CodeForbidden      = "forbidden"
	CodeNotFound       = "not_found"
	CodeRateLimited    = "rate_limited"
	CodeDeviceLimit    = "device_limit_reached"
	CodeInvalidProof   = "invalid_device_proof"
	CodeMFARequired    = "mfa_required"
	CodeLocked         = "temporarily_locked"
	CodeInternal       = "internal"
	CodeNoSubscription = "no_active_subscription"
	CodeNoLocations    = "no_locations"
	CodeConflict       = "conflict"
)

// StaffLoginRequest is step 1 of staff login.
type StaffLoginRequest struct {
	Login    string `json:"login"`
	Password string `json:"password"`
}

// StaffLoginResponse returns an MFA token for step 2.
type StaffLoginResponse struct {
	MFAToken  string `json:"mfa_token"`
	ExpiresIn int    `json:"expires_in"`
}

// StaffTOTPRequest is step 2.
type StaffTOTPRequest struct {
	MFAToken    string `json:"mfa_token"`
	Code        string `json:"code"`
	DeviceLabel string `json:"device_label,omitempty"`
}

// StaffTokenResponse returns staff session tokens.
type StaffTokenResponse struct {
	AccessToken  string   `json:"access_token"`
	RefreshToken string   `json:"refresh_token"`
	ExpiresIn    int      `json:"expires_in"`
	Role         string   `json:"role"`
	Permissions  []string `json:"permissions"`
}

// StaffMe describes the authenticated staff member.
type StaffMe struct {
	ID          string   `json:"id"`
	Login       string   `json:"login"`
	Role        string   `json:"role"`
	Permissions []string `json:"permissions"`
}

// AuditEvent is a staff audit row for the panel.
type AuditEvent struct {
	ID         int64  `json:"id"`
	StaffLogin string `json:"staff_login"`
	Action     string `json:"action"`
	TargetType string `json:"target_type"`
	TargetRef  string `json:"target_ref"`
	Comment    string `json:"comment"`
	CreatedAt  string `json:"created_at"`
}

// AuditPage is a page of audit events plus chain verification status.
type AuditPage struct {
	Events     []AuditEvent `json:"events"`
	ChainValid bool         `json:"chain_valid"`
}
