// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Package mobile is the gomobile-bindable bridge for the Android client:
// the app reuses the SAME Go code as the desktop daemon for
// signature verification, profile validation and sing-box config
// generation, so both clients enforce identical rules (no-log config,
// UDP policy, IPv6 policy, split rules).
//
// Only gomobile-compatible types cross the boundary: string, int64, bool,
// []byte and error. Build: gomobile bind -target=android
// -javapkg=net.veilon.core ./mobile
package mobile

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/veilon/veil-shared/assets/rulesets"
	"github.com/veilon/veil-shared/pkg/apitypes"
	"github.com/veilon/veil-shared/pkg/profile"
	"github.com/veilon/veil-shared/pkg/release"
	"github.com/veilon/veil-shared/pkg/sign"
	"github.com/veilon/veil-shared/pkg/singbox"
	"github.com/veilon/veil-shared/pkg/xray"
)

// Errors surfaced to Kotlin (matched by message prefix).
var (
	ErrClientTooOld = errors.New("client_too_old")
	ErrBadInput     = errors.New("bad_input")
)

func rootKeys(csv string) ([]sign.PublicKey, error) {
	var out []sign.PublicKey
	for _, item := range strings.Split(csv, ",") {
		id, k, ok := strings.Cut(strings.TrimSpace(item), "=")
		if !ok {
			return nil, fmt.Errorf("%w: root key %q (want id=base64)", ErrBadInput, item)
		}
		raw, err := base64.StdEncoding.DecodeString(k)
		if err != nil {
			raw, err = base64.RawURLEncoding.DecodeString(k)
		}
		if err != nil || len(raw) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("%w: root key %q", ErrBadInput, id)
		}
		out = append(out, sign.PublicKey{ID: id, Purpose: sign.PurposeKeyset, Key: raw})
	}
	return out, nil
}

func unix(t int64) func() time.Time { return func() time.Time { return time.Unix(t, 0) } }

// verified returns the keyset and profile after full verification.
func verified(roots, keysetJSON, envJSON string, minKeysetVersion, now int64, clientVersion string) (*sign.Keyset, *profile.Profile, error) {
	rk, err := rootKeys(roots)
	if err != nil {
		return nil, nil, err
	}
	var ksEnv, env sign.Envelope
	if err := json.Unmarshal([]byte(keysetJSON), &ksEnv); err != nil {
		return nil, nil, fmt.Errorf("%w: keyset", ErrBadInput)
	}
	if err := json.Unmarshal([]byte(envJSON), &env); err != nil {
		return nil, nil, fmt.Errorf("%w: profile", ErrBadInput)
	}
	ks, err := sign.VerifyKeyset(sign.NewVerifier(rk, unix(now)), &ksEnv, minKeysetVersion)
	if err != nil {
		return nil, nil, err
	}
	var p profile.Profile
	if err := sign.VerifierFromKeyset(ks, unix(now)).VerifyInto(&env, sign.PurposeProfile, &p); err != nil {
		return nil, nil, err
	}
	if err := p.Validate(time.Unix(now, 0)); err != nil {
		return nil, nil, err
	}
	need, _ := profile.ParseSemver(p.MinClientVersion)
	have, err := profile.ParseSemver(clientVersion)
	if err != nil || have.Compare(need) < 0 {
		return nil, nil, ErrClientTooOld
	}
	return ks, &p, nil
}

// KeysetVersion returns the version of a root-verified keyset (the app
// stores it to refuse downgrades).
func KeysetVersion(roots, keysetJSON string, now int64) (int64, error) {
	rk, err := rootKeys(roots)
	if err != nil {
		return 0, err
	}
	var env sign.Envelope
	if err := json.Unmarshal([]byte(keysetJSON), &env); err != nil {
		return 0, fmt.Errorf("%w: keyset", ErrBadInput)
	}
	ks, err := sign.VerifyKeyset(sign.NewVerifier(rk, unix(now)), &env, 0)
	if err != nil {
		return 0, err
	}
	return ks.Version, nil
}

// Summary is the credential-free view for the UI.
type summary struct {
	Subscription profile.Subscription `json:"subscription"`
	Nodes        []nodeSummary        `json:"nodes"`
	ExpiresAt    int64                `json:"expires_at"`
}

type nodeSummary struct {
	ID         string   `json:"id"`
	Name       string   `json:"name"`
	Region     string   `json:"region"`
	Transports []string `json:"transports"`
}

// ProfileSummary verifies the profile and returns a JSON summary without
// any credentials (safe to keep in UI state).
func ProfileSummary(roots, keysetJSON, envJSON string, minKeysetVersion, now int64, clientVersion string) (string, error) {
	_, p, err := verified(roots, keysetJSON, envJSON, minKeysetVersion, now, clientVersion)
	if err != nil {
		return "", err
	}
	out := summary{Subscription: p.Subscription, ExpiresAt: p.ExpiresAt}
	for _, n := range p.Nodes {
		ns := nodeSummary{ID: n.ID, Name: n.Name, Region: n.Region}
		if v := n.Transports.XHTTP; v != nil && v.Enabled {
			ns.Transports = append(ns.Transports, "xhttp")
		}
		if v := n.Transports.VLESS; v != nil && v.Enabled {
			ns.Transports = append(ns.Transports, "vless")
		}
		if h := n.Transports.Hysteria2; h != nil && h.Enabled {
			ns.Transports = append(ns.Transports, "hysteria2")
		}
		if nv := n.Transports.Naive; nv != nil && nv.Enabled && nv.CertificatePEM == "" {
			ns.Transports = append(ns.Transports, "naive")
		}
		out.Nodes = append(out.Nodes, ns)
	}
	b, err := json.Marshal(out)
	return string(b), err
}

// buildOptions are the BuildConfig options (JSON from Kotlin). Unexported:
// gobind must not generate a Java class for it.
type buildOptions struct {
	NodeID         string              `json:"node_id"`
	Disabled       []string            `json:"disabled"`
	AllowLAN       bool                `json:"allow_lan"`
	ClashAPIListen string              `json:"clash_api_listen"`
	ClashAPISecret string              `json:"clash_api_secret"`
	CacheFilePath  string              `json:"cache_file_path"`
	SplitRules     []profile.RouteRule `json:"split_rules"`
	// BypassRU: Russian zones and services outside the VPN; absent = on.
	BypassRU *bool `json:"bypass_ru"`
	// FilesDir is the app's private files dir: the bundled rule set is
	// written there (BuildConfigs only).
	FilesDir string `json:"files_dir"`
	// DNS: DoH provider id (quad9 default, cloudflare, google, adguard,
	// opendns, custom) and the custom URL.
	DNSProvider  string `json:"dns_provider"`
	DNSCustomURL string `json:"dns_custom_url"`
}

// ListDNSPresets returns the DoH presets as JSON for the settings screen.
func ListDNSPresets() string {
	b, _ := json.Marshal(singbox.DoHPresets)
	return string(b)
}

// ValidateDNS checks a DNS choice before the app saves it; "" when valid,
// otherwise the reason.
func ValidateDNS(provider, customURL string) string {
	if err := (singbox.DNSChoice{Provider: provider, CustomURL: customURL}).Validate(); err != nil {
		return err.Error()
	}
	return ""
}

// BuildConfig verifies everything again (never trust cached state) and
// renders the sing-box config for libbox. The result passes the same no-log
// assertions as the desktop config. VLESS transports need the Xray process
// and are offered only by BuildConfigs.
func BuildConfig(roots, keysetJSON, envJSON, optionsJSON string, minKeysetVersion, now int64, clientVersion string) (string, error) {
	b, err := build(roots, keysetJSON, envJSON, optionsJSON, minKeysetVersion, now, clientVersion, false)
	if err != nil {
		return "", err
	}
	return b.SingBox, nil
}

// bundle is the BuildConfigs result.
type bundle struct {
	SingBox string `json:"singbox"`
	// Xray is the config of the Xray process for the VLESS transports;
	// empty when the node offers none. The app writes it to a
	// private file (0600) and runs the bundled xray binary with it.
	Xray string `json:"xray"`
}

// BuildConfigs is BuildConfig plus the Xray config; returns bundle JSON.
// Local SOCKS ports and passwords are new on every call.
func BuildConfigs(roots, keysetJSON, envJSON, optionsJSON string, minKeysetVersion, now int64, clientVersion string) (string, error) {
	b, err := build(roots, keysetJSON, envJSON, optionsJSON, minKeysetVersion, now, clientVersion, true)
	if err != nil {
		return "", err
	}
	out, err := json.Marshal(b)
	return string(out), err
}

func build(roots, keysetJSON, envJSON, optionsJSON string, minKeysetVersion, now int64, clientVersion string, withXray bool) (*bundle, error) {
	_, p, err := verified(roots, keysetJSON, envJSON, minKeysetVersion, now, clientVersion)
	if err != nil {
		return nil, err
	}
	var o buildOptions
	if err := json.Unmarshal([]byte(optionsJSON), &o); err != nil {
		return nil, fmt.Errorf("%w: options", ErrBadInput)
	}
	disabled := map[profile.TransportID]bool{}
	for _, d := range o.Disabled {
		disabled[profile.TransportID(d)] = true
	}
	opts := singbox.ClientOptions{
		NodeID: o.NodeID, TunStack: "gvisor",
		ClashAPIListen: o.ClashAPIListen, ClashAPISecret: o.ClashAPISecret,
		CacheFilePath: o.CacheFilePath, Disabled: disabled, AllowLAN: o.AllowLAN,
		UserRules: o.SplitRules,
		DNS:       &singbox.DNSChoice{Provider: o.DNSProvider, CustomURL: o.DNSCustomURL},
	}
	if o.BypassRU == nil || *o.BypassRU {
		opts.BypassSuffixes = singbox.RUZones
		if withXray && o.FilesDir != "" {
			// Without the file the zone suffixes still apply.
			if path, err := rulesets.WriteCategoryRU(o.FilesDir); err == nil {
				opts.BypassRuleSets = []singbox.RuleSetFile{{Tag: rulesets.CategoryRUTag, Path: path}}
			}
		}
	}
	out := &bundle{}
	if withXray {
		node := &p.Nodes[0]
		for i := range p.Nodes {
			if p.Nodes[i].ID == o.NodeID {
				node = &p.Nodes[i]
			}
		}
		plan, err := xray.PlanClient(node, xray.PlanOptions{Disabled: disabled})
		if err != nil {
			return nil, err
		}
		if plan != nil {
			doc, err := xray.BuildClient(plan.Spec)
			if err != nil {
				return nil, err
			}
			raw, err := json.Marshal(doc)
			if err != nil {
				return nil, err
			}
			out.Xray, opts.Xray = string(raw), plan.Endpoints
		}
	}
	cfg, err := singbox.BuildClient(p, opts)
	if err != nil {
		return nil, err
	}
	b, err := json.Marshal(cfg)
	if err != nil {
		return nil, err
	}
	out.SingBox = string(b)
	return out, nil
}

// NewDeviceKey returns a new Ed25519 private key (base64url seed). The app
// stores it in Android Keystore-wrapped EncryptedSharedPreferences.
func NewDeviceKey() (string, error) {
	seed := make([]byte, ed25519.SeedSize)
	if _, err := rand.Read(seed); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(seed), nil
}

// DeviceProof signs a server challenge; returns the apitypes.DeviceProof JSON.
func DeviceProof(seedB64, nonce string) (string, error) {
	seed, err := base64.RawURLEncoding.DecodeString(seedB64)
	if err != nil || len(seed) != ed25519.SeedSize {
		return "", fmt.Errorf("%w: device key", ErrBadInput)
	}
	k := ed25519.NewKeyFromSeed(seed)
	b, err := json.Marshal(apitypes.DeviceProof{
		DevicePublicKey: apitypes.EncodeKey(k.Public().(ed25519.PublicKey)),
		Nonce:           nonce,
		Signature:       apitypes.EncodeKey(ed25519.Sign(k, apitypes.DeviceAuthMessage(nonce))),
	})
	return string(b), err
}

// VerifyRelease checks signed release metadata; returns its JSON.
func VerifyRelease(roots, keysetJSON, releaseJSON string, now int64) (string, error) {
	rk, err := rootKeys(roots)
	if err != nil {
		return "", err
	}
	var ksEnv, env sign.Envelope
	if json.Unmarshal([]byte(keysetJSON), &ksEnv) != nil || json.Unmarshal([]byte(releaseJSON), &env) != nil {
		return "", ErrBadInput
	}
	ks, err := sign.VerifyKeyset(sign.NewVerifier(rk, unix(now)), &ksEnv, 0)
	if err != nil {
		return "", err
	}
	m, err := release.Verify(ks, &env, unix(now))
	if err != nil {
		return "", err
	}
	b, err := json.Marshal(m)
	return string(b), err
}
