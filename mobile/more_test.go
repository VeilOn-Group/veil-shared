// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package mobile

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/veilon/veil-shared/pkg/profile"
	"github.com/veilon/veil-shared/pkg/release"
	"github.com/veilon/veil-shared/pkg/sign"
)

func TestRootKeysParsing(t *testing.T) {
	seed, _ := sign.GenerateSeed()
	s, _ := sign.NewSigner("r", sign.PurposeKeyset, seed)
	urlKey := base64.RawURLEncoding.EncodeToString(s.PublicKey())
	keys, err := rootKeys("a=" + urlKey + ", b=" + base64.StdEncoding.EncodeToString(s.PublicKey()))
	if err != nil || len(keys) != 2 || keys[1].ID != "b" {
		t.Fatalf("%v %v", keys, err)
	}
	for _, bad := range []string{"no-equals", "a=!!!", "a=" + base64.StdEncoding.EncodeToString([]byte("short"))} {
		if _, err := rootKeys(bad); !errors.Is(err, ErrBadInput) {
			t.Errorf("%q: %v", bad, err)
		}
	}
}

func TestVerifiedErrors(t *testing.T) {
	_, prof, roots, ks := signers(t)
	p := profile.Fixture()
	env, _ := prof.Sign(p)
	envJSON, _ := json.Marshal(env)
	now := p.IssuedAt + 60
	cases := map[string]struct {
		roots, ks, env string
		min, now       int64
		ver            string
		want           error
	}{
		"bad roots":   {"x", ks, string(envJSON), 0, now, "1.0.0", ErrBadInput},
		"bad keyset":  {roots, "{", string(envJSON), 0, now, "1.0.0", ErrBadInput},
		"bad profile": {roots, ks, "{", 0, now, "1.0.0", ErrBadInput},
		"downgrade":   {roots, ks, string(envJSON), 99, now, "1.0.0", sign.ErrKeysetDowngrade},
		"too old":     {roots, ks, string(envJSON), 0, now, "0.0.1", ErrClientTooOld},
		"bad version": {roots, ks, string(envJSON), 0, now, "x", ErrClientTooOld},
	}
	for name, c := range cases {
		if _, err := ProfileSummary(c.roots, c.ks, c.env, c.min, c.now, c.ver); !errors.Is(err, c.want) {
			t.Errorf("%s: want %v, got %v", name, c.want, err)
		}
	}
	if _, err := ProfileSummary(roots, ks, string(envJSON), 0, p.ExpiresAt+1, "1.0.0"); err == nil {
		t.Fatal("expired profile accepted")
	}
	// Signed by the root key instead of a profile key.
	other, _ := json.Marshal(&sign.Envelope{Payload: env.Payload, Purpose: sign.PurposeProfile, Canon: env.Canon, SigAlg: env.SigAlg, KeyID: "nope", Sig: env.Sig})
	if _, err := ProfileSummary(roots, ks, string(other), 0, now, "1.0.0"); !errors.Is(err, sign.ErrUnknownKey) {
		t.Fatalf("unknown key: %v", err)
	}
}

func TestKeysetVersionErrors(t *testing.T) {
	_, _, roots, ks := signers(t)
	if v, err := KeysetVersion(roots, ks, time.Now().Unix()); err != nil || v != 3 {
		t.Fatalf("%d %v", v, err)
	}
	if _, err := KeysetVersion("x", ks, 0); !errors.Is(err, ErrBadInput) {
		t.Fatal(err)
	}
	if _, err := KeysetVersion(roots, "{", 0); !errors.Is(err, ErrBadInput) {
		t.Fatal(err)
	}
	var env sign.Envelope
	_ = json.Unmarshal([]byte(ks), &env)
	env.Sig = "AAAA"
	bad, _ := json.Marshal(env)
	if _, err := KeysetVersion(roots, string(bad), time.Now().Unix()); err == nil {
		t.Fatal("tampered keyset accepted")
	}
}

func TestBuildConfigsOptionsAndNodes(t *testing.T) {
	_, prof, roots, ks := signers(t)
	p := profile.Fixture()
	env, _ := prof.Sign(p)
	envJSON, _ := json.Marshal(env)
	now := p.IssuedAt + 60
	if _, err := BuildConfigs(roots, ks, string(envJSON), "{", 0, now, "1.0.0"); !errors.Is(err, ErrBadInput) {
		t.Fatalf("bad options: %v", err)
	}
	if _, err := BuildConfigs("x", ks, string(envJSON), "{}", 0, now, "1.0.0"); !errors.Is(err, ErrBadInput) {
		t.Fatalf("bad roots: %v", err)
	}
	// The selected node's Xray transports are planned; the rule set file is
	// written into files_dir.
	dir := t.TempDir()
	opts := `{"node_id":"` + p.Nodes[len(p.Nodes)-1].ID + `","clash_api_listen":"127.0.0.1:9090","clash_api_secret":"s","files_dir":"` + dir + `"}`
	out, err := BuildConfigs(roots, ks, string(envJSON), opts, 0, now, "1.0.0")
	if err != nil {
		t.Fatal(err)
	}
	var b bundle
	if err := json.Unmarshal([]byte(out), &b); err != nil || b.SingBox == "" {
		t.Fatalf("bundle: %v", err)
	}
	if !strings.Contains(b.SingBox, filepath.Join(dir, "geosite-category-ru.srs")) {
		t.Fatal("rule set not referenced")
	}
	// Disabling every Xray transport leaves no Xray config.
	opts = `{"clash_api_listen":"127.0.0.1:9090","clash_api_secret":"s","disabled":["xhttp","vless"],"bypass_ru":false}`
	out, err = BuildConfigs(roots, ks, string(envJSON), opts, 0, now, "1.0.0")
	if err != nil {
		t.Fatal(err)
	}
	_ = json.Unmarshal([]byte(out), &b)
	if b.Xray != "" {
		t.Fatal("xray config without xray transports")
	}
	// A bad DNS choice fails the sing-box build.
	if _, err := BuildConfigs(roots, ks, string(envJSON), `{"dns_provider":"nope"}`, 0, now, "1.0.0"); err == nil {
		t.Fatal("unknown DNS provider accepted")
	}
}

func TestDeviceKeyAndProofErrors(t *testing.T) {
	k, err := NewDeviceKey()
	if err != nil || len(k) != 43 {
		t.Fatalf("%q %v", k, err)
	}
	if _, err := DeviceProof("!!", "n"); !errors.Is(err, ErrBadInput) {
		t.Fatal(err)
	}
	if _, err := DeviceProof(base64.RawURLEncoding.EncodeToString([]byte("short")), "n"); !errors.Is(err, ErrBadInput) {
		t.Fatal(err)
	}
}

func TestVerifyRelease(t *testing.T) {
	root, _, roots, _ := signers(t)
	seed, _ := sign.GenerateSeed()
	rel, _ := sign.NewSigner("rel-1", sign.PurposeRelease, seed)
	ksEnv, _ := root.Sign(sign.Keyset{Version: 4, Keys: []sign.PublicKey{{ID: "rel-1", Purpose: sign.PurposeRelease, Key: rel.PublicKey()}}})
	ksJSON, _ := json.Marshal(ksEnv)
	now := time.Now().Unix()
	m := release.Metadata{Platform: "android", Channel: "stable", Version: "1.2.3", URL: "https://dl.example.net/a.apk",
		SHA256: strings.Repeat("ab", 32), Size: 10, IssuedAt: now}
	env, _ := rel.Sign(m)
	envJSON, _ := json.Marshal(env)
	out, err := VerifyRelease(roots, string(ksJSON), string(envJSON), now)
	if err != nil || !strings.Contains(out, `"version":"1.2.3"`) {
		t.Fatalf("%s %v", out, err)
	}
	if _, err := VerifyRelease("x", string(ksJSON), string(envJSON), now); !errors.Is(err, ErrBadInput) {
		t.Fatal(err)
	}
	if _, err := VerifyRelease(roots, "{", string(envJSON), now); !errors.Is(err, ErrBadInput) {
		t.Fatal(err)
	}
	if _, err := VerifyRelease(roots, string(ksJSON), "{", now); !errors.Is(err, ErrBadInput) {
		t.Fatal(err)
	}
	var bad sign.Envelope
	_ = json.Unmarshal(ksJSON, &bad)
	bad.Sig = "AAAA"
	badJSON, _ := json.Marshal(bad)
	if _, err := VerifyRelease(roots, string(badJSON), string(envJSON), now); err == nil {
		t.Fatal("tampered keyset accepted")
	}
	m.URL = "http://dl.example.net/a.apk"
	env2, _ := rel.Sign(m)
	env2JSON, _ := json.Marshal(env2)
	if _, err := VerifyRelease(roots, string(ksJSON), string(env2JSON), now); err == nil {
		t.Fatal("plain HTTP release accepted")
	}
}

func TestCrashHelpers(t *testing.T) {
	if CrashTitle("x\npanic: boom\n") != "panic: boom" {
		t.Fatal(CrashTitle("x\npanic: boom\n"))
	}
	if _, err := InstallCrashOutput(filepath.Join(t.TempDir(), "missing", "crash.txt")); err == nil {
		t.Fatal("unwritable path accepted")
	}
}
