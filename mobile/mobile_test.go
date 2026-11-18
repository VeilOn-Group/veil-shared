// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package mobile

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/veilon/veil-shared/pkg/apitypes"
	"github.com/veilon/veil-shared/pkg/profile"
	"github.com/veilon/veil-shared/pkg/sign"
	"github.com/veilon/veil-shared/pkg/singbox"
)

func signers(t *testing.T) (*sign.Signer, *sign.Signer, string, string) {
	mk := func(id string, p sign.Purpose) *sign.Signer {
		seed, _ := sign.GenerateSeed()
		s, err := sign.NewSigner(id, p, seed)
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	root, prof := mk("root-1", sign.PurposeKeyset), mk("prof-1", sign.PurposeProfile)
	ks, _ := root.Sign(sign.Keyset{Version: 3, Keys: []sign.PublicKey{{ID: "prof-1", Purpose: sign.PurposeProfile, Key: prof.PublicKey()}}})
	ksJSON, _ := json.Marshal(ks)
	return root, prof, "root-1=" + base64.StdEncoding.EncodeToString(root.PublicKey()), string(ksJSON)
}

func TestBuildAndSummary(t *testing.T) {
	_, prof, roots, ks := signers(t)
	p := profile.Fixture()
	env, _ := prof.Sign(p)
	envJSON, _ := json.Marshal(env)
	now := p.IssuedAt + 60
	sum, err := ProfileSummary(roots, ks, string(envJSON), 0, now, "0.1.0")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(sum, p.Nodes[0].Transports.VLESS.UUID) || strings.Contains(sum, "password") {
		t.Fatalf("summary leaks credentials: %s", sum)
	}
	opts := `{"node_id":"","clash_api_listen":"127.0.0.1:9090","clash_api_secret":"s3cr3t","split_rules":[{"package_name":["org.example.bank"],"action":"direct"}]}`
	cfgJSON, err := BuildConfig(roots, ks, string(envJSON), opts, 0, now, "0.1.0")
	if err != nil {
		t.Fatal(err)
	}
	var cfg singbox.Config
	_ = json.Unmarshal([]byte(cfgJSON), &cfg)
	if err := singbox.AssertClientNoLog(&cfg); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(cfgJSON, `"package_name":["org.example.bank"]`) {
		t.Fatal("per-app rule missing")
	}
	if !strings.Contains(cfgJSON, `"domain_suffix":["ru","su","xn--p1ai"`) {
		t.Fatal("Russian zones bypass (.ru .su .рф ...) must be on by default")
	}
	off := strings.Replace(opts, `"node_id":""`, `"node_id":"","bypass_ru":false`, 1)
	if c, err := BuildConfig(roots, ks, string(envJSON), off, 0, now, "0.1.0"); err != nil || strings.Contains(c, `"ru","su"`) {
		t.Fatalf("bypass_ru=false ignored: %v", err)
	}
	if _, err := KeysetVersion(roots, ks, now); err != nil {
		t.Fatal(err)
	}
	if _, err := BuildConfig(roots, ks, string(envJSON), opts, 4, now, "0.1.0"); err == nil {
		t.Fatal("keyset downgrade accepted")
	}
	if _, err := BuildConfig(roots, ks, string(envJSON), opts, 0, now, "0.0.1"); !errors.Is(err, ErrClientTooOld) {
		t.Fatalf("old client: %v", err)
	}
	// Tampered profile.
	var e2 sign.Envelope
	_ = json.Unmarshal(envJSON, &e2)
	e2.Payload = []byte(strings.Replace(string(e2.Payload), "203.0.113.10", "198.51.100.66", 1))
	bad, _ := json.Marshal(e2)
	if _, err := BuildConfig(roots, ks, string(bad), opts, 0, now, "0.1.0"); err == nil {
		t.Fatal("tampered profile accepted")
	}
}

func TestDeviceProof(t *testing.T) {
	k, _ := NewDeviceKey()
	js, err := DeviceProof(k, "nonce-123")
	if err != nil {
		t.Fatal(err)
	}
	var p apitypes.DeviceProof
	_ = json.Unmarshal([]byte(js), &p)
	if p.Nonce != "nonce-123" || p.Signature == "" {
		t.Fatalf("%+v", p)
	}
}

func TestBuildConfigsXray(t *testing.T) {
	_, prof, roots, ks := signers(t)
	p := profile.Fixture()
	env, _ := prof.Sign(p)
	envJSON, _ := json.Marshal(env)
	now := p.IssuedAt + 60
	dir := t.TempDir()
	opts := `{"node_id":"","clash_api_listen":"127.0.0.1:9090","clash_api_secret":"s3cr3t","files_dir":"` + dir + `"}`
	out, err := BuildConfigs(roots, ks, string(envJSON), opts, 0, now, "0.1.0")
	if err != nil {
		t.Fatal(err)
	}
	var b bundle
	if err := json.Unmarshal([]byte(out), &b); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(b.Xray, `"network":"xhttp"`) || !strings.Contains(b.Xray, `"loglevel":"none"`) {
		t.Fatalf("xray config: %s", b.Xray)
	}
	var cfg singbox.Config
	_ = json.Unmarshal([]byte(b.SingBox), &cfg)
	var xh *singbox.Outbound
	for i := range cfg.Outbounds {
		if cfg.Outbounds[i].Tag == singbox.TagXHTTP {
			xh = &cfg.Outbounds[i]
		}
	}
	if xh == nil || xh.Type != "socks" || !strings.Contains(b.Xray, xh.Password) {
		t.Fatal("sing-box must reach the Xray SOCKS inbound with its per-start password")
	}
	if !strings.Contains(b.SingBox, `"rule_set":["geosite-category-ru"]`) || !strings.Contains(b.SingBox, dir) {
		t.Fatal("bundled category-ru rule set not used")
	}
	// DNS: Quad9 by default, the chosen provider otherwise, invalid refused.
	if !strings.Contains(b.SingBox, `"server_name":"dns.quad9.net"`) {
		t.Fatal("Quad9 is not the default resolver")
	}
	ag := strings.Replace(opts, `"node_id":""`, `"node_id":"","dns_provider":"adguard"`, 1)
	if c, _ := BuildConfig(roots, ks, string(envJSON), ag, 0, now, "0.1.0"); !strings.Contains(c, `"server":"94.140.14.14"`) {
		t.Fatal("AdGuard choice ignored")
	}
	bad := strings.Replace(opts, `"node_id":""`, `"node_id":"","dns_provider":"custom","dns_custom_url":"http://x.example/q"`, 1)
	if _, err := BuildConfig(roots, ks, string(envJSON), bad, 0, now, "0.1.0"); err == nil {
		t.Fatal("plain-http DoH accepted")
	}
	if ValidateDNS("custom", "https://doh.example.net/dns-query") != "" || ValidateDNS("custom", "https://10.0.0.1/q") == "" {
		t.Fatal("ValidateDNS")
	}
	if !strings.Contains(ListDNSPresets(), "dns.adguard-dns.com") {
		t.Fatal("presets")
	}
	// Plain BuildConfig (no Xray) does not offer VLESS transports.
	c, _ := BuildConfig(roots, ks, string(envJSON), opts, 0, now, "0.1.0")
	if strings.Contains(c, `"tag":"xhttp"`) || strings.Contains(c, `"tag":"vless"`) {
		t.Fatal("VLESS without Xray offered")
	}
	// Disabling both VLESS transports: no Xray process.
	off := strings.Replace(opts, `"node_id":""`, `"node_id":"","disabled":["xhttp","vless"]`, 1)
	out, _ = BuildConfigs(roots, ks, string(envJSON), off, 0, now, "0.1.0")
	_ = json.Unmarshal([]byte(out), &b)
	if b.Xray != "" {
		t.Fatal("xray config without VLESS transports")
	}
}

func TestCrashBridge(t *testing.T) {
	dir := t.TempDir()
	p := dir + "/go-crash.txt"
	if err := os.WriteFile(p, []byte("panic: boom near 203.0.113.5\n\ngoroutine 1 [running]:\nmain.main()\n\t/home/u/x/main.go:5 +0x1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	prev, err := InstallCrashOutput(p)
	if err != nil || !strings.Contains(prev, "panic: boom") {
		t.Fatalf("%q %v", prev, err)
	}
	if b, _ := os.ReadFile(p); len(b) != 0 {
		t.Fatal("crash file must be truncated after reading")
	}
	js, err := NewCrashReport("panic", "0.8.0", "arm64", prev, time.Now().Unix())
	if err != nil {
		t.Fatal(err)
	}
	var r apitypes.CrashReport
	if err := json.Unmarshal([]byte(js), &r); err != nil {
		t.Fatal(err)
	}
	if r.OS != "android" || r.Component != "android" || strings.Contains(r.Text, "203.0.113.5") || strings.Contains(r.Text, "/home/u") {
		t.Fatalf("%+v", r)
	}
	if _, err := NewCrashReport("panic", "0.8.0", "mips", prev, time.Now().Unix()); err == nil {
		t.Fatal("bad arch accepted")
	}
}
