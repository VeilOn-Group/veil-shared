// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package singbox

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/veilon/veil-shared/pkg/profile"
	"github.com/veilon/veil-shared/pkg/tmpl"
)

func nodeSpec() NodeSpec {
	return NodeSpec{
		Domain: "node1.example.net", Listen: "::", UDPPort: 443, NaivePort: 8444,
		CertPath: "/run/veilon-node/tls/fullchain.pem", KeyPath: "/run/veilon-node/tls/privkey.pem",
		Hy2ObfsPassword: "golden-obfs-not-real", Hy2UpMbps: 1000, Hy2DownMbps: 1000,
		StatsListen: "127.0.0.1:10085", BlockPorts: []uint16{25, 465, 587},
	}
}

func nodeUsers() []NodeUser {
	return []NodeUser{
		{Pseudonym: "u_bbbb", VLESSUUID: "11111111-2222-4333-8444-555555555555", Hy2Password: "u_bbbb:hy2-golden", NaivePassword: "naive-golden-b"},
		{Pseudonym: "u_aaaa", VLESSUUID: "8c7c3b1e-5d1a-4a4e-9a65-2f0f7a8b9c01", Hy2Password: "u_aaaa:hy2-golden", NaivePassword: "naive-golden-a"},
	}
}

// selfSigned writes a throwaway certificate for `sing-box check`.
func selfSigned(t *testing.T, dir string) (string, string) {
	t.Helper()
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "node1.example.net"},
		DNSNames: []string{"node1.example.net"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, _ := x509.CreateCertificate(rand.Reader, tpl, tpl, &k.PublicKey, k)
	kd, _ := x509.MarshalECPrivateKey(k)
	cp, kp := filepath.Join(dir, "c.pem"), filepath.Join(dir, "k.pem")
	_ = os.WriteFile(cp, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600)
	_ = os.WriteFile(kp, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kd}), 0o600)
	return cp, kp
}

// tunedSpec exercises every operator option of the transport editor
// (ADR-0062) that sing-box still serves.
func tunedSpec() NodeSpec {
	s := nodeSpec()
	s.Hy2NoObfs = true
	s.Hy2IgnoreClientBandwidth = true
	s.Hy2Masquerade = "https://www.example.net/"
	s.AllowCIDRs = []string{"10.200.0.0/24"}
	return s
}

func TestGoldenServerConfig(t *testing.T) {
	for name, spec := range map[string]NodeSpec{"server_node.json": nodeSpec(), "server_node_tuned.json": tunedSpec()} {
		t.Run(name, func(t *testing.T) { goldenServer(t, name, spec) })
	}
}

func goldenServer(t *testing.T, name string, spec NodeSpec) {
	doc, err := BuildServer(nil, spec, nodeUsers())
	if err != nil {
		t.Fatal(err)
	}
	got, err := tmpl.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join("testdata", "golden", name)
	if *update {
		_ = os.WriteFile(path, got, 0o644)
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("missing golden (run with -update): %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("golden mismatch for %s", path)
	}
	checkServer(t, doc)
}

// checkServer validates a node config with the pinned sing-box binaries.
// The official build lacks v2ray_api (ADR-0043), so stats are validated
// separately with SINGBOX_NODE_BIN.
func checkServer(t *testing.T, doc tmpl.Doc) {
	t.Helper()
	for _, bin := range []struct {
		env        string
		stripStats bool
	}{{"SINGBOX_BIN", true}, {"SINGBOX_NODE_BIN", false}} {
		sb := os.Getenv(bin.env)
		if sb == "" {
			t.Logf("%s not set: server config not validated by that binary", bin.env)
			continue
		}
		dir := t.TempDir()
		cp, kp := selfSigned(t, dir)
		raw, _ := tmpl.Marshal(doc)
		raw = bytes.ReplaceAll(raw, []byte("/run/veilon-node/tls/fullchain.pem"), []byte(cp))
		raw = bytes.ReplaceAll(raw, []byte("/run/veilon-node/tls/privkey.pem"), []byte(kp))
		if bin.stripStats {
			var m map[string]any
			_ = json.Unmarshal(raw, &m)
			delete(m, "experimental")
			raw, _ = json.Marshal(m)
		}
		p := filepath.Join(dir, "node.json")
		_ = os.WriteFile(p, raw, 0o600)
		if out, err := exec.Command(sb, "check", "-c", p).CombinedOutput(); err != nil {
			t.Fatalf("%s check: %v\n%s", bin.env, err, out)
		}
	}
}

func TestServerSpecRejects(t *testing.T) {
	for name, mut := range map[string]func(*NodeSpec){
		"no domain":      func(s *NodeSpec) { s.Domain = "" },
		"public stats":   func(s *NodeSpec) { s.StatsListen = "0.0.0.0:10085" },
		"no naive port":  func(s *NodeSpec) { s.NaivePort = 0 },
		"no obfs":        func(s *NodeSpec) { s.Hy2ObfsPassword = "" },
		"no certificate": func(s *NodeSpec) { s.CertPath = "" },
		"bad cidr":       func(s *NodeSpec) { s.AllowCIDRs = []string{"10.0.0.0/33"} },
	} {
		s := nodeSpec()
		mut(&s)
		if _, err := BuildServer(nil, s, nodeUsers()); !errors.Is(err, ErrNodeSpec) {
			t.Errorf("%s: want ErrNodeSpec, got %v", name, err)
		}
	}
	if _, err := BuildServer(nil, nodeSpec(), nil); !errors.Is(err, ErrNodeSpec) {
		t.Error("node without users and without placeholder must be rejected (naive needs a user)")
	}
	dup := append(nodeUsers(), nodeUsers()[0])
	if _, err := BuildServer(nil, nodeSpec(), dup); err == nil {
		t.Error("duplicate pseudonym accepted")
	}
}

func inbound(t *testing.T, d tmpl.Doc, tag string) map[string]any {
	t.Helper()
	for _, in := range tmpl.Objects(d, "inbounds") {
		if in["tag"] == tag {
			return in
		}
	}
	return nil
}

func TestServerStealSelfAndDeterminism(t *testing.T) {
	a, _ := BuildServer(nil, nodeSpec(), nodeUsers())
	u := nodeUsers()
	u[0], u[1] = u[1], u[0]
	b, _ := BuildServer(nil, nodeSpec(), u)
	ja, _ := tmpl.Marshal(a)
	jb, _ := tmpl.Marshal(b)
	if !bytes.Equal(ja, jb) {
		t.Fatal("user order must not change the config (stable reloads)")
	}
	n := inbound(t, a, TagInNaive)
	if n["listen"] != "127.0.0.1" || n["network"] != "tcp" {
		t.Fatal("naive inbound must be loopback-only and TCP-only (REALITY target)")
	}
	api := a["experimental"].(map[string]any)["v2ray_api"].(map[string]any)
	if api["listen"] != "127.0.0.1:10085" || len(api["stats"].(map[string]any)["users"].([]any)) != 2 {
		t.Fatal("stats must count users only, on loopback")
	}
	rules := a["route"].(map[string]any)["rules"].([]any)
	last := rules[len(rules)-1].(map[string]any)
	if last["ip_is_private"] != true || last["action"] != "reject" {
		t.Fatal("private destinations must be rejected")
	}
}

func TestServerNoLogTemplates(t *testing.T) {
	for name, mut := range map[string]func(tmpl.Doc){
		"log on":     func(d tmpl.Doc) { d["log"] = map[string]any{"level": "info"} },
		"clash api":  func(d tmpl.Doc) { d["experimental"].(map[string]any)["clash_api"] = map[string]any{} },
		"cache file": func(d tmpl.Doc) { d["experimental"].(map[string]any)["cache_file"] = map[string]any{"enabled": true} },
		"key log": func(d tmpl.Doc) {
			tmpl.Objects(d, "inbounds")[0]["tls"].(map[string]any)["key_log"] = "/tmp/keys"
		},
		"public stats": func(d tmpl.Doc) {
			d["experimental"].(map[string]any)["v2ray_api"] = map[string]any{"listen": "0.0.0.0:1"}
		},
	} {
		d := DefaultServerTemplate()
		mut(d)
		if _, err := BuildServer(d, nodeSpec(), nodeUsers()); !errors.Is(err, ErrNoLogViolation) {
			t.Errorf("%s: want ErrNoLogViolation, got %v", name, err)
		}
	}
}

func TestServerTokensDocumented(t *testing.T) {
	names, err := tmpl.Tokens(DefaultServerTemplate())
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range names {
		if _, ok := ServerTokens[n]; !ok {
			t.Errorf("token %s not documented", n)
		}
	}
	if len(names) != len(ServerTokens) {
		t.Errorf("ServerTokens documents %d tokens, template uses %d", len(ServerTokens), len(names))
	}
}

func TestNaiveCertificateDevOnly(t *testing.T) {
	p := profile.Fixture()
	p.Nodes[0].Transports.Naive.CertificatePEM = "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----"
	rel, err := BuildClient(&p, baseOpts())
	if err != nil {
		t.Fatal(err)
	}
	if findOutbound(rel, TagNaive) != nil {
		t.Fatal("release builds must skip naive with a private trust anchor")
	}
	o := baseOpts()
	o.AllowInsecure = true
	dev, _ := BuildClient(&p, o)
	n := findOutbound(dev, TagNaive)
	if n == nil || len(n.TLS.Certificate) != 3 {
		t.Fatalf("dev build must pass the PEM as lines, got %+v", n)
	}
}

func TestServerPlaceholderAndDisabled(t *testing.T) {
	s := nodeSpec()
	s.PlaceholderPassword = "placeholder-0123456789"
	doc, err := BuildServer(nil, s, nil)
	if err != nil {
		t.Fatal(err)
	}
	naive := inbound(t, doc, TagInNaive)["users"].([]any)
	if len(naive) != 1 || naive[0].(map[string]any)["username"] != PlaceholderUser {
		t.Fatalf("naive users %+v", naive)
	}
	if len(inbound(t, doc, TagInHysteria2)["users"].([]any)) != 0 {
		t.Fatal("no subscribers: Hysteria 2 must have no users")
	}
	s.DisableHysteria2, s.DisableNaive = true, true
	doc, err = BuildServer(nil, s, nodeUsers())
	if err != nil {
		t.Fatal(err)
	}
	if inbound(t, doc, TagInHysteria2) != nil || len(tmpl.Objects(doc, "inbounds")) != 1 {
		t.Fatal("hysteria2 inbound must be removed")
	}
	if u := inbound(t, doc, TagInNaive)["users"].([]any); len(u) != 1 || u[0].(map[string]any)["username"] != PlaceholderUser {
		t.Fatalf("disabled naive must only hold the placeholder: %+v", u)
	}
	checkServer(t, doc)
	bad := nodeUsers()
	bad[0].Pseudonym = PlaceholderUser
	if _, err := BuildServer(nil, nodeSpec(), bad); err == nil {
		t.Fatal("reserved pseudonym accepted")
	}
}
