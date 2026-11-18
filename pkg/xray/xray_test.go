// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package xray

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/veilon/veil-shared/pkg/profile"
	"github.com/veilon/veil-shared/pkg/tmpl"
)

// Synthetic values only (keys generated for tests, never used anywhere else).
func spec() ServerSpec {
	return ServerSpec{
		Listen: "0.0.0.0", Port: 443, Domain: "node1.example.net", Target: "127.0.0.1:8444",
		PrivateKey: "AHfhQF2iiyDFQZCYA2c4xOlwnAoplmy5vsw4mILQZUs", ShortIDs: []string{"0123456789abcdef", "ab"},
		MaxTimeDiffMs: 90000, Flow: FlowVision, XHTTPPath: "/x7golden", XHTTPMode: "auto",
		APIListen: "127.0.0.1:10086", BlockPorts: []uint16{25, 465, 587}, Vision: true, XHTTP: true,
	}
}

func users() []User {
	return []User{
		{Email: "u_bbbb", UUID: "11111111-2222-4333-8444-555555555555"},
		{Email: "u_aaaa", UUID: "8c7c3b1e-5d1a-4a4e-9a65-2f0f7a8b9c01"},
	}
}

// xrayBin is the official Xray release binary used to validate goldens
// (VEILON_XRAY, else /opt/xray/linux/xray when present).
func xrayBin(t *testing.T) string {
	if p := os.Getenv("VEILON_XRAY"); p != "" {
		return p
	}
	if _, err := os.Stat("/opt/xray/linux/xray"); err == nil {
		return "/opt/xray/linux/xray"
	}
	t.Log("xray binary not found: skipping `xray run -test`")
	return ""
}

func xrayTest(t *testing.T, doc tmpl.Doc) {
	t.Helper()
	bin := xrayBin(t)
	if bin == "" {
		return
	}
	b, _ := tmpl.Marshal(doc)
	p := filepath.Join(t.TempDir(), "c.json")
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command(bin, "run", "-test", "-c", p).CombinedOutput() //nolint:gosec // test binary
	if err != nil || !bytes.Contains(out, []byte("Configuration OK")) {
		t.Fatalf("xray run -test: %v\n%s", err, out)
	}
}

func golden(t *testing.T, name string, doc tmpl.Doc) {
	t.Helper()
	got, err := tmpl.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join("testdata", name)
	if os.Getenv("UPDATE_GOLDEN") == "1" {
		_ = os.MkdirAll("testdata", 0o755)
		if err := os.WriteFile(p, got, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("%v (run with UPDATE_GOLDEN=1 after review)", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("%s differs from golden:\n%s", name, got)
	}
}

func TestServerGolden(t *testing.T) {
	doc, err := BuildServer(nil, spec(), users())
	if err != nil {
		t.Fatal(err)
	}
	golden(t, "server_node.json", doc)
	xrayTest(t, doc)

	s := spec()
	s.Flow, s.Vision, s.AllowCIDRs, s.MaxTimeDiffMs = "", false, []string{"10.200.0.0/24"}, 0
	doc, err = BuildServer(nil, s, users())
	if err != nil {
		t.Fatal(err)
	}
	golden(t, "server_node_xhttp_only.json", doc)
	xrayTest(t, doc)
}

func TestServerNoUsersStillValid(t *testing.T) {
	doc, err := BuildServer(nil, spec(), nil)
	if err != nil {
		t.Fatal(err)
	}
	xrayTest(t, doc)
}

func TestTemplateHasNoSecrets(t *testing.T) {
	b, _ := tmpl.Marshal(DefaultServerTemplate())
	for _, secret := range []string{spec().PrivateKey, users()[0].UUID} {
		if bytes.Contains(b, []byte(secret)) {
			t.Fatal("template contains a secret")
		}
	}
	names, err := tmpl.Tokens(DefaultServerTemplate())
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range names {
		if _, ok := ServerTokens[n]; !ok {
			t.Errorf("token %s is not documented in ServerTokens", n)
		}
	}
	if len(names) != len(ServerTokens) {
		t.Errorf("ServerTokens documents %d tokens, template uses %d", len(ServerTokens), len(names))
	}
}

func TestServerNoLogRejects(t *testing.T) {
	cases := map[string]func(tmpl.Doc){
		"access log": func(d tmpl.Doc) { d["log"].(map[string]any)["access"] = "/var/log/xray.log" },
		"loglevel":   func(d tmpl.Doc) { d["log"].(map[string]any)["loglevel"] = "warning" },
		"no log":     func(d tmpl.Doc) { delete(d, "log") },
		"dnslog":     func(d tmpl.Doc) { d["log"].(map[string]any)["dnsLog"] = true },
		"online ips": func(d tmpl.Doc) {
			d["policy"].(map[string]any)["levels"].(map[string]any)["0"].(map[string]any)["statsUserOnline"] = true
		},
		"public api":     func(d tmpl.Doc) { d["api"].(map[string]any)["listen"] = "0.0.0.0:10086" },
		"logger service": func(d tmpl.Doc) { d["api"].(map[string]any)["services"] = []any{"LoggerService"} },
		"metrics":        func(d tmpl.Doc) { d["metrics"] = map[string]any{"listen": "127.0.0.1:9000"} },
		"key log": func(d tmpl.Doc) {
			tmpl.Objects(d, "inbounds")[0]["streamSettings"].(map[string]any)["realitySettings"].(map[string]any)["masterKeyLog"] = "/tmp/k"
		},
		"show": func(d tmpl.Doc) {
			tmpl.Objects(d, "inbounds")[0]["streamSettings"].(map[string]any)["realitySettings"].(map[string]any)["show"] = true
		},
	}
	for name, mut := range cases {
		t.Run(name, func(t *testing.T) {
			d := DefaultServerTemplate()
			mut(d)
			if _, err := BuildServer(d, spec(), users()); !errors.Is(err, ErrNoLogViolation) {
				t.Fatalf("want ErrNoLogViolation, got %v", err)
			}
		})
	}
}

func TestCustomTemplate(t *testing.T) {
	raw := []byte(`{"log":{"access":"none","error":"none","loglevel":"none"},
	 "inbounds":[{"tag":"vless-in","listen":"$veilon:listen","port":"$veilon:tcp_port","protocol":"vless",
	   "settings":{"clients":"$veilon:clients_vision","decryption":"none"},
	   "streamSettings":{"network":"raw","security":"reality","realitySettings":{"target":"$veilon:reality_target",
	     "serverNames":"$veilon:server_names","privateKey":"$veilon:reality_private_key","shortIds":"$veilon:reality_short_ids"}}}],
	 "outbounds":[{"protocol":"freedom"}]}`)
	d, err := tmpl.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	doc, err := BuildServer(d, spec(), users())
	if err != nil {
		t.Fatal(err)
	}
	xrayTest(t, doc)
	b, _ := tmpl.Marshal(doc)
	if !bytes.Contains(b, []byte(users()[0].UUID)) || !bytes.Contains(b, []byte(`"port": 443`)) {
		t.Fatalf("tokens not rendered:\n%s", b)
	}
	d["inbounds"].([]any)[0].(map[string]any)["port"] = "$veilon:nope"
	if _, err := BuildServer(d, spec(), users()); err == nil || !strings.Contains(err.Error(), "unknown token") {
		t.Fatalf("unknown token accepted: %v", err)
	}
}

func TestUsersDiffHelpers(t *testing.T) {
	a, _ := BuildServer(nil, spec(), users())
	b, _ := BuildServer(nil, spec(), users()[:1])
	wa, _ := tmpl.Marshal(WithoutUsers(a))
	wb, _ := tmpl.Marshal(WithoutUsers(b))
	if !bytes.Equal(wa, wb) {
		t.Fatal("configs differing only in users must be equal without users")
	}
	if ua := Users(a); len(ua[TagInVision]) != 2 || len(ua[TagInXHTTP]) != 2 {
		t.Fatalf("users: %v", ua)
	}
	p := UsersPatch(a, map[string]bool{"u_aaaa": true})
	ins := tmpl.Objects(p, "inbounds")
	if len(ins) != 2 || len(ins[0]["settings"].(map[string]any)["clients"].([]any)) != 1 {
		t.Fatalf("patch: %v", p)
	}
	// The original config keeps its users (WithoutUsers copies).
	if len(Users(a)[TagInVision]) != 2 {
		t.Fatal("WithoutUsers modified its input")
	}
}

func clientTransports() []ClientTransport {
	p := profile.Fixture()
	n := p.Nodes[0].Transports
	return []ClientTransport{
		{ID: profile.TransportXHTTP, VLESS: n.XHTTP, Address: "203.0.113.10", Local: LocalSOCKS{Port: 20001, Username: "vx", Password: "golden-password-xhttp"}},
		{ID: profile.TransportVLESS, VLESS: n.VLESS, Address: "203.0.113.10", Local: LocalSOCKS{Port: 20002, Username: "vv", Password: "golden-password-vless"}},
	}
}

func TestClientGolden(t *testing.T) {
	doc, err := BuildClient(ClientSpec{Transports: clientTransports(), Mark: 0x2a})
	if err != nil {
		t.Fatal(err)
	}
	golden(t, "client.json", doc)
	xrayTest(t, doc)
}

func TestClientPatch(t *testing.T) {
	ts := clientTransports()
	x := *ts[0].VLESS
	x.OutboundPatch = `{"streamSettings":{"xhttpSettings":{"mode":"packet-up","xmux":{"maxConcurrency":"16-32"}},"sockopt":{"mark":1}},"tag":"evil","mux":{"enabled":false}}`
	ts[0].VLESS = &x
	doc, err := BuildClient(ClientSpec{Transports: ts, Mark: 0x2a})
	if err != nil {
		t.Fatal(err)
	}
	xrayTest(t, doc)
	ob := tmpl.Objects(doc, "outbounds")[0]
	ss := ob["streamSettings"].(map[string]any)
	if ob["tag"] != "xhttp" || ss["xhttpSettings"].(map[string]any)["mode"] != "packet-up" || ss["xhttpSettings"].(map[string]any)["path"] != "/f1xture" {
		t.Fatalf("patch not merged: %v", ob)
	}
	if ss["sockopt"].(map[string]any)["mark"] != int64(0x2a) {
		t.Fatal("the kill switch mark must survive a patch")
	}
}

func TestClientNoLog(t *testing.T) {
	doc, _ := BuildClient(ClientSpec{Transports: clientTransports()})
	tmpl.Objects(doc, "inbounds")[0]["listen"] = "0.0.0.0"
	if err := AssertClientNoLog(doc); !errors.Is(err, ErrNoLogViolation) {
		t.Fatal("public client inbound accepted")
	}
	doc, _ = BuildClient(ClientSpec{Transports: clientTransports()})
	doc["api"] = map[string]any{}
	if err := AssertClientNoLog(doc); !errors.Is(err, ErrNoLogViolation) {
		t.Fatal("client api accepted")
	}
}
