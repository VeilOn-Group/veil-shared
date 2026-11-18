// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package xray

import (
	"errors"
	"strings"
	"testing"

	"github.com/veilon/veil-shared/pkg/profile"
	"github.com/veilon/veil-shared/pkg/tmpl"
)

func TestLoopbackPort(t *testing.T) {
	p, err := LoopbackPort()
	if err != nil || p == 0 {
		t.Fatalf("port %d: %v", p, err)
	}
}

func TestPlanClient(t *testing.T) {
	n := profile.Fixture().Nodes[0]
	next := uint16(30000)
	free := func() (uint16, error) { next++; return next, nil }
	plan, err := PlanClient(&n, PlanOptions{Mark: 7, ProcessPath: "/opt/xray", FreePort: free,
		Resolve: func(h string) string {
			if h == n.Transports.XHTTP.Server {
				return "203.0.113.5"
			}
			return ""
		}})
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Spec.Transports) != 2 || plan.Spec.Mark != 7 {
		t.Fatalf("plan %+v", plan.Spec)
	}
	x := plan.Spec.Transports[0]
	if x.ID != profile.TransportXHTTP || x.Address != "203.0.113.5" || len(x.Local.Password) != 48 || !strings.HasPrefix(x.Local.Username, "v") {
		t.Fatalf("xhttp transport %+v", x)
	}
	ep := plan.Endpoints[profile.TransportXHTTP]
	if ep.Port != x.Local.Port || ep.Password != x.Local.Password || ep.ProcessPath != "/opt/xray" {
		t.Fatalf("endpoint %+v does not match %+v", ep, x.Local)
	}
	if plan.Spec.Transports[0].Local.Password == plan.Spec.Transports[1].Local.Password {
		t.Fatal("transports share a password")
	}
	if _, err := BuildClient(plan.Spec); err != nil {
		t.Fatalf("plan does not build: %v", err)
	}

	// Disabled transports get no process; with none left there is no plan.
	none, err := PlanClient(&n, PlanOptions{FreePort: free, Disabled: map[profile.TransportID]bool{
		profile.TransportXHTTP: true, profile.TransportVLESS: true}})
	if err != nil || none != nil {
		t.Fatalf("all disabled: %v %v", none, err)
	}
	if _, err := PlanClient(&n, PlanOptions{FreePort: func() (uint16, error) { return 0, errors.New("no ports") }}); err == nil {
		t.Fatal("port error swallowed")
	}
	// Default port source.
	if p, err := PlanClient(&n, PlanOptions{}); err != nil || p == nil {
		t.Fatalf("default ports: %v", err)
	}
}

func TestBuildClientRejects(t *testing.T) {
	base := clientTransports()
	mut := func(f func(*ClientTransport)) []ClientTransport {
		ts := clientTransports()
		v := *ts[0].VLESS
		ts[0].VLESS = &v
		f(&ts[0])
		return ts
	}
	cases := map[string][]ClientTransport{
		"none":       nil,
		"duplicate":  {base[0], base[0]},
		"naive":      mut(func(c *ClientTransport) { c.ID = profile.TransportNaive }),
		"nil vless":  mut(func(c *ClientTransport) { c.VLESS = nil }),
		"no port":    mut(func(c *ClientTransport) { c.Local.Port = 0 }),
		"weak pass":  mut(func(c *ClientTransport) { c.Local.Password = "short" }),
		"no user":    mut(func(c *ClientTransport) { c.Local.Username = "" }),
		"type":       mut(func(c *ClientTransport) { c.VLESS.Transport.Type = "kcp" }),
		"no reality": mut(func(c *ClientTransport) { c.VLESS.Reality = nil }),
		"security":   mut(func(c *ClientTransport) { c.VLESS.Security = "none" }),
		"patch":      mut(func(c *ClientTransport) { c.VLESS.OutboundPatch = "[1]" }),
		"patch null": mut(func(c *ClientTransport) { c.VLESS.OutboundPatch = "null" }),
	}
	for name, ts := range cases {
		if _, err := BuildClient(ClientSpec{Transports: ts}); !errors.Is(err, ErrClient) {
			t.Errorf("%s: want ErrClient, got %v", name, err)
		}
	}
}

func TestClientOutboundVariants(t *testing.T) {
	v := *profile.Fixture().Nodes[0].Transports.VLESS
	v.Flow = ""
	v.Security = "tls"
	v.Reality = nil
	v.TLS.ALPN = []string{"h2"}
	v.TLS.UTLSFingerprint = ""
	for _, tc := range []struct{ typ, network string }{{"ws", "ws"}, {"grpc", "grpc"}} {
		w := v
		w.Transport.Type = tc.typ
		w.Transport.Path, w.Transport.Host, w.Transport.ServiceName = "/w", "cdn.example.net", "svc"
		ob, err := ClientOutbound(ClientTransport{ID: profile.TransportVLESS, VLESS: &w, Local: LocalSOCKS{Port: 1, Username: "u", Password: strings.Repeat("p", 16)}}, 0)
		if err != nil {
			t.Fatalf("%s: %v", tc.typ, err)
		}
		ss := ob["streamSettings"].(map[string]any)
		if ss["network"] != tc.network || ss["security"] != "tls" {
			t.Fatalf("%s: %v", tc.typ, ss)
		}
		ts := ss["tlsSettings"].(map[string]any)
		if ts["fingerprint"] != "chrome" || ts["alpn"] == nil {
			t.Fatalf("tls settings %v", ts)
		}
		if tc.typ == "ws" && ss["wsSettings"].(map[string]any)["host"] != "cdn.example.net" {
			t.Fatalf("ws host lost: %v", ss)
		}
		if _, ok := ss["sockopt"]; ok {
			t.Fatal("sockopt without a mark")
		}
		// Without an explicit address the server name is dialed.
		if addr := ob["settings"].(map[string]any)["vnext"].([]any)[0].(map[string]any)["address"]; addr != w.Server {
			t.Fatalf("address %v", addr)
		}
	}
	x := *profile.Fixture().Nodes[0].Transports.XHTTP
	x.Transport.Mode, x.Transport.Host = "", "front.example.net"
	ob, err := ClientOutbound(ClientTransport{ID: profile.TransportXHTTP, VLESS: &x, Address: "198.51.100.1"}, 9)
	if err != nil {
		t.Fatal(err)
	}
	xs := ob["streamSettings"].(map[string]any)["xhttpSettings"].(map[string]any)
	if xs["mode"] != "auto" || xs["host"] != "front.example.net" {
		t.Fatalf("xhttp settings %v", xs)
	}
	// A patch that removes streamSettings still gets the mark back.
	x.OutboundPatch = `{"streamSettings":null}`
	ob, err = ClientOutbound(ClientTransport{ID: profile.TransportXHTTP, VLESS: &x}, 9)
	if err != nil {
		t.Fatal(err)
	}
	if ob["streamSettings"].(map[string]any)["sockopt"].(map[string]any)["mark"] != int64(9) {
		t.Fatalf("mark lost: %v", ob)
	}
}

func TestClientNoLogMore(t *testing.T) {
	for name, mut := range map[string]func(tmpl.Doc){
		"no auth": func(d tmpl.Doc) { tmpl.Objects(d, "inbounds")[0]["settings"].(map[string]any)["auth"] = "noauth" },
		"no log":  func(d tmpl.Doc) { delete(d, "log") },
		"mask":    func(d tmpl.Doc) { d["log"].(map[string]any)["maskAddress"] = "quarter" },
		"stats":   func(d tmpl.Doc) { d["stats"] = map[string]any{} },
		"key log": func(d tmpl.Doc) { d["x"] = map[string]any{"masterKeyLog": "/k"} },
	} {
		doc, err := BuildClient(ClientSpec{Transports: clientTransports()})
		if err != nil {
			t.Fatal(err)
		}
		mut(doc)
		if err := AssertClientNoLog(doc); !errors.Is(err, ErrNoLogViolation) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestServerSpecValidation(t *testing.T) {
	cases := map[string]func(*ServerSpec){
		"domain":    func(s *ServerSpec) { s.Domain = "a b" },
		"port":      func(s *ServerSpec) { s.Port = 0 },
		"target":    func(s *ServerSpec) { s.Target = "203.0.113.1:443" },
		"key":       func(s *ServerSpec) { s.PrivateKey = "short" },
		"no short":  func(s *ServerSpec) { s.ShortIDs = nil },
		"bad short": func(s *ServerSpec) { s.ShortIDs = []string{"xyz"} },
		"socket":    func(s *ServerSpec) { s.XHTTPSocket = "/tmp/sock" },
		"time":      func(s *ServerSpec) { s.MaxTimeDiffMs = 700_000 },
		"flow":      func(s *ServerSpec) { s.Flow = "other" },
		"path":      func(s *ServerSpec) { s.XHTTPPath = "bad" },
		"mode":      func(s *ServerSpec) { s.XHTTPMode = "grpc" },
		"api":       func(s *ServerSpec) { s.APIListen = "0.0.0.0:1" },
		"cidr":      func(s *ServerSpec) { s.AllowCIDRs = []string{"nope"} },
	}
	for name, mut := range cases {
		s := spec()
		mut(&s)
		if _, err := BuildServer(nil, s, users()); !errors.Is(err, ErrSpec) {
			t.Errorf("%s: want ErrSpec, got %v", name, err)
		}
	}
	bad := users()
	bad[0].UUID = "not-a-uuid"
	if _, err := BuildServer(nil, spec(), bad); !errors.Is(err, ErrSpec) {
		t.Fatalf("bad user: %v", err)
	}
	dup := append(users(), users()[0])
	if _, err := BuildServer(nil, spec(), dup); !errors.Is(err, ErrSpec) {
		t.Fatalf("duplicate user: %v", err)
	}
}

func TestUsersHelpersSkipOtherInbounds(t *testing.T) {
	doc := tmpl.Doc{"inbounds": []any{
		map[string]any{"tag": "dokodemo", "protocol": "dokodemo-door"},
		map[string]any{"protocol": "vless", "settings": map[string]any{"clients": []any{}}},
		map[string]any{"tag": "v", "protocol": "vless", "settings": map[string]any{"clients": []any{map[string]any{"email": "u_a"}, "junk"}}},
	}}
	if u := Users(doc); len(u) != 1 || len(u["v"]) != 1 {
		t.Fatalf("Users %v", u)
	}
	if p := UsersPatch(doc, map[string]bool{"u_zzz": true}); len(p["inbounds"].([]any)) != 0 {
		t.Fatalf("patch without matching users: %v", p)
	}
	w := WithoutUsers(doc)
	if len(tmpl.Objects(w, "inbounds")[2]["settings"].(map[string]any)["clients"].([]any)) != 0 {
		t.Fatal("clients kept")
	}
}
