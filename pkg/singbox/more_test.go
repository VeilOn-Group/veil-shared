// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package singbox

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/veilon/veil-shared/pkg/profile"
	"github.com/veilon/veil-shared/pkg/tmpl"
)

func TestTagFor(t *testing.T) {
	want := map[profile.TransportID]string{
		profile.TransportXHTTP: TagXHTTP, profile.TransportVLESS: TagVLESS,
		profile.TransportHysteria2: TagHysteria2, profile.TransportNaive: TagNaive, "wireguard": "",
	}
	for id, tag := range want {
		if TagFor(id) != tag {
			t.Errorf("TagFor(%s) = %q", id, TagFor(id))
		}
	}
}

func TestPresetURL(t *testing.T) {
	p, ok := Preset(DNSQuad9)
	if !ok || p.URL() != "https://dns.quad9.net/dns-query" {
		t.Fatalf("%v %q", ok, p.URL())
	}
}

func TestBuildClientOptionErrors(t *testing.T) {
	p := profile.Fixture()
	many := make([]string, 65)
	for i := range many {
		many[i] = "zone"
	}
	rs := make([]RuleSetFile, 9)
	cases := map[string]func(*ClientOptions){
		"log level":  func(o *ClientOptions) { o.LogLevel = "debug" },
		"many zones": func(o *ClientOptions) { o.BypassSuffixes = many },
		"bad zone":   func(o *ClientOptions) { o.BypassSuffixes = []string{"bad zone!"} },
		"many sets":  func(o *ClientOptions) { o.BypassRuleSets = rs },
		"probe host": func(o *ClientOptions) { o.ProbeListen, o.ProbePassword = "0.0.0.0:1", strings.Repeat("p", 16) },
		"probe pass": func(o *ClientOptions) { o.ProbeListen, o.ProbePassword = "127.0.0.1:1", "short" },
		"probe port": func(o *ClientOptions) { o.ProbeListen, o.ProbePassword = "127.0.0.1:x", strings.Repeat("p", 16) },
	}
	for name, mut := range cases {
		o := baseOpts()
		mut(&o)
		if _, err := BuildClient(&p, o); !errors.Is(err, ErrBadOptions) {
			t.Errorf("%s: want ErrBadOptions, got %v", name, err)
		}
	}
}

func TestPickNode(t *testing.T) {
	p := profile.Fixture()
	if n, err := pickNode(&p, p.Nodes[0].ID); err != nil || n.ID != p.Nodes[0].ID {
		t.Fatalf("by id: %v", err)
	}
	if _, err := pickNode(&p, "missing"); !errors.Is(err, ErrNoNode) {
		t.Fatalf("missing id: %v", err)
	}
	p.Nodes = nil
	if _, err := pickNode(&p, ""); !errors.Is(err, ErrNoNode) {
		t.Fatalf("no nodes: %v", err)
	}
}

func TestPriorityOrderAppendsUnlisted(t *testing.T) {
	enabled := map[profile.TransportID]bool{profile.TransportNaive: true, profile.TransportHysteria2: true}
	got := priorityOrder([]profile.TransportID{profile.TransportNaive, profile.TransportNaive, profile.TransportVLESS}, enabled)
	if len(got) != 2 || got[0] != profile.TransportNaive || got[1] != profile.TransportHysteria2 {
		t.Fatalf("order %v", got)
	}
}

func TestPatchHelpersNil(t *testing.T) {
	if patchOf(nil) != "" || patchOfNaive(nil) != "" {
		t.Fatal("nil transports have no patch")
	}
}

func TestHysteria2DefaultALPN(t *testing.T) {
	h := *profile.Fixture().Nodes[0].Transports.Hysteria2
	h.ALPN = nil
	ob, err := Hysteria2Outbound(&h, false)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(ob)
	if !strings.Contains(string(b), `"h3"`) {
		t.Fatalf("default ALPN missing: %s", b)
	}
}

func TestMarshalRejectsBadPatches(t *testing.T) {
	p := profile.Fixture()
	p.Nodes[0].Transports.Hysteria2.OutboundPatch = `{"up_mbps":`
	cfg, err := BuildClient(&p, baseOpts())
	if err == nil {
		if _, err = json.Marshal(cfg); err == nil {
			t.Fatal("broken patch accepted")
		}
	}
	// A patch that turns a field into the wrong type fails the re-decode.
	p = profile.Fixture()
	p.Nodes[0].Transports.Hysteria2.OutboundPatch = `{"server_port":"not a number"}`
	if _, err := BuildClient(&p, baseOpts()); !errors.Is(err, ErrBadOptions) || !strings.Contains(err.Error(), "patched config") {
		t.Fatalf("type-breaking patch: %v", err)
	}
}

func TestServerNoLogDebug(t *testing.T) {
	d := DefaultServerTemplate()
	d["debug"] = map[string]any{"listen": "127.0.0.1:6060"}
	if _, err := BuildServer(d, nodeSpec(), nodeUsers()); !errors.Is(err, ErrNoLogViolation) {
		t.Fatalf("debug listener accepted: %v", err)
	}
}

func TestServerTemplateErrors(t *testing.T) {
	s := nodeSpec()
	s.Domain = ""
	if _, err := BuildServer(nil, s, nodeUsers()); err == nil {
		t.Fatal("bad spec accepted")
	}
	// An empty experimental object is dropped from the output.
	d := tmpl.Doc{"log": map[string]any{"disabled": true}, "experimental": map[string]any{}, "inbounds": []any{}, "outbounds": []any{}}
	doc, err := BuildServer(d, nodeSpec(), nodeUsers())
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := doc["experimental"]; ok {
		t.Fatal("empty experimental kept")
	}
}

func TestValidHostNameCharacters(t *testing.T) {
	for _, h := range []string{"doh_x.example.net", "DOH.example.net", strings.Repeat("a", 64) + ".net", strings.Repeat("a.", 127) + "aa"} {
		if validHostName(h) {
			t.Errorf("%q accepted", h)
		}
	}
	if !validHostName("doh-1.example.net") {
		t.Fatal("valid host rejected")
	}
}
