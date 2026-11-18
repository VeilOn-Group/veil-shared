// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package singbox

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/veilon/veil-shared/pkg/profile"
	"github.com/veilon/veil-shared/pkg/tmpl"
)

var update = flag.Bool("update", false, "rewrite golden files")

// Fixed, obviously synthetic runtime values so golden files are stable.
func baseOpts() ClientOptions {
	return ClientOptions{
		ClashAPIListen: "127.0.0.1:19090",
		ClashAPISecret: "golden-secret-not-real",
		CacheFilePath:  "/run/veilon/cache.db",
		AllowLAN:       true,
		Xray: map[profile.TransportID]*ExternalSOCKS{
			profile.TransportXHTTP: {Port: 1091, Username: "x-golden", Password: "x-golden-pass-not-real", ProcessPath: "/usr/lib/veilon/xray"},
			profile.TransportVLESS: {Port: 1092, Username: "v-golden", Password: "v-golden-pass-not-real", ProcessPath: "/usr/lib/veilon/xray"},
		},
	}
}

// ruleSetPath is the bundled rule set, relative to this package (sing-box
// check resolves it from the test's working directory).
const ruleSetPath = "../../assets/rulesets/geosite-category-ru.srs"

type scenario struct {
	name    string
	profile func() profile.Profile
	opts    func() ClientOptions
}

func scenarios() []scenario {
	return []scenario{
		{"default", profile.Fixture, baseOpts},
		{"naive_only", profile.Fixture, func() ClientOptions {
			o := baseOpts()
			o.Disabled = map[profile.TransportID]bool{profile.TransportXHTTP: true, profile.TransportVLESS: true, profile.TransportHysteria2: true}
			return o
		}},
		{"naive_external_socks", profile.Fixture, func() ClientOptions {
			o := baseOpts()
			o.NaiveExternal = &ExternalSOCKS{Port: 1081, Username: "local-golden", Password: "local-golden-pass", ProcessPath: "/usr/lib/veilon/naive"}
			return o
		}},
		{"kill_switch_pinned_hosts", profile.Fixture, func() ClientOptions {
			o := baseOpts()
			o.PinnedHosts = map[string][]string{"node1.example.net": {"203.0.113.10"}}
			o.DirectMark = 0x5649
			o.ProbeListen, o.ProbePassword = "127.0.0.1:19077", "golden-probe-password"
			o.UserRules = []profile.RouteRule{
				{DomainSuffix: []string{"bank.example.rs"}, Action: "direct"},
				{PackageName: []string{"org.example.bank"}, Action: "direct"},
			}
			return o
		}},
		{"ipv6_block_rules", func() profile.Profile {
			p := profile.Fixture()
			p.IPv6 = profile.IPv6Block
			p.Routing = []profile.RouteRule{
				{DomainSuffix: []string{"bank.example.rs"}, Action: "direct"},
				{ProcessName: []string{"torrent-client.exe"}, Action: "block"},
				{IPCIDR: []string{"192.0.2.0/24"}, Action: "proxy"},
			}
			return p
		}, func() ClientOptions { o := baseOpts(); o.AllowLAN = false; return o }},
		{"ru_bypass_kill_switch", func() profile.Profile {
			p := profile.Fixture()
			p.Routing = []profile.RouteRule{{IPCIDR: []string{"192.0.2.0/24"}, Action: "proxy"}}
			return p
		}, func() ClientOptions {
			o := baseOpts()
			o.DirectMark = 0x5649
			o.BypassSuffixes = RUZones
			o.BypassRuleSets = []RuleSetFile{{Tag: RuleSetCategoryRU, Path: ruleSetPath}}
			o.UserRules = []profile.RouteRule{{DomainSuffix: []string{"mail.example.ru"}, Action: "proxy"}}
			return o
		}},
		{"dns_quad9_default", profile.Fixture, func() ClientOptions { o := baseOpts(); o.DNS = &DNSChoice{}; return o }},
		{"dns_adguard", profile.Fixture, func() ClientOptions { o := baseOpts(); o.DNS = &DNSChoice{Provider: DNSAdGuard}; return o }},
		{"dns_custom_name_kill_switch", profile.Fixture, func() ClientOptions {
			o := baseOpts()
			o.DNS = &DNSChoice{Provider: DNSCustom, CustomURL: "https://doh.example.net/custom-query"}
			o.PinnedHosts = map[string][]string{"node1.example.net": {"203.0.113.10"}}
			o.DirectMark = 0x5649
			return o
		}},
		{"dns_custom_ip_port", profile.Fixture, func() ClientOptions {
			o := baseOpts()
			o.DNS = &DNSChoice{Provider: DNSCustom, CustomURL: "https://203.0.113.53:8443/dns-query"}
			return o
		}},
		{"host_without_ipv6", profile.Fixture, func() ClientOptions { o := baseOpts(); o.HostNoIPv6 = true; return o }},
		{"patches_no_xray", func() profile.Profile {
			p := profile.Fixture()
			p.Nodes[0].Transports.Hysteria2.OutboundPatch = `{"up_mbps":77,"tls":{"alpn":["h3","h3-29"]},"brutal_debug":null}`
			p.Nodes[0].Transports.Naive.OutboundPatch = `{"extra_headers":{"X-Pad":"1"}}`
			return p
		}, func() ClientOptions { o := baseOpts(); o.CacheFilePath = ""; o.Xray = nil; return o }},
	}
}

func TestGoldenClientConfigs(t *testing.T) {
	sb := os.Getenv("SINGBOX_BIN")
	for _, sc := range scenarios() {
		t.Run(sc.name, func(t *testing.T) {
			p := sc.profile()
			cfg, err := BuildClient(&p, sc.opts())
			if err != nil {
				t.Fatal(err)
			}
			got, err := json.MarshalIndent(cfg, "", "  ")
			if err != nil {
				t.Fatal(err)
			}
			got = append(got, '\n')
			path := filepath.Join("testdata", "golden", "client_"+sc.name+".json")
			if *update {
				if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, got, 0o644); err != nil {
					t.Fatal(err)
				}
			}
			want, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("missing golden (run with -update): %v", err)
			}
			if !bytes.Equal(got, want) {
				t.Fatalf("golden mismatch for %s; run `go test ./pkg/singbox -run Golden -update` and review the diff", path)
			}
			assertJSONNoLog(t, got)
			if sb != "" {
				out, err := exec.Command(sb, "check", "-c", path).CombinedOutput()
				if err != nil {
					t.Fatalf("sing-box check failed: %v\n%s", err, out)
				}
			}
		})
	}
	if sb == "" {
		t.Log("SINGBOX_BIN not set: golden files were not validated by sing-box check (CI sets it)")
	}
}

// assertJSONNoLog inspects the raw JSON independently of our structs, so a
// field added by mistake (e.g. via map types later) is still caught.
func assertJSONNoLog(t *testing.T, raw []byte) {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	log, _ := m["log"].(map[string]any)
	if log == nil {
		t.Fatal("NoLog: log section missing")
	}
	if lvl, _ := log["level"].(string); lvl != "warn" && lvl != "error" {
		t.Fatalf("NoLog: level %q", lvl)
	}
	if _, ok := log["output"]; ok {
		t.Fatal("NoLog: log.output set")
	}
	s := string(raw)
	for _, forbidden := range []string{`"udp_over_tcp"`, `"store_fakeip": true`, `"store_rdrc": true`, `"external_ui"`, `"v2ray_api"`} {
		if strings.Contains(s, forbidden) {
			t.Fatalf("NoLog: forbidden %s in client config", forbidden)
		}
	}
	for _, ob := range m["outbounds"].([]any) {
		o := ob.(map[string]any)
		if o["type"] == "naive" && o["quic"] != false {
			t.Fatal("NoLog: naive must have quic=false")
		}
		if o["tag"] == TagSelectorUDP {
			for _, x := range o["outbounds"].([]any) {
				if x == TagNaive {
					t.Fatal("NoLog: naive in UDP selector")
				}
			}
		}
	}
}

func TestStrictRouteDefaultOn(t *testing.T) {
	p := profile.Fixture()
	cfg, _ := BuildClient(&p, baseOpts())
	if !cfg.Inbounds[0].StrictRoute || len(cfg.Inbounds[0].Address) != 2 {
		t.Fatal("dual-stack hosts must use strict_route and both TUN families")
	}
}

func TestNoLogAssertions(t *testing.T) {
	p := profile.Fixture()
	cfg, err := BuildClient(&p, baseOpts())
	if err != nil {
		t.Fatal(err)
	}
	mutations := map[string]func(*Config){
		"info level":   func(c *Config) { c.Log.Level = "info" },
		"log file":     func(c *Config) { c.Log.Output = "/tmp/sb.log" },
		"no log":       func(c *Config) { c.Log = nil },
		"rdrc":         func(c *Config) { c.Experimental.CacheFile.StoreRDRC = true },
		"fakeip":       func(c *Config) { c.Experimental.CacheFile.StoreFakeIP = true },
		"clash public": func(c *Config) { c.Experimental.ClashAPI.ExternalController = "0.0.0.0:9090" },
		"clash nosec":  func(c *Config) { c.Experimental.ClashAPI.Secret = "" },
		"naive quic":   func(c *Config) { tr := true; findOutbound(c, TagNaive).QUIC = &tr },
		"naive in udp": func(c *Config) { s := findOutbound(c, TagSelectorUDP); s.Outbounds = append(s.Outbounds, TagNaive) },
	}
	for name, mut := range mutations {
		t.Run(name, func(t *testing.T) {
			c, _ := BuildClient(&p, baseOpts())
			mut(c)
			if err := AssertClientNoLog(c); !errors.Is(err, ErrNoLogViolation) {
				t.Fatalf("expected violation, got %v", err)
			}
		})
	}
	_ = cfg
	if err := AssertServerNoLog(tmpl.Doc{"log": map[string]any{"level": "warn"}}); err == nil {
		t.Fatal("server with logging enabled must fail")
	}
	if err := AssertServerNoLog(tmpl.Doc{"log": map[string]any{"disabled": true}}); err != nil {
		t.Fatal(err)
	}
}

func TestNoLogOptionsRejected(t *testing.T) {
	p := profile.Fixture()
	for name, o := range map[string]ClientOptions{
		"debug level":  func() ClientOptions { o := baseOpts(); o.LogLevel = "debug"; return o }(),
		"public clash": func() ClientOptions { o := baseOpts(); o.ClashAPIListen = "0.0.0.0:1"; return o }(),
		"empty secret": func() ClientOptions { o := baseOpts(); o.ClashAPISecret = ""; return o }(),
		"all disabled": func() ClientOptions {
			o := baseOpts()
			o.Disabled = map[profile.TransportID]bool{"xhttp": true, "vless": true, "hysteria2": true, "naive": true}
			return o
		}(),
		"unknown node": func() ClientOptions { o := baseOpts(); o.NodeID = "nope"; return o }(),
	} {
		if _, err := BuildClient(&p, o); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
	p.Nodes[0].Transports.Hysteria2.Insecure = true
	if _, err := BuildClient(&p, baseOpts()); err == nil {
		t.Error("insecure hysteria2 must be rejected outside dev builds")
	}
}

func TestUDPNeverToNaive(t *testing.T) {
	p := profile.Fixture()
	p.Priorities = []profile.TransportID{profile.TransportNaive, profile.TransportHysteria2, profile.TransportXHTTP, profile.TransportVLESS}
	cfg, err := BuildClient(&p, baseOpts())
	if err != nil {
		t.Fatal(err)
	}
	udp := findOutbound(cfg, TagSelectorUDP)
	if udp == nil || udp.Default != TagHysteria2 {
		t.Fatalf("udp selector must default to first UDP-capable transport, got %+v", udp)
	}
	tcp := findOutbound(cfg, TagSelectorTCP)
	if tcp.Default != TagNaive {
		t.Fatalf("tcp selector must follow priorities, got %s", tcp.Default)
	}
}

func findOutbound(c *Config, tag string) *Outbound {
	for i := range c.Outbounds {
		if c.Outbounds[i].Tag == tag {
			return &c.Outbounds[i]
		}
	}
	return nil
}

func TestHostWithoutIPv6RejectsV6(t *testing.T) {
	p := profile.Fixture()
	o := baseOpts()
	o.HostNoIPv6 = true
	cfg, err := BuildClient(&p, o)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Inbounds[0].StrictRoute {
		t.Fatal("strict_route must be off on IPv6-less Linux hosts")
	}
	if len(cfg.Inbounds[0].Address) != 1 {
		t.Fatalf("tun must be IPv4-only, got %v", cfg.Inbounds[0].Address)
	}
	found := false
	for _, r := range cfg.Route.Rules {
		if r.IPVersion == 6 && r.Action == "reject" {
			found = true
		}
	}
	if !found {
		t.Fatal("IPv6 must be rejected explicitly when the host has no IPv6")
	}
}

func TestXrayTransports(t *testing.T) {
	p := profile.Fixture()
	cfg, err := BuildClient(&p, baseOpts())
	if err != nil {
		t.Fatal(err)
	}
	x := findOutbound(cfg, TagXHTTP)
	if x == nil || x.Type != "socks" || x.Server != "127.0.0.1" || x.ServerPort != 1091 || x.Network != "" {
		t.Fatalf("xhttp must go to the local Xray SOCKS endpoint (TCP and UDP): %+v", x)
	}
	if tcp := findOutbound(cfg, TagSelectorTCP); tcp.Default != TagXHTTP {
		t.Fatalf("xhttp is the default transport, got %s", tcp.Default)
	}
	if udp := findOutbound(cfg, TagSelectorUDP); udp.Outbounds[0] != TagXHTTP {
		t.Fatal("xhttp carries UDP")
	}
	if r := cfg.Route.Rules[0]; len(r.ProcessPath) != 1 || r.Outbound != TagDirect {
		t.Fatalf("the Xray process must bypass the TUN once: %+v", r)
	}
	o := baseOpts()
	o.Xray = nil
	cfg, _ = BuildClient(&p, o)
	if findOutbound(cfg, TagXHTTP) != nil || findOutbound(cfg, TagVLESS) != nil {
		t.Fatal("without Xray the VLESS transports are not offered")
	}
}

func TestPatchKeepsIdentityAndNoLog(t *testing.T) {
	p := profile.Fixture()
	p.Nodes[0].Transports.Hysteria2.OutboundPatch = `{"up_mbps":5}`
	cfg, err := BuildClient(&p, baseOpts())
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(cfg)
	if !strings.Contains(string(raw), `"up_mbps":5`) {
		t.Fatal("patch not applied")
	}
	// A patch that breaks a zero-log invariant is refused (naive QUIC).
	p = profile.Fixture()
	p.Nodes[0].Transports.Naive.OutboundPatch = `{"quic":true}`
	if _, err := BuildClient(&p, baseOpts()); !errors.Is(err, ErrNoLogViolation) {
		t.Fatalf("naive quic via patch: %v", err)
	}
}

func TestRuleSetOptions(t *testing.T) {
	p := profile.Fixture()
	o := baseOpts()
	o.BypassRuleSets = []RuleSetFile{{Tag: "Bad Tag", Path: "x.srs"}}
	if _, err := BuildClient(&p, o); err == nil {
		t.Fatal("bad rule set tag accepted")
	}
	o.BypassRuleSets = []RuleSetFile{{Tag: "ok", Path: "https://example.net/x.srs.json"}}
	if _, err := BuildClient(&p, o); err == nil {
		t.Fatal("non-local rule set accepted")
	}
}
