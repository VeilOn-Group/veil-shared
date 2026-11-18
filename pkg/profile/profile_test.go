// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package profile

import (
	"errors"
	"strings"
	"testing"
	"time"
)

var fixtureNow = time.Unix(1_800_000_100, 0)

func TestFixtureIsValid(t *testing.T) {
	p := Fixture()
	if err := p.Validate(fixtureNow); err != nil {
		t.Fatalf("fixture invalid: %v", err)
	}
}

func TestValidateRejects(t *testing.T) {
	cases := map[string]struct {
		mutate func(*Profile)
		want   string
	}{
		"expired":          {func(p *Profile) { p.ExpiresAt = fixtureNow.Unix() - 1 }, "expired"},
		"bad schema":       {func(p *Profile) { p.SchemaVersion = "1.0" }, "schema_version"},
		"old major":        {func(p *Profile) { p.SchemaVersion = "0.9.0" }, "older than supported"},
		"no nodes":         {func(p *Profile) { p.Nodes = nil }, "at least one node"},
		"bad uuid":         {func(p *Profile) { p.Nodes[0].Transports.VLESS.UUID = "NOT-A-UUID" }, "uuid"},
		"vision over ws":   {func(p *Profile) { p.Nodes[0].Transports.VLESS.Transport.Type = "ws" }, "vision requires tcp"},
		"odd short id":     {func(p *Profile) { p.Nodes[0].Transports.VLESS.Reality.ShortID = "abc" }, "short_id"},
		"bad hop":          {func(p *Profile) { p.Nodes[0].Transports.Hysteria2.HopPorts = "40000:20000" }, "invalid range"},
		"short hop":        {func(p *Profile) { p.Nodes[0].Transports.Hysteria2.HopInterval = "1s" }, "hop_interval"},
		"obfs":             {func(p *Profile) { p.Nodes[0].Transports.Hysteria2.ObfsType = "xor" }, "salamander"},
		"naive creds":      {func(p *Profile) { p.Nodes[0].Transports.Naive.Password = "" }, "username and password"},
		"dup priority":     {func(p *Profile) { p.Priorities = []TransportID{TransportVLESS, TransportVLESS} }, "duplicate"},
		"xhttp flow":       {func(p *Profile) { p.Nodes[0].Transports.XHTTP.Flow = "xtls-rprx-vision" }, "takes no flow"},
		"xhttp path":       {func(p *Profile) { p.Nodes[0].Transports.XHTTP.Transport.Path = "nope" }, "transport.path"},
		"xhttp mode":       {func(p *Profile) { p.Nodes[0].Transports.XHTTP.Transport.Mode = "grpc" }, "transport.mode"},
		"xhttp type":       {func(p *Profile) { p.Nodes[0].Transports.XHTTP.Transport.Type = "tcp" }, "must be xhttp"},
		"patch not object": {func(p *Profile) { p.Nodes[0].Transports.XHTTP.OutboundPatch = "[1]" }, "JSON object"},
		"patch protocol":   {func(p *Profile) { p.Nodes[0].Transports.XHTTP.OutboundPatch = `{"protocol":"vmess"}` }, "cannot be changed"},
		"patch hy2 type":   {func(p *Profile) { p.Nodes[0].Transports.Hysteria2.OutboundPatch = `{"type":"direct"}` }, "cannot be changed"},
		"patch naive tag":  {func(p *Profile) { p.Nodes[0].Transports.Naive.OutboundPatch = `{"tag":"x"}` }, "cannot be changed"},
		"http api":         {func(p *Profile) { p.API.BaseURLs = []string{"http://api.example.net"} }, "must be https"},
		"udp policy":       {func(p *Profile) { p.UDPPolicy = "direct" }, "udp_policy"},
		"bad cidr":         {func(p *Profile) { p.Routing = []RouteRule{{IPCIDR: []string{"10.0.0.0/33"}, Action: "direct"}} }, "ip_cidr"},
		"bad date":         {func(p *Profile) { p.Subscription.EndsOn = "2027-01-31T10:00:00Z" }, "YYYY-MM-DD"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			p := Fixture()
			tc.mutate(&p)
			err := p.Validate(fixtureNow)
			var ve *ValidationError
			if !errors.As(err, &ve) {
				t.Fatalf("want ValidationError, got %v", err)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error %q does not mention %q", err, tc.want)
			}
		})
	}
}

// TestUnknownPriorityIgnored: a newer server may list a transport this
// client does not know; the profile stays valid (schema 1.1.0).
func TestUnknownPriorityIgnored(t *testing.T) {
	p := Fixture()
	p.Priorities = append([]TransportID{"wireguard"}, p.Priorities...)
	if err := p.Validate(fixtureNow); err != nil {
		t.Fatal(err)
	}
}

func TestNaiveNeverUDP(t *testing.T) {
	if TransportNaive.SupportsUDP() {
		t.Fatal("naive must never be UDP-capable")
	}
	if !TransportHysteria2.SupportsUDP() || !TransportVLESS.SupportsUDP() || !TransportXHTTP.SupportsUDP() {
		t.Fatal("hysteria2, vless and xhttp carry UDP")
	}
}

func TestSemver(t *testing.T) {
	a, _ := ParseSemver("1.10.0")
	b, _ := ParseSemver("1.9.9-beta.1")
	if a.Compare(b) != 1 || b.Compare(a) != -1 || a.Compare(a) != 0 {
		t.Fatal("compare broken")
	}
	for _, bad := range []string{"", "1", "1.2", "01.2.3", "a.b.c", "1.2.-3"} {
		if _, err := ParseSemver(bad); err == nil {
			t.Errorf("expected error for %q", bad)
		}
	}
}
