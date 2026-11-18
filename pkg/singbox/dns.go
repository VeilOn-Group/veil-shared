// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package singbox

import (
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
)

// DNS over HTTPS through the tunnel (ADR-0073). The user picks a provider
// in the app; Quad9 is the default. Every query leaves through the active
// transport, so the provider sees the node address, never the user's.

// DNS providers.
const (
	DNSQuad9      = "quad9"
	DNSCloudflare = "cloudflare"
	DNSGoogle     = "google"
	DNSAdGuard    = "adguard"
	DNSOpenDNS    = "opendns"
	DNSCustom     = "custom"
	// DNSDefault is used when the user has not chosen.
	DNSDefault = DNSQuad9
)

// TagDNSBootstrap resolves the host name of a custom DoH server, through
// the tunnel (Quad9 by address), so the name never reaches the local
// resolver.
const TagDNSBootstrap = "dns-bootstrap"

// DoHPreset is a well-known public DoH service. Servers are dialled by
// address (no bootstrap lookup) and the certificate is checked for Host.
type DoHPreset struct {
	ID   string   `json:"id"`
	Name string   `json:"name"`
	Host string   `json:"host"` // TLS server name and the host of URL
	IPs  []string `json:"ips"`  // first is used, the rest documented
	Path string   `json:"path"`
}

// URL is the DoH URL of the preset.
func (p DoHPreset) URL() string { return "https://" + p.Host + p.Path }

// DoHPresets in the order shown in the apps. Addresses and URLs from the
// providers' public documentation (checked 2026-11-02).
var DoHPresets = []DoHPreset{
	{ID: DNSQuad9, Name: "Quad9", Host: "dns.quad9.net", IPs: []string{"9.9.9.9", "149.112.112.112"}, Path: "/dns-query"},
	{ID: DNSCloudflare, Name: "Cloudflare", Host: "cloudflare-dns.com", IPs: []string{"1.1.1.1", "1.0.0.1"}, Path: "/dns-query"},
	{ID: DNSGoogle, Name: "Google", Host: "dns.google", IPs: []string{"8.8.8.8", "8.8.4.4"}, Path: "/dns-query"},
	{ID: DNSAdGuard, Name: "AdGuard", Host: "dns.adguard-dns.com", IPs: []string{"94.140.14.14", "94.140.15.15"}, Path: "/dns-query"},
	{ID: DNSOpenDNS, Name: "OpenDNS", Host: "doh.opendns.com", IPs: []string{"208.67.222.222", "208.67.220.220"}, Path: "/dns-query"},
}

// Preset returns the preset with id.
func Preset(id string) (DoHPreset, bool) {
	for _, p := range DoHPresets {
		if p.ID == id {
			return p, true
		}
	}
	return DoHPreset{}, false
}

// DNSChoice is the user's resolver selection (client setting, not part of
// the signed profile).
type DNSChoice struct {
	Provider  string `json:"provider"`             // one of the DNS* ids; "" = default
	CustomURL string `json:"custom_url,omitempty"` // provider "custom": https://host[:port]/path
}

// ErrDNS reports an invalid DNS choice.
var ErrDNS = errors.New("singbox: invalid DNS choice")

// dohEndpoint is a resolved choice, ready for the config.
type dohEndpoint struct {
	server     string // address or host name
	port       uint16 // 0 = 443
	path       string
	serverName string // TLS SNI and certificate name
	byName     bool   // server is a host name: needs the bootstrap resolver
}

// Validate checks the choice.
func (c DNSChoice) Validate() error {
	_, err := c.endpoint()
	return err
}

func (c DNSChoice) endpoint() (*dohEndpoint, error) {
	id := c.Provider
	if id == "" {
		id = DNSDefault
	}
	if id != DNSCustom {
		p, ok := Preset(id)
		if !ok {
			return nil, fmt.Errorf("%w: unknown provider %q", ErrDNS, id)
		}
		return &dohEndpoint{server: p.IPs[0], path: p.Path, serverName: p.Host}, nil
	}
	return parseCustomDoH(c.CustomURL)
}

// parseCustomDoH accepts https://host[:port][/path]. The host may be a
// name or a public IP address; private, loopback and link-local
// addresses are refused (the query leaves through the node, which does not
// reach private networks). No credentials, query or fragment, no URL
// templates.
func parseCustomDoH(raw string) (*dohEndpoint, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" || len(raw) > 255 || strings.ContainsAny(raw, "{} \t\n") {
		return nil, fmt.Errorf("%w: custom DoH URL is empty, too long or a template", ErrDNS)
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" {
		return nil, fmt.Errorf("%w: custom DoH URL must be https://host[:port]/path", ErrDNS)
	}
	e := &dohEndpoint{path: u.EscapedPath()}
	if e.path == "" || e.path == "/" {
		e.path = "/dns-query"
	}
	if p := u.Port(); p != "" {
		n, err := strconv.Atoi(p)
		if err != nil || n < 1 || n > 65535 {
			return nil, fmt.Errorf("%w: port", ErrDNS)
		}
		e.port = uint16(n) //nolint:gosec // 1..65535 checked
	}
	host := strings.ToLower(u.Hostname())
	if a, err := netip.ParseAddr(host); err == nil {
		a = a.Unmap()
		if !a.IsGlobalUnicast() || a.IsPrivate() || a.IsLoopback() || a.IsLinkLocalUnicast() {
			return nil, fmt.Errorf("%w: the DoH server must have a public address", ErrDNS)
		}
		e.server = a.String()
		return e, nil
	}
	if !validHostName(host) {
		return nil, fmt.Errorf("%w: host name", ErrDNS)
	}
	e.server, e.serverName, e.byName = host, host, true
	return e, nil
}

func validHostName(h string) bool {
	if len(h) > 253 || !strings.Contains(h, ".") {
		return false
	}
	for _, l := range strings.Split(h, ".") {
		if l == "" || len(l) > 63 || l[0] == '-' || l[len(l)-1] == '-' {
			return false
		}
		for _, r := range l {
			if (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '-' {
				return false
			}
		}
	}
	return true
}

// dnsServers returns the remote DoH server (and the bootstrap server when
// the custom DoH host is a name) for the choice; legacyServer is the
// profile's remote_doh_server, used when choice is nil (callers that do not
// pass a choice keep the server-side default).
func dnsServers(choice *DNSChoice, legacyServer, detour string) ([]DNSServer, error) {
	if choice == nil {
		return []DNSServer{{Type: "https", Tag: TagDNSRemote, Server: legacyServer, Detour: detour}}, nil
	}
	e, err := choice.endpoint()
	if err != nil {
		return nil, err
	}
	s := DNSServer{Type: "https", Tag: TagDNSRemote, Server: e.server, ServerPort: e.port, Path: e.path, Detour: detour}
	if e.serverName != "" {
		s.TLS = &TLS{Enabled: true, ServerName: e.serverName}
	}
	if !e.byName {
		return []DNSServer{s}, nil
	}
	q, _ := Preset(DNSQuad9)
	s.DomainResolver = TagDNSBootstrap
	boot := DNSServer{Type: "https", Tag: TagDNSBootstrap, Server: q.IPs[0], Path: q.Path, Detour: detour,
		TLS: &TLS{Enabled: true, ServerName: q.Host}}
	return []DNSServer{s, boot}, nil
}
