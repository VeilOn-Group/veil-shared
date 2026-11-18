// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package singbox

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/veilon/veil-shared/pkg/profile"
	"github.com/veilon/veil-shared/pkg/tmpl"
)

// Fixed tags used by veilond's controller.
const (
	TagTun         = "tun-in"
	TagXHTTP       = "xhttp"
	TagVLESS       = "vless"
	TagHysteria2   = "hy2"
	TagNaive       = "naive"
	TagSelectorTCP = "sel-tcp"
	TagSelectorUDP = "sel-udp"
	TagDirect      = "direct"
	TagDNSRemote   = "dns-remote"
	TagDNSLocal    = "dns-local"
	TagDNSPinned   = "dns-pinned"
	TagProbeIn     = "probe-in"
)

// TagFor maps a transport to its outbound tag.
func TagFor(t profile.TransportID) string {
	switch t {
	case profile.TransportXHTTP:
		return TagXHTTP
	case profile.TransportVLESS:
		return TagVLESS
	case profile.TransportHysteria2:
		return TagHysteria2
	case profile.TransportNaive:
		return TagNaive
	}
	return ""
}

// ExternalSOCKS is the local endpoint of a transport served by another
// process: the external naive fallback or Xray for VLESS.
type ExternalSOCKS struct {
	Port     uint16
	Username string
	Password string
	// ProcessPath is the absolute path of the binary. Its own traffic to
	// the node must bypass the TUN, otherwise it would loop through
	// sing-box back into itself.
	ProcessPath string
}

// RuleSetFile is a local binary rule set shipped with the client.
type RuleSetFile struct {
	Tag  string
	Path string
}

// ClientOptions are runtime parameters chosen by veilond (not part of the
// signed profile).
type ClientOptions struct {
	NodeID         string // empty = first node
	TunName        string
	TunMTU         int
	TunStack       string // system | gvisor | mixed
	ClashAPIListen string // 127.0.0.1:<random>
	ClashAPISecret string // random per start
	CacheFilePath  string
	LogLevel       string // warn (default) | error
	// Disabled transports (user toggles in UI).
	Disabled map[profile.TransportID]bool
	// NaiveExternal switches naive to the SOCKS fallback mode.
	NaiveExternal *ExternalSOCKS
	// Xray holds the local endpoints of the Xray process for the VLESS
	// transports (xhttp, vless). sing-box 1.13 has no XHTTP and its REALITY
	// client is refused by current Xray nodes, so a VLESS transport without
	// an endpoint here is not offered.
	Xray map[profile.TransportID]*ExternalSOCKS
	// AllowLAN routes private ranges directly (default true in UI).
	AllowLAN bool
	// AllowInsecure is only set by builds with the devinsecure tag.
	AllowInsecure bool
	// ProbeListen enables the health-probe inbound: an authenticated local
	// SOCKS/HTTP proxy where the user name selects the transport outbound
	// ("vless", "hysteria2", "naive"), so veilond measures the real data path
	// of every transport (the Clash delay test fails for Hysteria 2 in
	// sing-box 1.13). Loopback only.
	ProbeListen   string
	ProbePassword string
	// DirectMark (Linux only) marks split-tunnel "direct" connections so the
	// nftables kill switch can allow exactly them. 0 = unset.
	DirectMark uint32
	// PinnedHosts maps node and API host names to addresses that veilond
	// resolved before the tunnel came up. When set, the core resolves server
	// names only from this map, never through the system resolver, which the
	// kill switch blocks.
	PinnedHosts map[string][]string
	// UserRules are the user's split-tunnelling rules from the client
	// settings; they take precedence over the profile's routing rules.
	UserRules []profile.RouteRule
	// BypassSuffixes are domain zones sent around the VPN (automatic split
	// tunnelling), e.g. RUZones. They rank below UserRules (a user
	// rule can still force a single .ru site through the VPN) and above the
	// profile's rules. DNS for these zones is answered by the local
	// resolver, outside the tunnel, so CDNs pick local addresses.
	BypassSuffixes []string
	// BypassRuleSets are local rule sets (geosite-category-ru) with the same
	// role as BypassSuffixes. Both are applied: the suffixes
	// still work if a rule set file is missing.
	BypassRuleSets []RuleSetFile
	// HostNoIPv6 is set (by veilond, Linux only) when the kernel has no IPv6
	// stack (ipv6.disable=1, IPv6-less containers). Then:
	//   - the TUN gets only an IPv4 address (otherwise: "add address .../126:
	//     operation not supported");
	//   - strict_route is off: on Linux, sing-tun v0.8.15 strict_route only
	//     installs an "unreachable" rule for the missing address family
	//     (tun_linux.go), which fails with EAFNOSUPPORT when IPv6 does not
	//     exist, and there is no IPv6 to leak;
	//   - IPv6 is still rejected by a route rule (defence in depth).
	// Never set it on Windows/macOS, where
	// strict_route has other effects.
	HostNoIPv6 bool
	// DNS is the user's DoH choice. nil keeps the profile's
	// remote_doh_server (older callers).
	DNS *DNSChoice
}

// RUZones are the zones of the automatic split tunnelling preset:
// every top-level domain of geosite category-ru
// (sing-geosite rule-set at the pinned commit): .ru, .su, .рф and the other
// Russian-language and Russian city/region zones. The rule set itself adds
// Russian services on other zones; these suffixes keep the zones bypassed
// even without the rule set file.
var RUZones = []string{
	"ru", "su", "xn--p1ai", // .рф
	"xn--p1acf",    // .рус
	"xn--80adxhks", // .москва
	"xn--80asehdb", // .онлайн
	"xn--80aswg",   // .сайт
	"xn--c1avg",    // .орг
	"xn--d1acj3b",  // .дети
	"moscow", "tatar", "yandex",
}

// RuleSetCategoryRU is the tag of the bundled geosite-category-ru rule set.
const RuleSetCategoryRU = "geosite-category-ru"

var reTag = regexp.MustCompile(`^[a-z0-9-]{1,64}$`)

var reZone = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$`)

// Errors.
var (
	ErrNoNode       = errors.New("singbox: node not found in profile")
	ErrNoTransports = errors.New("singbox: no enabled transports")
	ErrBadOptions   = errors.New("singbox: invalid client options")
)

// BuildClient generates a client config for one node of a verified profile.
func BuildClient(p *profile.Profile, o ClientOptions) (*Config, error) {
	if o.ClashAPIListen == "" || o.ClashAPISecret == "" || !strings.HasPrefix(o.ClashAPIListen, "127.0.0.1:") {
		return nil, fmt.Errorf("%w: clash api must listen on 127.0.0.1 with a secret", ErrBadOptions)
	}
	if o.LogLevel == "" {
		o.LogLevel = "warn"
	}
	if o.LogLevel != "warn" && o.LogLevel != "error" {
		return nil, fmt.Errorf("%w: log level %q not allowed in client builds", ErrBadOptions, o.LogLevel)
	}
	if o.TunName == "" {
		o.TunName = "veilon0"
	}
	if o.TunMTU == 0 {
		o.TunMTU = 1400
	}
	if o.TunStack == "" {
		o.TunStack = "mixed"
	}
	if len(o.BypassSuffixes) > 64 {
		return nil, fmt.Errorf("%w: too many bypass zones", ErrBadOptions)
	}
	for _, z := range o.BypassSuffixes {
		if !reZone.MatchString(z) {
			return nil, fmt.Errorf("%w: bypass zone %q", ErrBadOptions, z)
		}
	}
	if len(o.BypassRuleSets) > 8 {
		return nil, fmt.Errorf("%w: too many rule sets", ErrBadOptions)
	}
	for _, r := range o.BypassRuleSets {
		if !reTag.MatchString(r.Tag) || r.Path == "" || !strings.HasSuffix(r.Path, ".srs") {
			return nil, fmt.Errorf("%w: rule set %q", ErrBadOptions, r.Tag)
		}
	}
	node, err := pickNode(p, o.NodeID)
	if err != nil {
		return nil, err
	}

	outs, enabled, err := transportOutbounds(node, o)
	if err != nil {
		return nil, err
	}
	order := priorityOrder(p.Priorities, enabled)
	if len(order) == 0 {
		return nil, ErrNoTransports
	}

	var tcpTags, udpTags []string
	for _, t := range order {
		tcpTags = append(tcpTags, TagFor(t))
		if t.SupportsUDP() {
			udpTags = append(udpTags, TagFor(t))
		}
	}
	outs = append(outs, Outbound{Type: "selector", Tag: TagSelectorTCP, Outbounds: tcpTags, Default: tcpTags[0], InterruptExistConnections: true})
	if len(udpTags) > 0 {
		outs = append(outs, Outbound{Type: "selector", Tag: TagSelectorUDP, Outbounds: udpTags, Default: udpTags[0], InterruptExistConnections: true})
	}
	outs = append(outs, Outbound{Type: "direct", Tag: TagDirect, RoutingMark: o.DirectMark})

	remote, err := dnsServers(o.DNS, p.DNS.RemoteDoHServer, TagSelectorTCP)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrBadOptions, err)
	}
	cfg := &Config{
		Log: &Log{Level: o.LogLevel},
		DNS: &DNS{
			Servers:  append(remote, DNSServer{Type: "local", Tag: TagDNSLocal, RoutingMark: o.DirectMark}),
			Final:    TagDNSRemote,
			Strategy: p.DNS.Strategy,
		},
		Inbounds: []Inbound{{
			Type: "tun", Tag: TagTun, InterfaceName: o.TunName,
			// Both families always enter the TUN: IPv6 is either tunneled or
			// rejected, never leaked around the tunnel.
			Address:   tunAddresses(o.HostNoIPv6),
			MTU:       o.TunMTU,
			AutoRoute: true, StrictRoute: !o.HostNoIPv6, Stack: o.TunStack,
		}},
		Outbounds: outs,
		Route: &Route{
			Rules:                 routeRules(p, o, len(udpTags) > 0, outs),
			Final:                 TagSelectorTCP,
			AutoDetectInterface:   true,
			DefaultDomainResolver: TagDNSLocal,
		},
		Experimental: &Experimental{
			ClashAPI: &ClashAPI{ExternalController: o.ClashAPIListen, Secret: o.ClashAPISecret},
		},
	}
	if len(o.BypassRuleSets) > 0 || len(o.BypassSuffixes) > 0 {
		// A user rule that sends a bypassed site through the VPN also
		// resolves it through the tunnel (its name does not reach the ISP's
		// resolver).
		for _, r := range o.UserRules {
			if r.Action == "proxy" && (len(r.Domain) > 0 || len(r.DomainSuffix) > 0) {
				cfg.DNS.Rules = append(cfg.DNS.Rules, DNSRule{Domain: r.Domain, DomainSuffix: r.DomainSuffix, Server: TagDNSRemote})
			}
		}
	}
	for _, r := range o.BypassRuleSets {
		cfg.Route.RuleSet = append(cfg.Route.RuleSet, RuleSet{Type: "local", Tag: r.Tag, Format: "binary", Path: r.Path})
		cfg.DNS.Rules = append(cfg.DNS.Rules, DNSRule{RuleSet: []string{r.Tag}, Server: TagDNSLocal})
	}
	if len(o.BypassSuffixes) > 0 {
		cfg.DNS.Rules = append(cfg.DNS.Rules, DNSRule{DomainSuffix: o.BypassSuffixes, Server: TagDNSLocal})
	}
	if o.ProbeListen != "" {
		host, port, err := net.SplitHostPort(o.ProbeListen)
		pn, perr := strconv.Atoi(port)
		if err != nil || perr != nil || host != "127.0.0.1" || pn < 1 || pn > 65535 || len(o.ProbePassword) < 16 {
			return nil, fmt.Errorf("%w: probe inbound must be 127.0.0.1:<port> with a password", ErrBadOptions)
		}
		var users []InboundUser
		for _, ob := range outs {
			if isTransportTag(ob.Tag) {
				users = append(users, InboundUser{Username: ob.Tag, Password: o.ProbePassword})
			}
		}
		// "direct" lets veilond reach the VeilOn API outside the tunnel when
		// every transport is down (e.g. node keys rotated): it fetches the new
		// profile that way. Loopback, per-session password.
		users = append(users, InboundUser{Username: TagDirect, Password: o.ProbePassword})
		cfg.Inbounds = append(cfg.Inbounds, Inbound{Type: "mixed", Tag: TagProbeIn, Listen: host, ListenPort: uint16(pn), Users: users}) //nolint:gosec // 1..65535 checked above
	}
	if len(o.PinnedHosts) > 0 {
		cfg.DNS.Servers = append(cfg.DNS.Servers, DNSServer{Type: "hosts", Tag: TagDNSPinned, Predefined: o.PinnedHosts})
		cfg.Route.DefaultDomainResolver = TagDNSPinned
	}
	if o.CacheFilePath != "" {
		cfg.Experimental.CacheFile = &CacheFile{Enabled: true, Path: o.CacheFilePath}
	}
	if err := AssertClientNoLog(cfg); err != nil {
		return nil, err
	}
	for _, x := range []struct {
		tag   string
		patch string
		on    bool
	}{
		{TagHysteria2, patchOf(node.Transports.Hysteria2), enabled[profile.TransportHysteria2]},
		{TagNaive, patchOfNaive(node.Transports.Naive), enabled[profile.TransportNaive] && o.NaiveExternal == nil},
	} {
		if x.patch != "" && x.on {
			if cfg.patches == nil {
				cfg.patches = map[string]string{}
			}
			cfg.patches[x.tag] = x.patch
		}
	}
	if _, err := cfg.MarshalJSON(); err != nil {
		return nil, err
	}
	return cfg, nil
}

func patchOf(h *profile.Hysteria2) string {
	if h == nil {
		return ""
	}
	return h.OutboundPatch
}

func patchOfNaive(n *profile.Naive) string {
	if n == nil {
		return ""
	}
	return n.OutboundPatch
}

// MarshalJSON renders the config and applies the outbound patches: each
// patch is merged into the outbound with its tag (RFC 7396), keeping the
// tag and type, and the result must still satisfy AssertClientNoLog.
func (c Config) MarshalJSON() ([]byte, error) {
	type plain Config
	raw, err := json.Marshal(plain(c))
	if err != nil || len(c.patches) == 0 {
		return raw, err
	}
	doc, err := tmpl.Parse(raw)
	if err != nil {
		return nil, err
	}
	for _, ob := range tmpl.Objects(doc, "outbounds") {
		tag, _ := ob["tag"].(string)
		p, ok := c.patches[tag]
		if !ok {
			continue
		}
		pd, err := tmpl.Parse([]byte(p))
		if err != nil {
			return nil, fmt.Errorf("%w: outbound patch for %s: %w", ErrBadOptions, tag, err)
		}
		typ := ob["type"]
		merged := tmpl.MergePatch(ob, pd)
		merged["tag"], merged["type"] = tag, typ
		for k := range ob {
			delete(ob, k)
		}
		for k, v := range merged {
			ob[k] = v
		}
	}
	out, err := json.Marshal(doc)
	if err != nil {
		return nil, err
	}
	var check plain
	if err := json.Unmarshal(out, &check); err != nil {
		return nil, fmt.Errorf("%w: patched config: %w", ErrBadOptions, err)
	}
	cc := Config(check)
	if err := AssertClientNoLog(&cc); err != nil {
		return nil, err
	}
	return out, nil
}

func tunAddresses(noIPv6 bool) []string {
	if noIPv6 {
		return []string{"172.19.0.1/30"}
	}
	return []string{"172.19.0.1/30", "fdfe:dcba:9876::1/126"}
}

func pickNode(p *profile.Profile, id string) (*profile.Node, error) {
	if len(p.Nodes) == 0 {
		return nil, ErrNoNode
	}
	if id == "" {
		return &p.Nodes[0], nil
	}
	for i := range p.Nodes {
		if p.Nodes[i].ID == id {
			return &p.Nodes[i], nil
		}
	}
	return nil, ErrNoNode
}

func priorityOrder(prio []profile.TransportID, enabled map[profile.TransportID]bool) []profile.TransportID {
	var out []profile.TransportID
	seen := map[profile.TransportID]bool{}
	for _, t := range prio {
		if enabled[t] && !seen[t] {
			out = append(out, t)
			seen[t] = true
		}
	}
	for _, t := range profile.AllTransports { // enabled but missing from priorities: append
		if enabled[t] && !seen[t] {
			out = append(out, t)
		}
	}
	return out
}

func isTransportTag(tag string) bool {
	switch tag {
	case TagXHTTP, TagVLESS, TagHysteria2, TagNaive:
		return true
	}
	return false
}

func transportOutbounds(n *profile.Node, o ClientOptions) ([]Outbound, map[profile.TransportID]bool, error) {
	var outs []Outbound
	enabled := map[profile.TransportID]bool{}
	tr := n.Transports
	for _, x := range []struct {
		id profile.TransportID
		v  *profile.VLESS
	}{{profile.TransportXHTTP, tr.XHTTP}, {profile.TransportVLESS, tr.VLESS}} {
		ext := o.Xray[x.id]
		if x.v == nil || !x.v.Enabled || o.Disabled[x.id] || ext == nil {
			continue
		}
		outs = append(outs, XrayOutbound(TagFor(x.id), ext))
		enabled[x.id] = true
	}
	if h := tr.Hysteria2; h != nil && h.Enabled && !o.Disabled[profile.TransportHysteria2] {
		ob, err := Hysteria2Outbound(h, o.AllowInsecure)
		if err != nil {
			return nil, nil, err
		}
		outs = append(outs, ob)
		enabled[profile.TransportHysteria2] = true
	}
	// A naive entry carrying a private trust anchor is usable only in dev
	// builds; release builds skip it instead of failing the whole config.
	if nv := tr.Naive; nv != nil && nv.Enabled && !o.Disabled[profile.TransportNaive] && (nv.CertificatePEM == "" || o.AllowInsecure) {
		outs = append(outs, NaiveOutbound(nv, o.NaiveExternal))
		enabled[profile.TransportNaive] = true
	}
	return outs, enabled, nil
}

// XrayOutbound hands a VLESS transport to the local Xray process: SOCKS5
// with a per-session password, TCP and UDP (Xray carries UDP as XUDP).
func XrayOutbound(tag string, ext *ExternalSOCKS) Outbound {
	return Outbound{
		Type: "socks", Tag: tag, Server: "127.0.0.1", ServerPort: ext.Port, Version: "5",
		Username: ext.Username, Password: ext.Password,
	}
}

// Hysteria2Outbound builds the Hysteria 2 outbound.
func Hysteria2Outbound(h *profile.Hysteria2, allowInsecure bool) (Outbound, error) {
	if h.Insecure && !allowInsecure {
		return Outbound{}, fmt.Errorf("%w: hysteria2 insecure is only allowed in dev builds", ErrBadOptions)
	}
	alpn := h.ALPN
	if len(alpn) == 0 {
		alpn = []string{"h3"}
	}
	ob := Outbound{
		Type: "hysteria2", Tag: TagHysteria2, Server: h.Server, ServerPort: h.Port,
		HopInterval: h.HopInterval, UpMbps: h.UpMbps, DownMbps: h.DownMbps, Password: h.Password,
		TLS: &TLS{Enabled: true, ServerName: h.SNI, ALPN: alpn, Insecure: h.Insecure && allowInsecure, CertificatePublicKeySHA256: h.PinSHA256},
	}
	if h.HopPorts != "" {
		ob.ServerPorts = []string{h.HopPorts}
	}
	if h.ObfsType == "salamander" {
		ob.Obfs = &Obfs{Type: "salamander", Password: h.ObfsPass}
	}
	return ob, nil
}

// NaiveOutbound builds the naive outbound in-tree (HTTP/2 only), or the SOCKS
// fallback to an external naive process. Either way TCP-only.
func NaiveOutbound(n *profile.Naive, ext *ExternalSOCKS) Outbound {
	if ext != nil {
		return Outbound{
			Type: "socks", Tag: TagNaive, Server: "127.0.0.1", ServerPort: ext.Port, Version: "5",
			Username: ext.Username, Password: ext.Password, Network: "tcp",
		}
	}
	f := false
	ob := Outbound{
		Type: "naive", Tag: TagNaive, Server: n.Server, ServerPort: n.Port,
		Username: n.Username, Password: n.Password, QUIC: &f,
		TLS: &TLS{Enabled: true, ServerName: n.SNI},
	}
	if n.CertificatePEM != "" {
		// sing-box takes PEM as a list of lines.
		ob.TLS.Certificate = strings.Split(strings.TrimSpace(n.CertificatePEM), "\n")
	}
	return ob
}

func routeRules(p *profile.Profile, o ClientOptions, haveUDP bool, outbounds []Outbound) []Rule {
	rules := []Rule{}
	var procs []string
	if o.NaiveExternal != nil && o.NaiveExternal.ProcessPath != "" {
		procs = append(procs, o.NaiveExternal.ProcessPath)
	}
	for _, t := range []profile.TransportID{profile.TransportXHTTP, profile.TransportVLESS} {
		if x := o.Xray[t]; x != nil && x.ProcessPath != "" && !slices.Contains(procs, x.ProcessPath) {
			procs = append(procs, x.ProcessPath)
		}
	}
	if len(procs) > 0 {
		rules = append(rules, Rule{ProcessPath: procs, Outbound: TagDirect})
	}
	if o.ProbeListen != "" {
		for _, ob := range outbounds {
			if isTransportTag(ob.Tag) {
				rules = append(rules, Rule{Inbound: []string{TagProbeIn}, AuthUser: []string{ob.Tag}, Outbound: ob.Tag})
			}
		}
		rules = append(rules, Rule{Inbound: []string{TagProbeIn}, AuthUser: []string{TagDirect}, Outbound: TagDirect})
		rules = append(rules, Rule{Inbound: []string{TagProbeIn}, Action: "reject"})
	}
	rules = append(rules,
		Rule{Action: "sniff"},
		Rule{Protocol: "dns", Action: "hijack-dns"},
	)
	if p.IPv6 == profile.IPv6Block || o.HostNoIPv6 {
		rules = append(rules, Rule{IPVersion: 6, Action: "reject"})
	}
	bypass := bypassRules(o)
	for i, r := range append(append([]profile.RouteRule(nil), o.UserRules...), p.Routing...) {
		if i == len(o.UserRules) {
			rules = append(rules, bypass...)
		}
		rule := Rule{Domain: r.Domain, DomainSuffix: r.DomainSuffix, IPCIDR: r.IPCIDR, ProcessName: r.ProcessName, PackageName: r.PackageName}
		switch r.Action {
		case "direct":
			rule.Outbound = TagDirect
		case "block":
			rule.Action = "reject"
		default:
			rule.Outbound = TagSelectorTCP
		}
		rules = append(rules, rule)
	}
	if len(p.Routing) == 0 {
		rules = append(rules, bypass...)
	}
	if o.AllowLAN {
		rules = append(rules, Rule{IPIsPrivate: true, Outbound: TagDirect})
	}
	if haveUDP {
		rules = append(rules, Rule{Network: "udp", Outbound: TagSelectorUDP})
	} else {
		// No UDP-capable transport: reject UDP (QUIC falls back to TCP fast);
		// never route UDP into naive and never leak it direct.
		rules = append(rules, Rule{Network: "udp", Action: "reject"})
	}
	return rules
}

// bypassRules sends the automatic split-tunnelling set around the VPN:
// one rule per rule set and one for the suffixes (separate rules, so each
// matches on its own).
func bypassRules(o ClientOptions) []Rule {
	var out []Rule
	for _, r := range o.BypassRuleSets {
		out = append(out, Rule{RuleSet: []string{r.Tag}, Outbound: TagDirect})
	}
	if len(o.BypassSuffixes) > 0 {
		out = append(out, Rule{DomainSuffix: o.BypassSuffixes, Outbound: TagDirect})
	}
	return out
}
