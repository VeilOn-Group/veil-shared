// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Package singbox contains VeilOn's own, minimal typed model of the sing-box
// configuration (pinned to sing-box 1.13.x) and the generators that build
// client configs from a profile. It deliberately does NOT import sing-box
// (GPL boundary, ADR-0000 §0.4); compatibility is enforced by running the
// pinned `sing-box check` against golden files in CI.
//
// Every field used here was verified with `sing-box check` on 1.13.21
// (unknown fields are rejected by sing-box, so the golden check is strict).
package singbox

// Config is the root object.
type Config struct {
	Log          *Log          `json:"log,omitempty"`
	DNS          *DNS          `json:"dns,omitempty"`
	Inbounds     []Inbound     `json:"inbounds,omitempty"`
	Outbounds    []Outbound    `json:"outbounds"`
	Route        *Route        `json:"route,omitempty"`
	Experimental *Experimental `json:"experimental,omitempty"`

	// patches are the profile's outbound patches (tag -> JSON Merge Patch),
	// applied when the config is marshalled (ADR-0067).
	patches map[string]string
}

// Log controls sing-box logging. Servers: Disabled=true. Clients: level warn.
type Log struct {
	Disabled  bool   `json:"disabled,omitempty"`
	Level     string `json:"level,omitempty"`
	Output    string `json:"output,omitempty"`
	Timestamp bool   `json:"timestamp,omitempty"`
}

// DNS (new server format, sing-box >= 1.12).
type DNS struct {
	Servers  []DNSServer `json:"servers"`
	Rules    []DNSRule   `json:"rules,omitempty"`
	Final    string      `json:"final,omitempty"`
	Strategy string      `json:"strategy,omitempty"`
}

// DNSServer is one resolver.
type DNSServer struct {
	Type       string `json:"type"` // https | local | quic | tls
	Tag        string `json:"tag"`
	Server     string `json:"server,omitempty"`
	ServerPort uint16 `json:"server_port,omitempty"`
	Path       string `json:"path,omitempty"` // https: DoH path
	TLS        *TLS   `json:"tls,omitempty"`
	Detour     string `json:"detour,omitempty"`
	// DomainResolver resolves a server given by name (custom DoH host).
	DomainResolver string `json:"domain_resolver,omitempty"`
	// Predefined is used by type "hosts" (sing-box 1.12+).
	Predefined map[string][]string `json:"predefined,omitempty"`
	// RoutingMark (Linux): lets the kill switch pass the "local" resolver's
	// queries for bypassed zones (ADR-0053, ADR-0064).
	RoutingMark uint32 `json:"routing_mark,omitempty"`
}

// DNSRule routes DNS queries.
type DNSRule struct {
	Domain       []string `json:"domain,omitempty"`
	DomainSuffix []string `json:"domain_suffix,omitempty"`
	RuleSet      []string `json:"rule_set,omitempty"`
	Server       string   `json:"server,omitempty"`
	Action       string   `json:"action,omitempty"`
}

// Inbound is a union of the inbound types VeilOn uses: tun (client) and
// vless/hysteria2/naive (node).
type Inbound struct {
	Type string `json:"type"`
	Tag  string `json:"tag"`

	// tun
	InterfaceName string   `json:"interface_name,omitempty"`
	Address       []string `json:"address,omitempty"`
	MTU           int      `json:"mtu,omitempty"`
	AutoRoute     bool     `json:"auto_route,omitempty"`
	StrictRoute   bool     `json:"strict_route,omitempty"`
	Stack         string   `json:"stack,omitempty"`

	// listen fields (node)
	Listen     string `json:"listen,omitempty"`
	ListenPort uint16 `json:"listen_port,omitempty"`
	Network    string `json:"network,omitempty"` // naive: "tcp"

	Users []InboundUser `json:"users,omitempty"`
	TLS   *ServerTLS    `json:"tls,omitempty"`

	// hysteria2
	UpMbps                int    `json:"up_mbps,omitempty"`
	DownMbps              int    `json:"down_mbps,omitempty"`
	Obfs                  *Obfs  `json:"obfs,omitempty"`
	IgnoreClientBandwidth bool   `json:"ignore_client_bandwidth,omitempty"`
	Masquerade            string `json:"masquerade,omitempty"`
}

// InboundUser covers vless (name+uuid+flow), hysteria2 (name+password) and
// naive (username+password). Names are node-scoped pseudonyms (ADR-0014).
type InboundUser struct {
	Name     string `json:"name,omitempty"`
	UUID     string `json:"uuid,omitempty"`
	Flow     string `json:"flow,omitempty"`
	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"`
}

// ServerTLS is inbound TLS (certificate files or REALITY).
type ServerTLS struct {
	Enabled         bool           `json:"enabled"`
	ServerName      string         `json:"server_name,omitempty"`
	ALPN            []string       `json:"alpn,omitempty"`
	CertificatePath string         `json:"certificate_path,omitempty"`
	KeyPath         string         `json:"key_path,omitempty"`
	Reality         *RealityServer `json:"reality,omitempty"`
}

// RealityServer is the REALITY server part.
type RealityServer struct {
	Enabled    bool             `json:"enabled"`
	Handshake  RealityHandshake `json:"handshake"`
	PrivateKey string           `json:"private_key"`
	ShortID    []string         `json:"short_id"`
	// MaxTimeDifference rejects clients whose clock is further off (e.g.
	// "1m"); empty = no check.
	MaxTimeDifference string `json:"max_time_difference,omitempty"`
}

// RealityHandshake is the fallback destination for unauthenticated clients.
type RealityHandshake struct {
	Server     string `json:"server"`
	ServerPort uint16 `json:"server_port"`
}

// Outbound is a union of the outbound types VeilOn uses.
type Outbound struct {
	Type string `json:"type"`
	Tag  string `json:"tag"`

	Server     string `json:"server,omitempty"`
	ServerPort uint16 `json:"server_port,omitempty"`

	// vless
	UUID           string     `json:"uuid,omitempty"`
	Flow           string     `json:"flow,omitempty"`
	PacketEncoding string     `json:"packet_encoding,omitempty"`
	Transport      *Transport `json:"transport,omitempty"`

	// hysteria2
	ServerPorts []string `json:"server_ports,omitempty"`
	HopInterval string   `json:"hop_interval,omitempty"`
	UpMbps      int      `json:"up_mbps,omitempty"`
	DownMbps    int      `json:"down_mbps,omitempty"`
	Obfs        *Obfs    `json:"obfs,omitempty"`

	// hysteria2 / naive / socks
	Password string `json:"password,omitempty"`
	Username string `json:"username,omitempty"`

	// naive: QUIC must be explicitly false (ADR-0002), so it is a pointer to
	// keep `false` in the output instead of dropping it.
	QUIC *bool `json:"quic,omitempty"`

	// socks (external naive fallback)
	Version string `json:"version,omitempty"`
	Network string `json:"network,omitempty"`

	TLS *TLS `json:"tls,omitempty"`

	// selector
	Outbounds                 []string `json:"outbounds,omitempty"`
	Default                   string   `json:"default,omitempty"`
	InterruptExistConnections bool     `json:"interrupt_exist_connections,omitempty"`
	// RoutingMark (Linux): SO_MARK on direct connections, so the OS kill
	// switch can let split-tunnel "direct" traffic out (ADR-0053).
	RoutingMark uint32 `json:"routing_mark,omitempty"`
}

// Transport is the V2Ray transport for VLESS.
type Transport struct {
	Type        string            `json:"type"`
	Path        string            `json:"path,omitempty"`
	Headers     map[string]string `json:"headers,omitempty"`
	ServiceName string            `json:"service_name,omitempty"`
}

// Obfs for hysteria2.
type Obfs struct {
	Type     string `json:"type"`
	Password string `json:"password"`
}

// TLS (client).
type TLS struct {
	Enabled    bool   `json:"enabled"`
	ServerName string `json:"server_name,omitempty"`
	// Certificate is a custom trust anchor as PEM lines (sing-box Listable).
	// Used only for naive in dev builds (private test CAs, ADR-0052).
	Certificate                []string `json:"certificate,omitempty"`
	ALPN                       []string `json:"alpn,omitempty"`
	Insecure                   bool     `json:"insecure,omitempty"`
	CertificatePublicKeySHA256 []string `json:"certificate_public_key_sha256,omitempty"`
	UTLS                       *UTLS    `json:"utls,omitempty"`
	Reality                    *Reality `json:"reality,omitempty"`
}

// UTLS fingerprinting.
type UTLS struct {
	Enabled     bool   `json:"enabled"`
	Fingerprint string `json:"fingerprint,omitempty"`
}

// Reality (client).
type Reality struct {
	Enabled   bool   `json:"enabled"`
	PublicKey string `json:"public_key"`
	ShortID   string `json:"short_id,omitempty"`
}

// Route section.
type Route struct {
	Rules                 []Rule    `json:"rules"`
	RuleSet               []RuleSet `json:"rule_set,omitempty"`
	Final                 string    `json:"final"`
	AutoDetectInterface   bool      `json:"auto_detect_interface,omitempty"`
	DefaultDomainResolver string    `json:"default_domain_resolver,omitempty"`
}

// Rule is a route rule (subset).
type Rule struct {
	Inbound      []string `json:"inbound,omitempty"`
	AuthUser     []string `json:"auth_user,omitempty"`
	Protocol     string   `json:"protocol,omitempty"`
	Network      string   `json:"network,omitempty"`
	IPVersion    int      `json:"ip_version,omitempty"`
	IPIsPrivate  bool     `json:"ip_is_private,omitempty"`
	Domain       []string `json:"domain,omitempty"`
	DomainSuffix []string `json:"domain_suffix,omitempty"`
	RuleSet      []string `json:"rule_set,omitempty"`
	IPCIDR       []string `json:"ip_cidr,omitempty"`
	Port         []uint16 `json:"port,omitempty"`
	ProcessName  []string `json:"process_name,omitempty"`
	ProcessPath  []string `json:"process_path,omitempty"`
	PackageName  []string `json:"package_name,omitempty"` // Android per-app rules
	Action       string   `json:"action,omitempty"`       // route (default) | reject | sniff | hijack-dns
	Outbound     string   `json:"outbound,omitempty"`
}

// RuleSet is a route rule set; VeilOn uses only local binary (.srs) files
// shipped with the client (no remote downloads, ADR-0068).
type RuleSet struct {
	Type   string `json:"type"`   // local
	Tag    string `json:"tag"`    //
	Format string `json:"format"` // binary
	Path   string `json:"path"`
}

// Experimental section.
type Experimental struct {
	ClashAPI  *ClashAPI  `json:"clash_api,omitempty"`
	CacheFile *CacheFile `json:"cache_file,omitempty"`
	V2RayAPI  *V2RayAPI  `json:"v2ray_api,omitempty"`
}

// V2RayAPI exposes per-user traffic counters on loopback (node only,
// ADR-0013). Requires a sing-box build with the with_v2ray_api tag.
type V2RayAPI struct {
	Listen string     `json:"listen"`
	Stats  V2RayStats `json:"stats"`
}

// V2RayStats selects counters. Only users are counted: no inbound/outbound
// counters, nothing per destination.
type V2RayStats struct {
	Enabled bool     `json:"enabled"`
	Users   []string `json:"users,omitempty"`
}

// ClashAPI is bound to loopback with a per-start random secret (ADR-0003).
type ClashAPI struct {
	ExternalController string `json:"external_controller"`
	Secret             string `json:"secret"`
}

// CacheFile persists only the selected outbound (ADR-0003). StoreFakeIP and
// StoreRDRC are always false: DNS answers must never be written to disk.
type CacheFile struct {
	Enabled     bool   `json:"enabled"`
	Path        string `json:"path,omitempty"`
	StoreFakeIP bool   `json:"store_fakeip"`
	StoreRDRC   bool   `json:"store_rdrc"`
}
