// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Package profile defines the VeilOn client profile (ADR-0005): the single
// source from which sing-box client configs are generated. JSON is canonical;
// proto/veilon/profile/v1/profile.proto mirrors it for gRPC.
package profile

// SchemaVersion is the profile schema version produced by this library.
// 1.1.0 (ADR-0066): the "xhttp" transport, xhttp mode, outbound patches.
// Clients ignore unknown transports in priorities (forward compatible).
const SchemaVersion = "1.1.0"

// MinSupportedSchemaMajor is the oldest major version clients accept.
const MinSupportedSchemaMajor = 1

// TransportID identifies a transport implementation.
type TransportID string

const (
	TransportXHTTP     TransportID = "xhttp" // VLESS + REALITY + XHTTP (Xray), default (ADR-0066)
	TransportVLESS     TransportID = "vless" // VLESS + REALITY + Vision (Xray)
	TransportHysteria2 TransportID = "hysteria2"
	TransportNaive     TransportID = "naive"
)

// AllTransports lists transports in canonical order.
var AllTransports = []TransportID{TransportXHTTP, TransportVLESS, TransportHysteria2, TransportNaive}

// SupportsUDP reports whether the transport may carry UDP. Naive never does
// (ADR-0002, ADR-0004).
func (t TransportID) SupportsUDP() bool {
	switch t {
	case TransportXHTTP, TransportVLESS, TransportHysteria2:
		return true
	default:
		return false
	}
}

// Profile is the signed payload delivered to clients.
type Profile struct {
	SchemaVersion    string        `json:"schema_version"`
	MinClientVersion string        `json:"min_client_version"`
	ProfileID        string        `json:"profile_id"`
	IssuedAt         int64         `json:"issued_at"`  // unix seconds; never stored server-side
	ExpiresAt        int64         `json:"expires_at"` // unix seconds
	Subscription     Subscription  `json:"subscription"`
	Nodes            []Node        `json:"nodes"`
	Priorities       []TransportID `json:"priorities"`
	Fallback         Fallback      `json:"fallback"`
	UDPPolicy        UDPPolicy     `json:"udp_policy"`
	Routing          []RouteRule   `json:"routing,omitempty"`
	DNS              DNS           `json:"dns"`
	IPv6             IPv6Mode      `json:"ipv6"`
	API              APIEndpoints  `json:"api"`
}

// Subscription is informational for UI; enforcement happens server-side.
type Subscription struct {
	Plan              string `json:"plan"`
	Status            string `json:"status"`  // active|limited|expired|disabled
	EndsOn            string `json:"ends_on"` // YYYY-MM-DD (date only)
	TrafficLimitBytes int64  `json:"traffic_limit_bytes"`
	DeviceLimit       int    `json:"device_limit"`
}

// Node is one exit location with its enabled transports.
type Node struct {
	ID         string         `json:"id"`
	Name       string         `json:"name"`
	Region     string         `json:"region"`
	Transports NodeTransports `json:"transports"`
}

// NodeTransports holds per-transport settings; nil means not offered.
type NodeTransports struct {
	XHTTP     *VLESS     `json:"xhttp,omitempty"` // transport.type "xhttp"
	VLESS     *VLESS     `json:"vless,omitempty"`
	Hysteria2 *Hysteria2 `json:"hysteria2,omitempty"`
	Naive     *Naive     `json:"naive,omitempty"`
}

// VLESS settings (VLESS + REALITY or TLS).
type VLESS struct {
	Enabled   bool       `json:"enabled"`
	Server    string     `json:"server"`
	Port      uint16     `json:"port"`
	UUID      string     `json:"uuid"`
	Flow      string     `json:"flow,omitempty"` // "xtls-rprx-vision" or ""
	Transport VLESSWire  `json:"transport"`
	Security  string     `json:"security"` // "reality" | "tls"
	TLS       TLSClient  `json:"tls"`
	Reality   *RealityPK `json:"reality,omitempty"`
	// OutboundPatch is a JSON Merge Patch (RFC 7396) applied by the client
	// to the generated Xray outbound object (raw config editor, ADR-0067).
	OutboundPatch string `json:"outbound_patch,omitempty"`
}

// VLESSWire is the V2Ray transport under VLESS.
type VLESSWire struct {
	Type        string `json:"type"`           // tcp | xhttp | ws | grpc
	Mode        string `json:"mode,omitempty"` // xhttp: auto | packet-up | stream-up | stream-one
	Path        string `json:"path,omitempty"`
	Host        string `json:"host,omitempty"`
	ServiceName string `json:"service_name,omitempty"`
}

// TLSClient is common client TLS settings.
type TLSClient struct {
	SNI             string   `json:"sni"`
	ALPN            []string `json:"alpn,omitempty"`
	UTLSFingerprint string   `json:"utls_fingerprint,omitempty"` // e.g. "chrome"
}

// RealityPK is the REALITY client part.
type RealityPK struct {
	PublicKey string `json:"public_key"`
	ShortID   string `json:"short_id"`
}

// Hysteria2 settings.
type Hysteria2 struct {
	Enabled     bool     `json:"enabled"`
	Server      string   `json:"server"`
	Port        uint16   `json:"port"`
	HopPorts    string   `json:"hop_ports,omitempty"`    // "20000:40000"
	HopInterval string   `json:"hop_interval,omitempty"` // Go duration, e.g. "30s"
	Password    string   `json:"password"`
	ObfsType    string   `json:"obfs_type,omitempty"` // "salamander"
	ObfsPass    string   `json:"obfs_password,omitempty"`
	SNI         string   `json:"sni"`
	ALPN        []string `json:"alpn,omitempty"` // default ["h3"]
	UpMbps      int      `json:"up_mbps,omitempty"`
	DownMbps    int      `json:"down_mbps,omitempty"`
	// PinSHA256 maps to sing-box tls.certificate_public_key_sha256: base64 of
	// SHA-256 over the leaf certificate's PKIX SubjectPublicKeyInfo (verified
	// in sing-box 1.13.21 common/tls/std_client.go and end-to-end).
	PinSHA256 []string `json:"pin_sha256,omitempty"`
	// Insecure is honored only by builds compiled with the "devinsecure" tag.
	Insecure bool `json:"insecure,omitempty"`
	// OutboundPatch: JSON Merge Patch for the sing-box outbound (ADR-0067).
	OutboundPatch string `json:"outbound_patch,omitempty"`
}

// Naive settings. TCP-only by construction.
type Naive struct {
	Enabled  bool   `json:"enabled"`
	Server   string `json:"server"`
	Port     uint16 `json:"port"`
	Username string `json:"username"`
	Password string `json:"password"`
	SNI      string `json:"sni"`
	// CertificatePEM is a custom trust anchor for private test nodes. Honored
	// only by dev builds (devinsecure); release clients ignore naive when it
	// is set, because a self-signed chain changes naive's traffic profile
	// (sing-box documentation). Production nodes use publicly trusted certs.
	CertificatePEM string `json:"certificate_pem,omitempty"`
	// OutboundPatch: JSON Merge Patch for the sing-box outbound (ADR-0067).
	OutboundPatch string `json:"outbound_patch,omitempty"`
}

// Fallback configures the hysteresis controller (ADR-0004).
type Fallback struct {
	ProbeIntervalSec  int    `json:"probe_interval_sec"`
	SwitchMarginPct   int    `json:"switch_margin_pct"`
	ConsecutiveProbes int    `json:"consecutive_probes"`
	MinDwellSec       int    `json:"min_dwell_sec"`
	FailThreshold     int    `json:"fail_threshold"`
	ProbeURL          string `json:"probe_url"`
	AutoSwitch        bool   `json:"auto_switch"` // Iteration 4; MVP uses manual switching
}

// UDPPolicy decides what happens to UDP when no UDP-capable transport works.
type UDPPolicy string

const (
	UDPRejectWhenUnavailable UDPPolicy = "reject" // never leak, never route to naive
)

// IPv6Mode (ADR-0008).
type IPv6Mode string

const (
	IPv6Tunnel IPv6Mode = "tunnel"
	IPv6Block  IPv6Mode = "block"
)

// RouteRule maps traffic to an action.
type RouteRule struct {
	DomainSuffix []string `json:"domain_suffix,omitempty"`
	Domain       []string `json:"domain,omitempty"`
	IPCIDR       []string `json:"ip_cidr,omitempty"`
	ProcessName  []string `json:"process_name,omitempty"`
	PackageName  []string `json:"package_name,omitempty"` // Android apps (per-app split tunnelling)
	Action       string   `json:"action"`                 // proxy | direct | block
}

// DNS settings (ADR-0008).
type DNS struct {
	RemoteDoHServer string `json:"remote_doh_server"` // IP or host of the DoH server used through the tunnel
	Strategy        string `json:"strategy,omitempty"`
}

// APIEndpoints for reaching veilon-api under censorship (ADR-0022).
type APIEndpoints struct {
	BaseURLs []string `json:"base_urls"`
	SPKIPins []string `json:"spki_pins"` // base64(SHA-256(SPKI)); at least current + backup
}
