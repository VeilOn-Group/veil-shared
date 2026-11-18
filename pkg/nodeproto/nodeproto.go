// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Package nodeproto is the wire format between veilon-api (node API) and
// veilon-node-agent. JSON over HTTPS with mutual TLS.
package nodeproto

import "github.com/veilon/veil-shared/pkg/singbox"

// Paths.
const (
	PathEnroll  = "/node/v1/enroll"
	PathDesired = "/node/v1/desired"
	PathReport  = "/node/v1/report"
)

// EnrollRequest exchanges a one-time token and a CSR for a client certificate.
type EnrollRequest struct {
	Token string `json:"token"`
	CSR   string `json:"csr"` // PEM, ECDSA P-256/P-384
}

// EnrollResponse carries the agent certificate and the node CA.
type EnrollResponse struct {
	NodeID      string `json:"node_id"`
	Certificate string `json:"certificate"` // PEM
	CA          string `json:"ca"`          // PEM
}

// NodeParams is the server-managed part of a node's sing-box spec.
type NodeParams struct {
	ID                string   `json:"id"`
	Domain            string   `json:"domain"`
	TCPPort           int      `json:"tcp_port"`
	UDPPort           int      `json:"udp_port"`
	NaivePort         int      `json:"naive_port"`
	Transports        []string `json:"transports"`
	Status            string   `json:"status"`
	RealityPrivateKey string   `json:"reality_private_key"`
	RealityShortID    string   `json:"reality_short_id"`
	Hy2ObfsPassword   string   `json:"hy2_obfs_password"`
	Hy2UpMbps         int      `json:"hy2_up_mbps"`
	Hy2DownMbps       int      `json:"hy2_down_mbps"`
	BlockPorts        []uint16 `json:"block_ports"`

	// Transport editor options. Zero values keep the previous
	// behaviour, so older agents and servers interoperate.
	RealityShortIDs          []string `json:"reality_short_ids,omitempty"` // first = RealityShortID
	RealityMaxTimeDiff       string   `json:"reality_max_time_diff,omitempty"`
	VLESSFlow                string   `json:"vless_flow,omitempty"` // "" = xtls-rprx-vision | "none"
	Hy2NoObfs                bool     `json:"hy2_no_obfs,omitempty"`
	Hy2IgnoreClientBandwidth bool     `json:"hy2_ignore_client_bandwidth,omitempty"`
	Hy2Masquerade            string   `json:"hy2_masquerade,omitempty"`

	// Managed TLS: the node domain certificate and key, uploaded
	// in the panel and stored encrypted; the agent writes them to its tmpfs
	// runtime dir. Empty = the agent uses cert_file/key_file from its config.
	TLSCertPEM string `json:"tls_cert_pem,omitempty"`
	TLSKeyPEM  string `json:"tls_key_pem,omitempty"`

	// XHTTP: VLESS over XHTTP behind the same REALITY port.
	XHTTPPath string `json:"xhttp_path,omitempty"`
	XHTTPMode string `json:"xhttp_mode,omitempty"` // default "auto"

	// Raw config templates: custom node configs with
	// "$veilon:<name>" tokens; empty = the built-in templates.
	XrayTemplate    string `json:"xray_template,omitempty"`
	SingboxTemplate string `json:"singbox_template,omitempty"`

	// ACMEHTTP01 are pending ACME HTTP-01 challenges (token -> key
	// authorisation): the agent serves them on port 80 while the
	// map is not empty, and nothing else.
	ACMEHTTP01 map[string]string `json:"acme_http01,omitempty"`
}

// ShortIDs returns the accepted REALITY short ids (first = current).
func (p NodeParams) ShortIDs() []string {
	if len(p.RealityShortIDs) > 0 {
		return p.RealityShortIDs
	}
	return []string{p.RealityShortID}
}

// Desired is what an agent must run.
type Desired struct {
	Revision string             `json:"revision"`
	Node     NodeParams         `json:"node"`
	Users    []singbox.NodeUser `json:"users"`
}

// UserDelta is one user's traffic since the previous report.
type UserDelta struct {
	Up   uint64 `json:"up"`
	Down uint64 `json:"down"`
}

// ReportRequest is sent periodically by the agent.
type ReportRequest struct {
	Revision   string               `json:"revision"`
	Compliance map[string]any       `json:"compliance"`
	Deltas     map[string]UserDelta `json:"deltas"`
	// FailedRevision is a desired revision the agent refused or rolled back
	// (sing-box check failed, or the core died after the reload); the node
	// keeps serving Revision. ApplyError is a short, sanitised reason.
	FailedRevision string `json:"failed_revision,omitempty"`
	ApplyError     string `json:"apply_error,omitempty"`
}

// Has reports whether the node offers transport t.
func (p NodeParams) Has(t string) bool {
	for _, x := range p.Transports {
		if x == t {
			return true
		}
	}
	return false
}
