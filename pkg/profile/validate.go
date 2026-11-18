// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package profile

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var (
	uuidRe    = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	shortIDRe = regexp.MustCompile(`^[0-9a-f]{0,16}$`)
	hostRe    = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9.-]{0,251}[a-zA-Z0-9])?$`)
	hopRe     = regexp.MustCompile(`^(\d{1,5}):(\d{1,5})$`)
	dateRe    = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}$`)
	// xhttpPathRe matches xray.ValidXHTTPPath.
	xhttpPathRe = regexp.MustCompile(`^/[A-Za-z0-9._~/-]{1,63}$`)
)

// ValidationError collects all problems so callers can show them at once.
type ValidationError struct{ Problems []string }

func (e *ValidationError) Error() string {
	return "invalid profile: " + strings.Join(e.Problems, "; ")
}

type collector struct{ problems []string }

func (c *collector) addf(format string, a ...any) {
	c.problems = append(c.problems, fmt.Sprintf(format, a...))
}

// Validate checks structural and security invariants. now is injected for tests.
func (p *Profile) Validate(now time.Time) error {
	c := &collector{}
	major, err := SemverMajor(p.SchemaVersion)
	switch {
	case err != nil:
		c.addf("schema_version: %v", err)
	case major < MinSupportedSchemaMajor:
		c.addf("schema_version %s is older than supported major %d", p.SchemaVersion, MinSupportedSchemaMajor)
	}
	if _, err := ParseSemver(p.MinClientVersion); err != nil {
		c.addf("min_client_version: %v", err)
	}
	if p.ProfileID == "" {
		c.addf("profile_id is empty")
	}
	if p.ExpiresAt <= p.IssuedAt {
		c.addf("expires_at must be after issued_at")
	}
	if now.Unix() >= p.ExpiresAt {
		c.addf("profile expired")
	}
	if p.Subscription.EndsOn != "" && !dateRe.MatchString(p.Subscription.EndsOn) {
		c.addf("subscription.ends_on must be YYYY-MM-DD")
	}
	if len(p.Nodes) == 0 {
		c.addf("nodes: at least one node required")
	}
	ids := map[string]bool{}
	for i, n := range p.Nodes {
		if n.ID == "" || ids[n.ID] {
			c.addf("nodes[%d]: empty or duplicate id", i)
		}
		ids[n.ID] = true
		validateNode(c, i, &n)
	}
	seen := map[TransportID]bool{}
	for _, t := range p.Priorities {
		// Unknown transports are ignored (a newer server may offer one this
		// client does not implement); duplicates are still an error.
		if seen[t] {
			c.addf("priorities: duplicate %q", t)
		}
		seen[t] = true
	}
	validateFallback(c, &p.Fallback)
	if p.UDPPolicy != UDPRejectWhenUnavailable {
		c.addf("udp_policy: only %q is supported", UDPRejectWhenUnavailable)
	}
	if p.IPv6 != IPv6Tunnel && p.IPv6 != IPv6Block {
		c.addf("ipv6: must be tunnel|block")
	}
	if p.DNS.RemoteDoHServer == "" {
		c.addf("dns.remote_doh_server is required")
	}
	for i, r := range p.Routing {
		switch r.Action {
		case "proxy", "direct", "block":
		default:
			c.addf("routing[%d].action: must be proxy|direct|block", i)
		}
		for _, cidr := range r.IPCIDR {
			if _, err := netip.ParsePrefix(cidr); err != nil {
				c.addf("routing[%d].ip_cidr %q: %v", i, cidr, err)
			}
		}
	}
	if len(p.API.BaseURLs) == 0 {
		c.addf("api.base_urls: at least one endpoint required")
	}
	for i, u := range p.API.BaseURLs {
		if !strings.HasPrefix(u, "https://") {
			c.addf("api.base_urls[%d]: must be https", i)
		}
	}
	if len(c.problems) > 0 {
		return &ValidationError{Problems: c.problems}
	}
	return nil
}

func validateNode(c *collector, i int, n *Node) {
	t := n.Transports
	if t.XHTTP == nil && t.VLESS == nil && t.Hysteria2 == nil && t.Naive == nil {
		c.addf("nodes[%d]: no transports", i)
	}
	if v := t.XHTTP; v != nil {
		p := fmt.Sprintf("nodes[%d].xhttp", i)
		validateVLESSCommon(c, p, v)
		if v.Transport.Type != "xhttp" {
			c.addf("%s.transport.type must be xhttp", p)
		}
		if v.Flow != "" {
			c.addf("%s.flow: XHTTP takes no flow", p)
		}
		if !xhttpPathRe.MatchString(v.Transport.Path) || strings.Contains(v.Transport.Path, "//") {
			c.addf("%s.transport.path: must start with / (1..64 URL path characters)", p)
		}
		switch v.Transport.Mode {
		case "", "auto", "packet-up", "stream-up", "stream-one":
		default:
			c.addf("%s.transport.mode: unsupported %q", p, v.Transport.Mode)
		}
	}
	if v := t.VLESS; v != nil {
		p := fmt.Sprintf("nodes[%d].vless", i)
		validateVLESSCommon(c, p, v)
		if v.Flow != "" && v.Flow != "xtls-rprx-vision" {
			c.addf("%s.flow: unsupported %q", p, v.Flow)
		}
		switch v.Transport.Type {
		case "tcp":
		case "ws", "grpc":
			if v.Flow != "" {
				c.addf("%s: flow vision requires tcp transport", p)
			}
		default:
			c.addf("%s.transport.type: must be tcp|ws|grpc", p)
		}
	}
	if h := t.Hysteria2; h != nil {
		p := fmt.Sprintf("nodes[%d].hysteria2", i)
		validateHostPort(c, p, h.Server, h.Port)
		if h.Password == "" {
			c.addf("%s.password is required", p)
		}
		if h.ObfsType != "" && h.ObfsType != "salamander" {
			c.addf("%s.obfs_type: only salamander", p)
		}
		if h.ObfsType == "salamander" && h.ObfsPass == "" {
			c.addf("%s.obfs_password is required for salamander", p)
		}
		if h.HopPorts != "" {
			m := hopRe.FindStringSubmatch(h.HopPorts)
			if m == nil {
				c.addf("%s.hop_ports: must be from:to", p)
			} else {
				from, _ := strconv.Atoi(m[1])
				to, _ := strconv.Atoi(m[2])
				if from < 1 || to > 65535 || from >= to {
					c.addf("%s.hop_ports: invalid range", p)
				}
			}
		}
		if h.HopInterval != "" {
			if d, err := time.ParseDuration(h.HopInterval); err != nil || d < 5*time.Second {
				c.addf("%s.hop_interval: duration >= 5s required", p)
			}
		}
		if h.SNI == "" {
			c.addf("%s.sni is required", p)
		}
		if h.UpMbps < 0 || h.DownMbps < 0 {
			c.addf("%s: bandwidth hints must be >= 0", p)
		}
		validatePatch(c, p, h.OutboundPatch, "type")
	}
	if nv := t.Naive; nv != nil {
		p := fmt.Sprintf("nodes[%d].naive", i)
		validateHostPort(c, p, nv.Server, nv.Port)
		if nv.Username == "" || nv.Password == "" {
			c.addf("%s: username and password are required", p)
		}
		if nv.SNI == "" {
			c.addf("%s.sni is required", p)
		}
		validatePatch(c, p, nv.OutboundPatch, "type")
	}
}

func validateVLESSCommon(c *collector, p string, v *VLESS) {
	validateHostPort(c, p, v.Server, v.Port)
	if !uuidRe.MatchString(v.UUID) {
		c.addf("%s.uuid: must be a lowercase UUID", p)
	}
	switch v.Security {
	case "reality":
		if v.Reality == nil || v.Reality.PublicKey == "" {
			c.addf("%s.reality.public_key is required", p)
		} else if !shortIDRe.MatchString(v.Reality.ShortID) || len(v.Reality.ShortID)%2 != 0 {
			c.addf("%s.reality.short_id: up to 16 hex chars, even length", p)
		}
	case "tls":
	default:
		c.addf("%s.security: must be reality|tls", p)
	}
	if v.TLS.SNI == "" {
		c.addf("%s.tls.sni is required", p)
	}
	validatePatch(c, p, v.OutboundPatch, "protocol")
}

// MaxPatchSize bounds an outbound patch (bytes).
const MaxPatchSize = 16 << 10

// validatePatch checks an outbound patch: a JSON object that keeps the
// outbound's identity (tag and type/protocol are set by the client).
func validatePatch(c *collector, p, patch, typeKey string) {
	if patch == "" {
		return
	}
	if len(patch) > MaxPatchSize {
		c.addf("%s.outbound_patch: larger than 16 KiB", p)
		return
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal([]byte(patch), &m); err != nil || m == nil {
		c.addf("%s.outbound_patch: must be a JSON object", p)
		return
	}
	for _, k := range []string{"tag", typeKey} {
		if _, ok := m[k]; ok {
			c.addf("%s.outbound_patch: %q cannot be changed", p, k)
		}
	}
}

func validateHostPort(c *collector, prefix, host string, port uint16) {
	if host == "" {
		c.addf("%s.server is required", prefix)
	} else if _, err := netip.ParseAddr(host); err != nil && !hostRe.MatchString(host) {
		c.addf("%s.server: not an IP or hostname", prefix)
	}
	if port == 0 {
		c.addf("%s.port is required", prefix)
	}
}

func validateFallback(c *collector, f *Fallback) {
	if f.ProbeIntervalSec < 5 {
		c.addf("fallback.probe_interval_sec must be >= 5")
	}
	if f.SwitchMarginPct < 0 || f.SwitchMarginPct > 100 {
		c.addf("fallback.switch_margin_pct must be 0..100")
	}
	if f.ConsecutiveProbes < 1 || f.FailThreshold < 1 {
		c.addf("fallback.consecutive_probes and fail_threshold must be >= 1")
	}
	if f.MinDwellSec < 0 {
		c.addf("fallback.min_dwell_sec must be >= 0")
	}
	// sing-box 1.13.21 clashapi getProxyDelay silently replaces http:// URLs
	// with its default (verified in experimental/clashapi/proxies.go), so only
	// https is meaningful.
	if !strings.HasPrefix(f.ProbeURL, "https://") {
		c.addf("fallback.probe_url must be https")
	}
}

// ErrNoUsableTransport is returned by selection helpers.
var ErrNoUsableTransport = errors.New("profile: no usable transport")
