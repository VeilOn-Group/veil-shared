// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Package xray renders Xray-core configurations for VLESS (ADR-0066).
//
// sing-box (1.13.21 and main as of 2026-10) has no XHTTP transport, and
// Xray-core since REALITY commit 8cdf7bf (2026-09-08) rejects REALITY Client
// Hellos without an X25519MLKEM768 key share, which the sing-box REALITY
// client does not send. VLESS therefore runs in Xray on both ends; sing-box
// keeps Hysteria 2, naive, the TUN and routing. Verified with the official
// Xray 26.9.30 release binaries (see docs/adr/0066-0070-iter6.md).
//
// Node layout (one public TCP port, as before):
//
//	:443/tcp  Xray VLESS + REALITY, RAW (Vision). Clients that pass REALITY
//	          authentication but do not speak VLESS over RAW (XHTTP clients
//	          send HTTP/2) fall back to the XHTTP inbound on an abstract unix
//	          socket. Unauthenticated TLS (naive clients, probes) is relayed by
//	          REALITY to the sing-box naive inbound on loopback ("steal-self").
//	@veilon-xhttp  Xray VLESS + XHTTP (plain: REALITY already terminated).
package xray

import (
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/veilon/veil-shared/pkg/tmpl"
)

// Inbound tags on the node.
const (
	TagInVision = "vless-in"
	TagInXHTTP  = "xhttp-in"
	// XHTTPSocket is the default listen address of the XHTTP inbound: an
	// abstract unix socket (Linux; private to the node's network namespace).
	XHTTPSocket = "@veilon-xhttp"
	// FlowVision is the only VLESS flow in use.
	FlowVision = "xtls-rprx-vision"
)

// XHTTPModes are the accepted XHTTP modes ("auto" lets the client pick
// stream-one with REALITY).
var XHTTPModes = []string{"auto", "packet-up", "stream-up", "stream-one"}

// ServerSpec is everything the node template needs besides the users.
type ServerSpec struct {
	Listen        string // public listen address ("0.0.0.0" or "::")
	Port          uint16 // public TCP port (REALITY)
	Domain        string // REALITY server name = node domain
	Target        string // REALITY target: "127.0.0.1:<naive port>"
	PrivateKey    string
	ShortIDs      []string
	MaxTimeDiffMs uint64 // 0 = off
	Flow          string // FlowVision or "" (no flow)
	XHTTPPath     string
	XHTTPMode     string
	XHTTPSocket   string // default XHTTPSocket
	APIListen     string // 127.0.0.1:port: StatsService + HandlerService
	BlockPorts    []uint16
	// AllowCIDRs lets VLESS reach private destinations (test benches only;
	// Xray blocks private and loopback targets of VLESS by default).
	AllowCIDRs []string
	// Transports offered: a disabled one keeps its inbound with no users,
	// so the REALITY front and the steal-self camouflage never change.
	Vision, XHTTP bool
}

// User is one subscriber on the node: a pseudonym (Xray "email", the stats
// key) and its VLESS UUID. Never an account id (ADR-0014).
type User struct {
	Email string
	UUID  string
}

// ErrSpec reports an invalid server spec.
var ErrSpec = errors.New("xray: invalid node spec")

var (
	rePath  = regexp.MustCompile(`^/[A-Za-z0-9._~/-]{1,63}$`)
	reShort = regexp.MustCompile(`^([0-9a-f]{2}){0,8}$`)
	reUUID  = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	reEmail = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,64}$`)
)

// ValidXHTTPPath reports whether p is an acceptable XHTTP path.
func ValidXHTTPPath(p string) bool { return rePath.MatchString(p) && !strings.Contains(p, "//") }

func (s ServerSpec) validate() error {
	var errs []string
	if s.Domain == "" || strings.ContainsAny(s.Domain, " /:") {
		errs = append(errs, "domain")
	}
	if s.Port == 0 {
		errs = append(errs, "port")
	}
	if ap, err := netip.ParseAddrPort(s.Target); err != nil || !ap.Addr().IsLoopback() {
		errs = append(errs, "reality target must be a loopback address:port")
	}
	if len(s.PrivateKey) != 43 {
		errs = append(errs, "reality private key")
	}
	if len(s.ShortIDs) == 0 || len(s.ShortIDs) > 8 {
		errs = append(errs, "1..8 reality short ids")
	}
	for _, id := range s.ShortIDs {
		if !reShort.MatchString(id) {
			errs = append(errs, "reality short id")
		}
	}
	if s.XHTTPSocket != "" && (!strings.HasPrefix(s.XHTTPSocket, "@veilon-") || len(s.XHTTPSocket) > 64) {
		errs = append(errs, "xhttp socket")
	}
	if s.MaxTimeDiffMs > 600_000 {
		errs = append(errs, "max time difference (at most 10 min)")
	}
	if s.Flow != "" && s.Flow != FlowVision {
		errs = append(errs, "flow")
	}
	if !ValidXHTTPPath(s.XHTTPPath) {
		errs = append(errs, "xhttp path")
	}
	if !slices.Contains(XHTTPModes, s.XHTTPMode) {
		errs = append(errs, "xhttp mode")
	}
	if ap, err := netip.ParseAddrPort(s.APIListen); err != nil || ap.Addr() != netip.MustParseAddr("127.0.0.1") {
		errs = append(errs, "api must listen on 127.0.0.1")
	}
	for _, c := range s.AllowCIDRs {
		if _, err := netip.ParsePrefix(c); err != nil {
			errs = append(errs, "allow cidr "+c)
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("%w: %s", ErrSpec, strings.Join(errs, ", "))
	}
	return nil
}

// ServerTokens documents the tokens of the node Xray template (shown in
// the panel's raw editor).
var ServerTokens = map[string]string{
	"listen":                   "public listen address",
	"tcp_port":                 "public TCP port (number)",
	"server_names":             "REALITY server names (list: the node domain)",
	"reality_target":           "REALITY target: the naive inbound on loopback (steal-self)",
	"reality_private_key":      "REALITY private key (secret)",
	"reality_short_ids":        "accepted REALITY short ids (list)",
	"reality_max_time_diff_ms": "allowed client clock skew in ms (0 = off)",
	"clients_vision":           "VLESS users of the RAW (Vision) inbound (list, secret)",
	"clients_xhttp":            "VLESS users of the XHTTP inbound (list, secret)",
	"xhttp_socket":             "listen address of the XHTTP inbound (abstract unix socket)",
	"xhttp_path":               "XHTTP path",
	"xhttp_mode":               "XHTTP mode",
	"api_listen":               "Xray API (stats, users) on loopback",
	"routing_rules":            "routing rules: blocked ports (list)",
	"freedom_final_rules":      "direct outbound final rules: private ranges allowed on test benches (list)",
}

// DefaultServerTemplate is the node Xray template used unless the operator
// saved a custom one. Its structure is constant: every node parameter is a
// token, so the template does not change when the panel changes a port or
// rotates a key.
func DefaultServerTemplate() tmpl.Doc {
	t := tmpl.Token
	return tmpl.Doc{
		"log": logOff(),
		"api": map[string]any{
			"tag": "api", "listen": t("api_listen"),
			"services": []any{"StatsService", "HandlerService"},
		},
		"stats": map[string]any{},
		"policy": map[string]any{
			"levels": map[string]any{
				"0": map[string]any{"statsUserUplink": true, "statsUserDownlink": true, "handshake": 4, "connIdle": 300},
			},
		},
		"inbounds": []any{
			map[string]any{
				"tag": TagInVision, "listen": t("listen"), "port": t("tcp_port"), "protocol": "vless",
				"settings": map[string]any{
					"clients": t("clients_vision"), "decryption": "none",
					"fallbacks": []any{map[string]any{"dest": t("xhttp_socket"), "xver": 0}},
				},
				"streamSettings": map[string]any{
					"network": "raw", "security": "reality",
					"realitySettings": map[string]any{
						"target": t("reality_target"), "xver": 0,
						"serverNames": t("server_names"), "privateKey": t("reality_private_key"),
						"shortIds": t("reality_short_ids"), "maxTimeDiff": t("reality_max_time_diff_ms"),
					},
				},
			},
			map[string]any{
				"tag": TagInXHTTP, "listen": t("xhttp_socket"), "protocol": "vless",
				"settings": map[string]any{"clients": t("clients_xhttp"), "decryption": "none"},
				"streamSettings": map[string]any{
					"network":       "xhttp",
					"xhttpSettings": map[string]any{"path": t("xhttp_path"), "mode": t("xhttp_mode")},
				},
			},
		},
		"outbounds": []any{
			map[string]any{"tag": "direct", "protocol": "freedom", "settings": map[string]any{"finalRules": t("freedom_final_rules")}},
			map[string]any{"tag": "block", "protocol": "blackhole"},
		},
		"routing": map[string]any{"domainStrategy": "AsIs", "rules": t("routing_rules")},
	}
}

func logOff() map[string]any {
	return map[string]any{"access": "none", "error": "none", "loglevel": "none", "dnsLog": false}
}

// ServerValues computes the token values for spec and users.
func ServerValues(spec ServerSpec, users []User) (map[string]any, error) {
	if err := spec.validate(); err != nil {
		return nil, err
	}
	us := append([]User(nil), users...)
	sort.Slice(us, func(i, j int) bool { return us[i].Email < us[j].Email })
	vision, xh := []any{}, []any{}
	seen := map[string]bool{}
	for _, u := range us {
		if !reEmail.MatchString(u.Email) || seen[u.Email] || !reUUID.MatchString(u.UUID) {
			return nil, fmt.Errorf("%w: user pseudonym or uuid", ErrSpec)
		}
		seen[u.Email] = true
		if spec.Vision {
			c := map[string]any{"id": u.UUID, "email": u.Email}
			if spec.Flow != "" {
				c["flow"] = spec.Flow
			}
			vision = append(vision, c)
		}
		if spec.XHTTP {
			xh = append(xh, map[string]any{"id": u.UUID, "email": u.Email})
		}
	}
	rules := []any{}
	if len(spec.BlockPorts) > 0 {
		ps := make([]string, 0, len(spec.BlockPorts))
		for _, p := range spec.BlockPorts {
			ps = append(ps, strconv.Itoa(int(p)))
		}
		rules = append(rules, map[string]any{"network": "tcp", "port": strings.Join(ps, ","), "outboundTag": "block"})
	}
	final := []any{}
	if len(spec.AllowCIDRs) > 0 {
		ips := make([]any, 0, len(spec.AllowCIDRs))
		for _, c := range spec.AllowCIDRs {
			ips = append(ips, c)
		}
		final = append(final, map[string]any{"action": "allow", "ip": ips})
	}
	socket := spec.XHTTPSocket
	if socket == "" {
		socket = XHTTPSocket
	}
	ids := make([]any, 0, len(spec.ShortIDs))
	for _, s := range spec.ShortIDs {
		ids = append(ids, s)
	}
	return map[string]any{
		"listen": spec.Listen, "tcp_port": int(spec.Port),
		"server_names":        []any{spec.Domain},
		"reality_target":      spec.Target,
		"reality_private_key": spec.PrivateKey, "reality_short_ids": ids,
		"reality_max_time_diff_ms": spec.MaxTimeDiffMs,
		"clients_vision":           vision, "clients_xhttp": xh,
		"xhttp_socket": socket, "xhttp_path": spec.XHTTPPath, "xhttp_mode": spec.XHTTPMode,
		"api_listen":    spec.APIListen,
		"routing_rules": rules, "freedom_final_rules": final,
	}, nil
}

// BuildServer renders the node config from a template (nil = default) and
// checks the zero-log invariants.
func BuildServer(template tmpl.Doc, spec ServerSpec, users []User) (tmpl.Doc, error) {
	if template == nil {
		template = DefaultServerTemplate()
	}
	vals, err := ServerValues(spec, users)
	if err != nil {
		return nil, err
	}
	doc, err := tmpl.Render(template, vals)
	if err != nil {
		return nil, err
	}
	if err := AssertServerNoLog(doc); err != nil {
		return nil, err
	}
	return doc, nil
}

// UsersPatch is the payload of "xray api adu": the users of the node
// inbounds, for adding them to a running core without a restart.
func UsersPatch(doc tmpl.Doc, emails map[string]bool) tmpl.Doc {
	var ins []any
	for _, in := range tmpl.Objects(doc, "inbounds") {
		if in["protocol"] != "vless" {
			continue
		}
		settings, _ := in["settings"].(map[string]any)
		cl, _ := settings["clients"].([]any)
		var keep []any
		for _, c := range cl {
			if m, ok := c.(map[string]any); ok {
				if e, _ := m["email"].(string); emails[e] {
					keep = append(keep, m)
				}
			}
		}
		if len(keep) == 0 {
			continue
		}
		// "xray api adu" builds the whole inbound to extract the users, so
		// it needs a listen address and port; they are not used.
		ins = append(ins, map[string]any{
			"tag": in["tag"], "listen": "127.0.0.1", "port": 1, "protocol": "vless",
			"settings": map[string]any{"decryption": "none", "clients": keep},
		})
	}
	return tmpl.Doc{"inbounds": ins}
}

// Users maps inbound tag -> email -> client object (as JSON) of a rendered
// config: the agent diffs two of them to add or remove users live.
func Users(doc tmpl.Doc) map[string]map[string]string {
	out := map[string]map[string]string{}
	for _, in := range tmpl.Objects(doc, "inbounds") {
		tag, _ := in["tag"].(string)
		settings, _ := in["settings"].(map[string]any)
		cl, _ := settings["clients"].([]any)
		if in["protocol"] != "vless" || tag == "" {
			continue
		}
		m := map[string]string{}
		for _, c := range cl {
			if cm, ok := c.(map[string]any); ok {
				e, _ := cm["email"].(string)
				b, _ := tmpl.Marshal(cm)
				m[e] = string(b)
			}
		}
		out[tag] = m
	}
	return out
}

// WithoutUsers returns a copy of doc whose VLESS client lists are empty:
// two configs with equal WithoutUsers differ only in users, which the agent
// applies through the API instead of restarting the core.
func WithoutUsers(doc tmpl.Doc) tmpl.Doc {
	cp := tmpl.MergePatch(doc, tmpl.Doc{})
	for _, in := range tmpl.Objects(cp, "inbounds") {
		if in["protocol"] != "vless" {
			continue
		}
		if s, ok := in["settings"].(map[string]any); ok {
			s["clients"] = []any{}
		}
	}
	return cp
}
