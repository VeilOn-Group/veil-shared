// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package xray

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/veilon/veil-shared/pkg/profile"
	"github.com/veilon/veil-shared/pkg/tmpl"
)

// LocalSOCKS is the authenticated loopback SOCKS5 endpoint through which
// sing-box hands one transport's traffic (TCP and UDP) to Xray.
type LocalSOCKS struct {
	Port     uint16
	Username string
	Password string
}

// ClientTransport is one VLESS transport served by the client Xray process.
type ClientTransport struct {
	ID      profile.TransportID // TransportXHTTP or TransportVLESS
	VLESS   *profile.VLESS
	Address string // server address to dial: the pre-resolved IP (kill switch blocks DNS)
	Local   LocalSOCKS
}

// ClientSpec is the client Xray process configuration.
type ClientSpec struct {
	Transports []ClientTransport
	// Mark (Linux) is set on every socket Xray opens, so the nftables kill
	// switch lets exactly this traffic out (same mark as sing-box "direct").
	Mark uint32
}

// ErrClient reports an invalid client spec.
var ErrClient = errors.New("xray: invalid client spec")

// BuildClient renders the client config: one authenticated SOCKS inbound
// on 127.0.0.1 per transport, routed to that transport's VLESS outbound.
// Logs are off; the outbound patch from the profile (ADR-0067) is applied
// on top of the generated outbound, but the tag, the protocol and the
// socket mark are always the generated ones.
func BuildClient(spec ClientSpec) (tmpl.Doc, error) {
	if len(spec.Transports) == 0 {
		return nil, fmt.Errorf("%w: no transports", ErrClient)
	}
	var ins, outs, rules []any
	seen := map[profile.TransportID]bool{}
	for _, t := range spec.Transports {
		if (t.ID != profile.TransportXHTTP && t.ID != profile.TransportVLESS) || seen[t.ID] || t.VLESS == nil {
			return nil, fmt.Errorf("%w: transport %q", ErrClient, t.ID)
		}
		seen[t.ID] = true
		if t.Local.Port == 0 || len(t.Local.Password) < 16 || t.Local.Username == "" {
			return nil, fmt.Errorf("%w: local socks endpoint", ErrClient)
		}
		inTag := "in-" + string(t.ID)
		ins = append(ins, map[string]any{
			"tag": inTag, "listen": "127.0.0.1", "port": int(t.Local.Port), "protocol": "socks",
			"settings": map[string]any{
				"auth":     "password",
				"accounts": []any{map[string]any{"user": t.Local.Username, "pass": t.Local.Password}},
				"udp":      true, "ip": "127.0.0.1",
			},
		})
		ob, err := ClientOutbound(t, spec.Mark)
		if err != nil {
			return nil, err
		}
		outs = append(outs, ob)
		rules = append(rules, map[string]any{"inboundTag": []any{inTag}, "outboundTag": string(t.ID)})
	}
	outs = append(outs, map[string]any{"tag": "block", "protocol": "blackhole"})
	doc := tmpl.Doc{
		"log":       logOff(),
		"inbounds":  ins,
		"outbounds": outs,
		"routing":   map[string]any{"domainStrategy": "AsIs", "rules": rules},
	}
	if err := AssertClientNoLog(doc); err != nil {
		return nil, err
	}
	return doc, nil
}

// ClientOutbound renders the VLESS outbound of one transport.
func ClientOutbound(t ClientTransport, mark uint32) (tmpl.Doc, error) {
	v := t.VLESS
	addr := t.Address
	if addr == "" {
		addr = v.Server
	}
	user := map[string]any{"id": v.UUID, "encryption": "none"}
	if v.Flow != "" {
		user["flow"] = v.Flow
	}
	stream := map[string]any{}
	switch v.Transport.Type {
	case "xhttp":
		mode := v.Transport.Mode
		if mode == "" {
			mode = "auto"
		}
		xs := map[string]any{"path": v.Transport.Path, "mode": mode}
		if v.Transport.Host != "" {
			xs["host"] = v.Transport.Host
		}
		stream["network"], stream["xhttpSettings"] = "xhttp", xs
	case "tcp", "":
		stream["network"] = "raw"
	case "ws":
		ws := map[string]any{"path": v.Transport.Path}
		if v.Transport.Host != "" {
			ws["host"] = v.Transport.Host
		}
		stream["network"], stream["wsSettings"] = "ws", ws
	case "grpc":
		stream["network"], stream["grpcSettings"] = "grpc", map[string]any{"serviceName": v.Transport.ServiceName}
	default:
		return nil, fmt.Errorf("%w: transport type %q", ErrClient, v.Transport.Type)
	}
	fp := v.TLS.UTLSFingerprint
	if fp == "" {
		fp = "chrome"
	}
	switch v.Security {
	case "reality":
		if v.Reality == nil {
			return nil, fmt.Errorf("%w: reality keys missing", ErrClient)
		}
		stream["security"] = "reality"
		stream["realitySettings"] = map[string]any{
			"serverName": v.TLS.SNI, "fingerprint": fp,
			"publicKey": v.Reality.PublicKey, "shortId": v.Reality.ShortID,
		}
	case "tls":
		ts := map[string]any{"serverName": v.TLS.SNI, "fingerprint": fp}
		if len(v.TLS.ALPN) > 0 {
			ts["alpn"] = v.TLS.ALPN
		}
		stream["security"], stream["tlsSettings"] = "tls", ts
	default:
		return nil, fmt.Errorf("%w: security %q", ErrClient, v.Security)
	}
	ob := tmpl.Doc{
		"tag": string(t.ID), "protocol": "vless",
		"settings": map[string]any{
			"vnext": []any{map[string]any{"address": addr, "port": int(v.Port), "users": []any{user}}},
		},
		"streamSettings": stream,
	}
	if v.OutboundPatch != "" {
		var p map[string]any
		if err := json.Unmarshal([]byte(v.OutboundPatch), &p); err != nil || p == nil {
			return nil, fmt.Errorf("%w: outbound patch is not a JSON object", ErrClient)
		}
		pd, err := tmpl.FromValue(p)
		if err != nil {
			return nil, err
		}
		ob = tmpl.MergePatch(ob, pd)
		ob["tag"], ob["protocol"] = string(t.ID), "vless"
	}
	if mark != 0 {
		ss, _ := ob["streamSettings"].(map[string]any)
		if ss == nil {
			ss = map[string]any{}
			ob["streamSettings"] = ss
		}
		so, _ := ss["sockopt"].(map[string]any)
		if so == nil {
			so = map[string]any{}
			ss["sockopt"] = so
		}
		so["mark"] = int64(mark)
	}
	return ob, nil
}
