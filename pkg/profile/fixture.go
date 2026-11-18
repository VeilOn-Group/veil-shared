// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package profile

// Fixture returns a deterministic, valid profile for tests and golden files.
// All values are synthetic test data (RFC 5737 addresses, example.* names,
// keys generated only for fixtures). Never used in production code paths.
func Fixture() Profile {
	return Profile{
		SchemaVersion:    SchemaVersion,
		MinClientVersion: "0.1.0",
		ProfileID:        "prof_fixture_0001",
		IssuedAt:         1_800_000_000,
		ExpiresAt:        1_800_086_400,
		Subscription: Subscription{
			Plan: "monthly", Status: "active", EndsOn: "2027-01-31",
			TrafficLimitBytes: 200 << 30, DeviceLimit: 5,
		},
		Nodes: []Node{{
			ID: "nl-ams-1", Name: "Amsterdam 1", Region: "NL",
			Transports: NodeTransports{
				XHTTP: &VLESS{
					Enabled: true, Server: "203.0.113.10", Port: 443,
					UUID:      "8c7c3b1e-5d1a-4a4e-9a65-2f0f7a8b9c01",
					Transport: VLESSWire{Type: "xhttp", Path: "/f1xture", Mode: "auto"},
					Security:  "reality",
					TLS:       TLSClient{SNI: "www.example.com", UTLSFingerprint: "chrome"},
					Reality:   &RealityPK{PublicKey: "PsQ23zEvp-4eCxAIdFOZ8ak4p-UpIQGSL8wpt4Ca_Qg", ShortID: "0123456789abcdef"},
				},
				VLESS: &VLESS{
					Enabled: true, Server: "203.0.113.10", Port: 443,
					UUID:      "8c7c3b1e-5d1a-4a4e-9a65-2f0f7a8b9c01",
					Flow:      "xtls-rprx-vision",
					Transport: VLESSWire{Type: "tcp"},
					Security:  "reality",
					TLS:       TLSClient{SNI: "www.example.com", UTLSFingerprint: "chrome"},
					Reality:   &RealityPK{PublicKey: "PsQ23zEvp-4eCxAIdFOZ8ak4p-UpIQGSL8wpt4Ca_Qg", ShortID: "0123456789abcdef"},
				},
				Hysteria2: &Hysteria2{
					Enabled: true, Server: "203.0.113.10", Port: 443,
					HopPorts: "20000:40000", HopInterval: "30s",
					Password: "fixture-hy2-password", ObfsType: "salamander", ObfsPass: "fixture-obfs",
					SNI: "node1.example.net", ALPN: []string{"h3"}, UpMbps: 50, DownMbps: 200,
				},
				Naive: &Naive{
					Enabled: true, Server: "node1.example.net", Port: 443,
					Username: "u_fixture", Password: "fixture-naive-password", SNI: "node1.example.net",
				},
			},
		}},
		Priorities: []TransportID{TransportXHTTP, TransportVLESS, TransportNaive, TransportHysteria2},
		Fallback: Fallback{
			ProbeIntervalSec: 30, SwitchMarginPct: 25, ConsecutiveProbes: 3,
			MinDwellSec: 60, FailThreshold: 3, ProbeURL: "https://www.gstatic.com/generate_204",
		},
		UDPPolicy: UDPRejectWhenUnavailable,
		DNS:       DNS{RemoteDoHServer: "1.1.1.1", Strategy: "prefer_ipv4"},
		IPv6:      IPv6Tunnel,
		API: APIEndpoints{
			BaseURLs: []string{"https://api.example.net", "https://api-alt.example.org"},
			SPKIPins: []string{"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB="},
		},
	}
}
