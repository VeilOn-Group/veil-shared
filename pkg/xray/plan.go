// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package xray

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net"

	"github.com/veilon/veil-shared/pkg/profile"
	"github.com/veilon/veil-shared/pkg/singbox"
)

// Plan is the client side of ADR-0066 for one node: the Xray config and
// the matching sing-box SOCKS endpoints (ClientOptions.Xray).
type Plan struct {
	Spec      ClientSpec
	Endpoints map[profile.TransportID]*singbox.ExternalSOCKS
}

// PlanOptions configure PlanClient.
type PlanOptions struct {
	Disabled map[profile.TransportID]bool
	// Resolve returns the address to dial for a server name (the
	// pre-resolved IP; the kill switch blocks the system resolver). nil or
	// "" keeps the name.
	Resolve func(host string) string
	Mark    uint32 // Linux SO_MARK (kill switch)
	// ProcessPath is the Xray binary; sing-box sends its traffic around the
	// TUN (desktop). Empty on Android (the app's own UID is excluded).
	ProcessPath string
	// FreePort returns a free loopback TCP port (default: ask the kernel).
	FreePort func() (uint16, error)
}

func randomHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// LoopbackPort asks the kernel for a free 127.0.0.1 TCP port.
func LoopbackPort() (uint16, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0") //nolint:noctx // instant local bind
	if err != nil {
		return 0, err
	}
	defer func() { _ = l.Close() }()
	p := l.Addr().(*net.TCPAddr).Port
	if p < 1 || p > 65535 {
		return 0, fmt.Errorf("xray: bad loopback port %d", p)
	}
	return uint16(p), nil //nolint:gosec // range checked above
}

// PlanClient prepares the Xray process for the enabled VLESS transports of
// node (nil Plan when there are none). Each start gets new ports and
// passwords.
func PlanClient(node *profile.Node, o PlanOptions) (*Plan, error) {
	if o.FreePort == nil {
		o.FreePort = LoopbackPort
	}
	plan := &Plan{Endpoints: map[profile.TransportID]*singbox.ExternalSOCKS{}, Spec: ClientSpec{Mark: o.Mark}}
	for _, x := range []struct {
		id profile.TransportID
		v  *profile.VLESS
	}{{profile.TransportXHTTP, node.Transports.XHTTP}, {profile.TransportVLESS, node.Transports.VLESS}} {
		if x.v == nil || !x.v.Enabled || o.Disabled[x.id] {
			continue
		}
		port, err := o.FreePort()
		if err != nil {
			return nil, err
		}
		local := LocalSOCKS{Port: port, Username: "v" + randomHex(6), Password: randomHex(24)}
		addr := x.v.Server
		if o.Resolve != nil {
			if a := o.Resolve(x.v.Server); a != "" {
				addr = a
			}
		}
		plan.Spec.Transports = append(plan.Spec.Transports, ClientTransport{ID: x.id, VLESS: x.v, Address: addr, Local: local})
		plan.Endpoints[x.id] = &singbox.ExternalSOCKS{Port: port, Username: local.Username, Password: local.Password, ProcessPath: o.ProcessPath}
	}
	if len(plan.Spec.Transports) == 0 {
		return nil, nil //nolint:nilnil // no VLESS transport: no Xray process
	}
	return plan, nil
}
