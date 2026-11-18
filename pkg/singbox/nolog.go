// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package singbox

import (
	"errors"
	"fmt"
	"net/netip"

	"github.com/veilon/veil-shared/pkg/tmpl"
)

// ErrNoLogViolation is returned when a generated config could leak user data.
var ErrNoLogViolation = errors.New("singbox: zero-log invariant violated")

// AssertClientNoLog enforces client invariants (ADR-0002/0003/0004/0011):
//   - log level warn/error only, no log file output (veilond owns logging);
//   - cache file never stores fake-IP or DNS (rdrc) data;
//   - Clash API only on loopback with a secret, no external UI;
//   - naive is never QUIC, never UDP-over-TCP, and never in the UDP selector.
func AssertClientNoLog(c *Config) error {
	// A missing log section means sing-box defaults (info level, which logs
	// destinations) -> reject. Disabled is always acceptable.
	if c.Log == nil {
		return fmt.Errorf("%w: log section must be explicit", ErrNoLogViolation)
	}
	if !c.Log.Disabled {
		if c.Log.Level != "warn" && c.Log.Level != "error" {
			return fmt.Errorf("%w: client log level %q", ErrNoLogViolation, c.Log.Level)
		}
		if c.Log.Output != "" {
			return fmt.Errorf("%w: client log must not write files directly", ErrNoLogViolation)
		}
	}
	if c.Experimental != nil {
		if cf := c.Experimental.CacheFile; cf != nil && (cf.StoreFakeIP || cf.StoreRDRC) {
			return fmt.Errorf("%w: cache_file must not persist DNS data", ErrNoLogViolation)
		}
		if ca := c.Experimental.ClashAPI; ca != nil {
			if ca.Secret == "" || len(ca.ExternalController) < 10 || ca.ExternalController[:10] != "127.0.0.1:" {
				return fmt.Errorf("%w: clash api must be loopback with secret", ErrNoLogViolation)
			}
		}
	}
	for _, o := range c.Outbounds {
		if o.Tag == TagNaive && o.Type == "naive" && (o.QUIC == nil || *o.QUIC) {
			return fmt.Errorf("%w: naive must be HTTP/2 only (quic=false)", ErrNoLogViolation)
		}
		if o.Tag == TagSelectorUDP {
			for _, t := range o.Outbounds {
				if t == TagNaive {
					return fmt.Errorf("%w: naive in UDP selector", ErrNoLogViolation)
				}
			}
		}
	}
	return nil
}

// AssertServerNoLog enforces the node invariants (ADR-0012, ADR-0013,
// ADR-0067) on any node config, generated or a custom template: logging
// fully disabled, no Clash API (exposes connections), no cache file, the
// V2Ray API only on loopback, no debug or pprof listener, and no TLS key
// log.
func AssertServerNoLog(d tmpl.Doc) error {
	lg, ok := d["log"].(map[string]any)
	if !ok || lg["disabled"] != true {
		return fmt.Errorf("%w: server log must be disabled", ErrNoLogViolation)
	}
	if e, ok := d["experimental"].(map[string]any); ok {
		for _, k := range []string{"clash_api", "cache_file", "debug"} {
			if _, bad := e[k]; bad {
				return fmt.Errorf("%w: server must not run experimental.%s", ErrNoLogViolation, k)
			}
		}
		if v, ok := e["v2ray_api"].(map[string]any); ok {
			l, _ := v["listen"].(string)
			if ap, err := netip.ParseAddrPort(l); err != nil || !ap.Addr().IsLoopback() {
				return fmt.Errorf("%w: v2ray_api must listen on loopback", ErrNoLogViolation)
			}
		}
	}
	if _, ok := d["debug"]; ok {
		return fmt.Errorf("%w: debug listener is not allowed on nodes", ErrNoLogViolation)
	}
	if p := tmpl.FindKey(d, "key_log", tmpl.Truthy); p != "" {
		return fmt.Errorf("%w: %s writes TLS keys", ErrNoLogViolation, p)
	}
	return nil
}
