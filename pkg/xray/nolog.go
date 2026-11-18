// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package xray

import (
	"errors"
	"fmt"
	"net/netip"
	"strings"

	"github.com/veilon/veil-shared/pkg/tmpl"
)

// ErrNoLogViolation is returned when a config could record user data.
var ErrNoLogViolation = errors.New("xray: zero-log invariant violated")

// allowedAPIServices may run on the node API: traffic counters and live
// user changes. LoggerService (log restart), RoutingService (exposes
// connection metadata through routing stats) and ObservatoryService are not.
var allowedAPIServices = map[string]bool{"StatsService": true, "HandlerService": true}

// AssertServerNoLog enforces the node invariants (ADR-0011, ADR-0013,
// ADR-0067) on any node config, generated or a custom template:
//   - "log" is present with access and error logs "none", loglevel "none",
//     dnsLog off;
//   - no online-user / source-IP tracking (statsUserOnline) at any level;
//   - the API listens only on 127.0.0.1 and runs only allowed services;
//   - no "metrics" endpoint (it publishes every counter over HTTP);
//   - no TLS key log (masterKeyLog) and no REALITY debug output ("show").
func AssertServerNoLog(d tmpl.Doc) error {
	if err := assertLogOff(d); err != nil {
		return err
	}
	if p := tmpl.FindKey(d, "statsUserOnline", tmpl.Truthy); p != "" {
		return fmt.Errorf("%w: %s records user source addresses", ErrNoLogViolation, p)
	}
	if api, ok := d["api"].(map[string]any); ok {
		if l, ok := api["listen"].(string); ok && l != "" {
			ap, err := netip.ParseAddrPort(l)
			if err != nil || !ap.Addr().IsLoopback() {
				return fmt.Errorf("%w: api must listen on loopback", ErrNoLogViolation)
			}
		}
		svcs, _ := api["services"].([]any)
		for _, s := range svcs {
			if n, _ := s.(string); !allowedAPIServices[n] {
				return fmt.Errorf("%w: api service %v is not allowed on nodes", ErrNoLogViolation, s)
			}
		}
	}
	if _, ok := d["metrics"]; ok {
		return fmt.Errorf("%w: metrics endpoint is not allowed on nodes", ErrNoLogViolation)
	}
	return assertNoKeyLog(d)
}

// AssertClientNoLog enforces the client invariants: logs off, no key log,
// no API or metrics (veilond reads nothing from the client core), and every
// inbound on loopback with authentication.
func AssertClientNoLog(d tmpl.Doc) error {
	if err := assertLogOff(d); err != nil {
		return err
	}
	for _, k := range []string{"api", "metrics", "stats"} {
		if _, ok := d[k]; ok {
			return fmt.Errorf("%w: %q is not allowed in client configs", ErrNoLogViolation, k)
		}
	}
	for _, in := range tmpl.Objects(d, "inbounds") {
		l, _ := in["listen"].(string)
		if a, err := netip.ParseAddr(l); err != nil || !a.IsLoopback() {
			return fmt.Errorf("%w: client inbound must listen on loopback", ErrNoLogViolation)
		}
		if s, _ := in["settings"].(map[string]any); s == nil || s["auth"] != "password" {
			return fmt.Errorf("%w: client inbound must require a password", ErrNoLogViolation)
		}
	}
	return assertNoKeyLog(d)
}

func assertLogOff(d tmpl.Doc) error {
	l, ok := d["log"].(map[string]any)
	if !ok {
		return fmt.Errorf("%w: log section must be explicit", ErrNoLogViolation)
	}
	for _, k := range []string{"access", "error"} {
		if v, _ := l[k].(string); v != "none" {
			return fmt.Errorf("%w: log.%s must be \"none\"", ErrNoLogViolation, k)
		}
	}
	if v, _ := l["loglevel"].(string); !strings.EqualFold(v, "none") {
		return fmt.Errorf("%w: log.loglevel must be \"none\"", ErrNoLogViolation)
	}
	if tmpl.Truthy(l["dnsLog"]) {
		return fmt.Errorf("%w: log.dnsLog must be off", ErrNoLogViolation)
	}
	if v := l["maskAddress"]; v != nil && v != "" {
		// Irrelevant with logs off; refused so a later edit cannot rely on it.
		return fmt.Errorf("%w: log.maskAddress is not used (logs are off)", ErrNoLogViolation)
	}
	return nil
}

func assertNoKeyLog(d tmpl.Doc) error {
	if p := tmpl.FindKey(d, "masterKeyLog", tmpl.Truthy); p != "" {
		return fmt.Errorf("%w: %s writes TLS keys", ErrNoLogViolation, p)
	}
	if p := tmpl.FindKey(d, "show", tmpl.Truthy); p != "" {
		return fmt.Errorf("%w: %s prints REALITY handshakes", ErrNoLogViolation, p)
	}
	return nil
}
