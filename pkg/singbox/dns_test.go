// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package singbox

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/veilon/veil-shared/pkg/profile"
)

func TestDNSChoiceValidation(t *testing.T) {
	for _, tc := range []struct {
		c  DNSChoice
		ok bool
	}{
		{DNSChoice{}, true},
		{DNSChoice{Provider: DNSQuad9}, true},
		{DNSChoice{Provider: DNSCloudflare}, true},
		{DNSChoice{Provider: DNSGoogle}, true},
		{DNSChoice{Provider: DNSAdGuard}, true},
		{DNSChoice{Provider: DNSOpenDNS}, true},
		{DNSChoice{Provider: "nextdns"}, false},
		{DNSChoice{Provider: DNSCustom, CustomURL: "https://doh.example.net/dns-query"}, true},
		{DNSChoice{Provider: DNSCustom, CustomURL: "https://doh.example.net"}, true},
		{DNSChoice{Provider: DNSCustom, CustomURL: "https://203.0.113.53:8443/q"}, true},
		{DNSChoice{Provider: DNSCustom, CustomURL: "https://[fd00::53]/dns-query"}, false},
		{DNSChoice{Provider: DNSCustom, CustomURL: "https://[2606:4700:4700::1111]/dns-query"}, true},
		{DNSChoice{Provider: DNSCustom, CustomURL: ""}, false},
		{DNSChoice{Provider: DNSCustom, CustomURL: "http://doh.example.net/dns-query"}, false},
		{DNSChoice{Provider: DNSCustom, CustomURL: "https://user:pw@doh.example.net/dns-query"}, false},
		{DNSChoice{Provider: DNSCustom, CustomURL: "https://doh.example.net/dns-query{?dns}"}, false},
		{DNSChoice{Provider: DNSCustom, CustomURL: "https://doh.example.net/dns-query?x=1"}, false},
		{DNSChoice{Provider: DNSCustom, CustomURL: "https://192.168.1.1/dns-query"}, false},
		{DNSChoice{Provider: DNSCustom, CustomURL: "https://127.0.0.1/dns-query"}, false},
		{DNSChoice{Provider: DNSCustom, CustomURL: "https://localhost/dns-query"}, false},
		{DNSChoice{Provider: DNSCustom, CustomURL: "https://doh.example.net:0/dns-query"}, false},
		{DNSChoice{Provider: DNSCustom, CustomURL: "https://-bad-.example/dns-query"}, false},
	} {
		err := tc.c.Validate()
		if (err == nil) != tc.ok || (err != nil && !errors.Is(err, ErrDNS)) {
			t.Errorf("%+v: %v", tc.c, err)
		}
	}
}

func TestDNSPresetsInConfig(t *testing.T) {
	sb := os.Getenv("SINGBOX_BIN")
	for _, pr := range DoHPresets {
		p := profile.Fixture()
		o := baseOpts()
		o.DNS = &DNSChoice{Provider: pr.ID}
		cfg, err := BuildClient(&p, o)
		if err != nil {
			t.Fatal(err)
		}
		s := cfg.DNS.Servers[0]
		if s.Tag != TagDNSRemote || s.Server != pr.IPs[0] || s.TLS == nil || s.TLS.ServerName != pr.Host || s.Detour != TagSelectorTCP || s.DomainResolver != "" {
			t.Fatalf("%s: %+v", pr.ID, s)
		}
		if cfg.DNS.Final != TagDNSRemote {
			t.Fatal("final resolver must be the tunnelled DoH")
		}
		if sb != "" {
			raw, _ := cfg.MarshalJSON()
			f := filepath.Join(t.TempDir(), "c.json")
			_ = os.WriteFile(f, raw, 0o600)
			cmd := exec.Command(sb, "check", "-c", f)
			cmd.Dir, _ = os.Getwd()
			if out, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("%s: sing-box check: %v\n%s", pr.ID, err, out)
			}
		}
	}
	// A custom host name is resolved through the tunnel, never locally.
	p := profile.Fixture()
	o := baseOpts()
	o.DNS = &DNSChoice{Provider: DNSCustom, CustomURL: "https://doh.example.net/q"}
	cfg, err := BuildClient(&p, o)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.DNS.Servers[0].DomainResolver != TagDNSBootstrap || cfg.DNS.Servers[1].Tag != TagDNSBootstrap || cfg.DNS.Servers[1].Detour != TagSelectorTCP {
		t.Fatalf("custom name: %+v", cfg.DNS.Servers)
	}
	o.DNS = &DNSChoice{Provider: "bogus"}
	if _, err := BuildClient(&p, o); !errors.Is(err, ErrDNS) {
		t.Fatalf("bogus provider: %v", err)
	}
}
