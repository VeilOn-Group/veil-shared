// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package redact

import (
	"bytes"
	"errors"
	"log/slog"
	"strings"
	"testing"
)

// Markers that must never survive redaction (shared with the canary test).
const (
	markerIPv4  = "198.51.100.77"
	markerIPv6  = "2001:db8:dead:beef::77"
	markerEmail = "canary.user+vpn@example.org"
	markerUUID  = "0f8e2a4c-7d1b-4c6e-9a3f-5b2d8e1c9a77"
)

func TestRedactNoLog(t *testing.T) {
	s := New(Options{Hostnames: true, KeepHosts: []string{"api.example.net"}})
	cases := []struct {
		in       string
		mustNot  []string
		mustHave []string
	}{
		{"dial tcp " + markerIPv4 + ":443: i/o timeout", []string{markerIPv4}, []string{"[IP]:443"}},
		{"outbound to [" + markerIPv6 + "]:443 failed", []string{"dead:beef"}, []string{"[IP]"}},
		{"user " + markerEmail + " registered", []string{markerEmail, "canary.user"}, []string{"[EMAIL]"}},
		{"uuid=" + markerUUID, []string{markerUUID}, nil},
		{"Authorization: Bearer abcdefghijklmnop123456", []string{"abcdefghijklmnop123456"}, nil},
		{`{"password":"hunter2-very-secret"}`, []string{"hunter2"}, nil},
		{"api_key=sk_live_1234567890", []string{"sk_live_1234567890"}, nil},
		{"token eyJhbGciOiJFZERTQSJ9.eyJzdWIiOiJ4In0.c2lnbmF0dXJl", []string{"eyJhbGci"}, nil},
		{"account 1234 5678 9012 3456 logged", []string{"9012"}, []string{"[NUM]"}},
		{"key AAAAC3NzaC1lZDI1NTE5AAAAIGtleS1tYXRlcmlhbC1mb3ItdGVzdHM=", []string{"AAAAC3NzaC1lZDI1NTE5"}, []string{"[BLOB]"}},
		{"connection to forbidden-site.example.com:443 reset", []string{"forbidden-site"}, []string{"[HOST]"}},
		{"api.example.net handshake ok", nil, []string{"api.example.net"}},
		{"started at 12:30:45 in conn.go", nil, []string{"12:30:45", "conn.go"}},
	}
	for _, tc := range cases {
		out := s.String(tc.in)
		for _, m := range tc.mustNot {
			if strings.Contains(out, m) {
				t.Errorf("leak %q in %q (input %q)", m, out, tc.in)
			}
		}
		for _, m := range tc.mustHave {
			if !strings.Contains(out, m) {
				t.Errorf("expected %q in %q", m, out)
			}
		}
	}
}

func TestSensitiveKey(t *testing.T) {
	for _, k := range []string{"ip", "client_ip", "remoteAddr", "user_agent", "UserAgent", "X-Forwarded-For", "password", "refresh_token", "totp_code", "account_number", "apiKey", "private-key", "email", "db.dsn"} {
		if !SensitiveKey(k) {
			t.Errorf("%q must be sensitive", k)
		}
	}
	for _, k := range []string{"request_id", "route", "status", "duration_ms", "description", "zip_level", "skip", "key_id", "method"} {
		if SensitiveKey(k) {
			t.Errorf("%q must not be sensitive", k)
		}
	}
}

func TestHandlerRedactsEverything(t *testing.T) {
	var buf bytes.Buffer
	log := NewLogger(&buf, slog.LevelDebug, Default)
	log = log.With("client_ip", markerIPv4)
	log.Info("login from "+markerIPv4,
		"email", markerEmail,
		"note", "contact "+markerEmail,
		slog.Group("req", "remote_addr", markerIPv6, "path", "/v1/x/"+markerUUID),
		"err", errors.New("dial "+markerIPv4+" failed"),
		"request_id", "req-1",
	)
	out := buf.String()
	for _, m := range []string{markerIPv4, markerIPv6, markerEmail, markerUUID} {
		if strings.Contains(out, m) {
			t.Fatalf("marker %q leaked: %s", m, out)
		}
	}
	if !strings.Contains(out, `"request_id":"req-1"`) {
		t.Fatalf("non-sensitive field lost: %s", out)
	}
}

func TestWriterLines(t *testing.T) {
	var dst bytes.Buffer
	w := NewWriter(&dst, New(Options{Hostnames: true}))
	_, _ = w.Write([]byte("ERROR dial " + markerIPv4))
	_, _ = w.Write([]byte(":443\nWARN blocked.example.com\npartial " + markerEmail))
	_ = w.Close()
	out := dst.String()
	if strings.Count(out, "\n") != 3 {
		t.Fatalf("want 3 lines, got %q", out)
	}
	for _, m := range []string{markerIPv4, "blocked.example.com", markerEmail} {
		if strings.Contains(out, m) {
			t.Fatalf("leak %q: %q", m, out)
		}
	}
}

func FuzzRedactNoLog(f *testing.F) {
	f.Add("prefix ", " suffix")
	f.Add("", "")
	f.Add("x=", ";")
	s := New(Options{Hostnames: true})
	f.Fuzz(func(t *testing.T, pre, post string) {
		for _, m := range []string{markerIPv4, markerEmail, markerUUID} {
			out := s.String(pre + " " + m + " " + post)
			if strings.Contains(out, m) {
				t.Fatalf("marker %q survived: %q", m, out)
			}
		}
	})
}
