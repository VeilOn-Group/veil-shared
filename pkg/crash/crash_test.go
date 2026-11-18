// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package crash

import (
	"runtime/debug"
	"strings"
	"testing"
	"time"

	"github.com/veilon/veil-shared/pkg/apitypes"
)

// goPanic is shaped like real Go 1.24 output; the markers below must not
// survive sanitization.
const goPanic = `some earlier log line about 203.0.113.9
panic: dial tcp 198.51.100.77:443: connect to canary-7f3a.example.org failed for alice@example.net [recovered]
	panic: dial tcp 198.51.100.77:443: connect to canary-7f3a.example.org failed

goroutine 42 gp=0xc000102a80 m=3 mp=0xc000080008 [running]:
github.com/veilon/veilon-app/veilond/internal/core.(*Manager).connect(0xc0001a2000, {0x7a1b20, 0xc00011e0f0}, 0x1bb)
	/home/alice/src/veilon-app/veilond/internal/core/manager.go:512 +0x1d4
github.com/sagernet/sing-box/route.(*Router).RouteConnection(...)
	/home/alice/go/pkg/mod/github.com/sagernet/sing-box@v1.13.21/route/route.go:88
created by github.com/veilon/veilon-app/veilond/internal/core.(*Manager).Connect in goroutine 1
	C:\Users\alice\veilon\veilond\internal\core\manager.go:430 +0x9a
[signal SIGSEGV: segmentation violation code=0x1 addr=0x18 pc=0x4a1b2c]
rax    0x0
rip    0x4a1b2c
exit status 2`

func TestSanitizeGo(t *testing.T) {
	s := Sanitize(goPanic)
	for _, bad := range []string{"203.0.113.9", "198.51.100.77", "canary-7f3a", "example.org", "alice", "0xc0001a2000", "0x1d4", "pc=0x", "rip", "gp=0x", "/home/"} {
		if strings.Contains(s, bad) {
			t.Errorf("%q survived:\n%s", bad, s)
		}
	}
	for _, want := range []string{
		"goroutine 42 [running]:",
		"github.com/veilon/veilon-app/veilond/internal/core.(*Manager).connect(...)",
		"\tinternal/core/manager.go:512",
		"github.com/sagernet/sing-box/route.(*Router).RouteConnection(...)",
		"\tsing-box@v1.13.21/route/route.go:88",
		"created by github.com/veilon/veilon-app/veilond/internal/core.(*Manager).Connect",
		"\tinternal/core/manager.go:430",
		"[signal SIGSEGV]",
		"exit status 2",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("missing %q in:\n%s", want, s)
		}
	}
	if got := Title(s); !strings.HasPrefix(got, "panic: dial tcp [IP]:443") {
		t.Errorf("title %q", got)
	}
	if Sanitize(s) != s {
		t.Error("Sanitize is not idempotent (the server re-sanitizes)")
	}
}

func TestSignatureStableAcrossArgsAndLines(t *testing.T) {
	a := Sanitize(goPanic)
	b := Sanitize(strings.NewReplacer("0xc0001a2000", "0xc0009f0000", ":512", ":530", "198.51.100.77", "192.0.2.1", "goroutine 42", "goroutine 7").Replace(goPanic))
	if Signature(ComponentVeilond, KindPanic, a) != Signature(ComponentVeilond, KindPanic, b) {
		t.Fatal("same bug must group together")
	}
	c := Sanitize(strings.ReplaceAll(goPanic, "(*Manager).connect(", "(*Manager).reconnect("))
	if Signature(ComponentVeilond, KindPanic, a) == Signature(ComponentVeilond, KindPanic, c) {
		t.Fatal("different top frame must give a different group")
	}
	if Signature(ComponentVeilond, KindPanic, a) == Signature(ComponentSingBox, KindPanic, a) {
		t.Fatal("component is part of the signature")
	}
}

func TestSanitizeRealTraceback(t *testing.T) {
	var trace string
	func() {
		defer func() {
			_ = recover()
			trace = "panic: test\n\n" + string(debug.Stack())
		}()
		panic("test")
	}()
	s := Sanitize(trace)
	if !strings.Contains(s, "crash.TestSanitizeRealTraceback") || !strings.Contains(s, "crash/crash_test.go:") {
		t.Fatalf("frames lost:\n%s", s)
	}
	if strings.Contains(s, "+0x") {
		t.Fatalf("pc offsets kept:\n%s", s)
	}
}

func TestSanitizeJava(t *testing.T) {
	in := `Exception in thread "worker-alice" java.lang.IllegalStateException: no route to 10.1.2.3 via vpn.example.com
	at net.veilon.app.vpn.LibboxPlatform.openTun(LibboxPlatform.kt:120)
	at net.veilon.app.vpn.VeilOnVpnService.onStartCommand(VeilOnVpnService.kt:44)
	at android.app.ActivityThread.handleServiceArgs(ActivityThread.java:5014)
Caused by: java.io.IOException: token=abcdef0123456789abcdef
	at java.net.Socket.connect(Socket.java:621)
	... 12 more`
	s := Sanitize(in)
	for _, bad := range []string{"alice", "10.1.2.3", "vpn.example.com", "abcdef0123456789"} {
		if strings.Contains(s, bad) {
			t.Errorf("%q survived:\n%s", bad, s)
		}
	}
	for _, want := range []string{"java.lang.IllegalStateException: no route to [IP]", "\tat net.veilon.app.vpn.LibboxPlatform.openTun(LibboxPlatform.kt:120)", "Caused by: java.io.IOException", "\t... 12 more"} {
		if !strings.Contains(s, want) {
			t.Errorf("missing %q in:\n%s", want, s)
		}
	}
	if got := Title(s); !strings.HasPrefix(got, "java.lang.IllegalStateException") {
		t.Errorf("title %q", got)
	}
	if f := framesForSignature(s); len(f) == 0 || f[0] != "net.veilon.app.vpn.LibboxPlatform.openTun" {
		t.Errorf("frames %v", f)
	}
}

func TestFromGoOutput(t *testing.T) {
	if _, ok := FromGoOutput("FATAL[0000] start service: bind: address already in use\n"); ok {
		t.Fatal("an error exit is not a crash")
	}
	tb, ok := FromGoOutput("INFO started\nfatal error: concurrent map writes\n\ngoroutine 1 [running]:\n")
	if !ok || !strings.HasPrefix(tb, "fatal error: concurrent map writes") {
		t.Fatalf("%q %v", tb, ok)
	}
	if tb, ok := FromGoOutput("x\nSIGSEGV: segmentation violation\nPC=0x1 m=0 sigcode=1\n"); !ok || Title(Sanitize(tb)) != "SIGSEGV: segmentation violation" {
		t.Fatalf("runtime signal report: %q", tb)
	}
	if _, ok := FromGoOutput("log says panic: in the middle of a line\n"); ok {
		t.Fatal("panic: must start a line")
	}
}

func TestValidate(t *testing.T) {
	now := time.Date(2026, 11, 2, 12, 0, 0, 0, time.UTC)
	ok := apitypes.CrashReport{ID: strings.Repeat("ab", 16), Component: ComponentVeilond, Kind: KindPanic, AppVersion: "0.8.0",
		OS: "linux", Arch: "amd64", Day: "2026-11-01", Text: "panic: x"}
	if err := Validate(ok, now); err != nil {
		t.Fatal(err)
	}
	for name, mut := range map[string]func(*apitypes.CrashReport){
		"id":        func(r *apitypes.CrashReport) { r.ID = "x" },
		"component": func(r *apitypes.CrashReport) { r.Component = "browser" },
		"os":        func(r *apitypes.CrashReport) { r.OS = "plan9" },
		"version":   func(r *apitypes.CrashReport) { r.AppVersion = "1.0 beta" },
		"old":       func(r *apitypes.CrashReport) { r.Day = "2026-09-01" },
		"future":    func(r *apitypes.CrashReport) { r.Day = "2026-11-05" },
		"empty":     func(r *apitypes.CrashReport) { r.Text = " " },
	} {
		r := ok
		mut(&r)
		if Validate(r, now) == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
