// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package crash

import (
	"errors"
	"runtime/debug"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

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

func TestValidateEveryField(t *testing.T) {
	now := time.Date(2026, 11, 2, 12, 0, 0, 0, time.UTC)
	ok := apitypes.CrashReport{ID: strings.Repeat("ab", 16), Component: ComponentXray, Kind: KindSignal, AppVersion: "0.8.0",
		ComponentVersion: "26.9.30", OS: "android", Arch: "arm64", Day: "2026-11-03", Text: "SIGSEGV"}
	if err := Validate(ok, now); err != nil {
		t.Fatalf("tomorrow (clock skew) must be accepted: %v", err)
	}
	for name, mut := range map[string]func(*apitypes.CrashReport){
		"kind":              func(r *apitypes.CrashReport) { r.Kind = "oom" },
		"component_version": func(r *apitypes.CrashReport) { r.ComponentVersion = "v 1" },
		"arch":              func(r *apitypes.CrashReport) { r.Arch = "mips" },
		"long text":         func(r *apitypes.CrashReport) { r.Text = strings.Repeat("x", 2*MaxText+1) },
		"bad day":           func(r *apitypes.CrashReport) { r.Day = "02.11.2026" },
	} {
		r := ok
		mut(&r)
		if err := Validate(r, now); err == nil || !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestSanitizeLimits(t *testing.T) {
	var b strings.Builder
	for i := 0; i < MaxLines+50; i++ {
		b.WriteString("line\n")
	}
	if n := strings.Count(Sanitize(b.String()), "\n") + 1; n > MaxLines {
		t.Fatalf("%d lines kept", n)
	}
	long := strings.Repeat("ж", MaxLine+10)
	if got := Sanitize(long); utf8.RuneCountInString(got) != MaxLine+1 || !strings.HasSuffix(got, "…") {
		t.Fatalf("long line not cut: %d runes", utf8.RuneCountInString(got))
	}
	// Total size is bounded and the result stays valid UTF-8.
	b.Reset()
	for i := 0; i < MaxLines; i++ {
		b.WriteString(strings.Repeat("ж", MaxLine) + "\n")
	}
	got := Sanitize(b.String())
	if len(got) > MaxText || !utf8.ValidString(got) {
		t.Fatalf("size %d, valid %v", len(got), utf8.ValidString(got))
	}
	if Sanitize("bad \xff byte\r\n") != "bad ? byte" {
		t.Fatalf("invalid UTF-8 or CRLF: %q", Sanitize("bad \xff byte\r\n"))
	}
}

func TestSanitizeOddFrames(t *testing.T) {
	in := "goroutine 1 [running]:\n" +
		strings.Repeat("a", 210) + "(0x1)\n\t/x/y.go:1\n" + // too long to be a function name
		"weird name!(0x1)\n\t/x/y.go:2\n" + // not a Go identifier: scrubbed as text
		"main.main()\n\t/very/long/home/user/project/main.go:7 +0x1\n" +
		"main.f()\n\t/tmp/has space/x.go:9\n"
	got := Sanitize(in)
	if !strings.Contains(got, "user/project/main.go:7") || strings.Contains(got, "/very/long/home") {
		t.Fatalf("path not shortened:\n%s", got)
	}
	if !strings.Contains(got, "[PATH]:9") {
		t.Fatalf("odd path not replaced:\n%s", got)
	}
	if !strings.Contains(got, "weird name!(0x1)") {
		t.Fatalf("free text line lost:\n%s", got)
	}
}

func TestTitle(t *testing.T) {
	cases := map[string]string{
		"":                                        "",
		"\n\nfirst line\nsecond":                  "first line",
		"log\nfatal error: out of memory\nmore":   "fatal error: out of memory",
		"log\n[signal SIGSEGV]\n":                 "[signal SIGSEGV]",
		"log\nSIGABRT: abort\nPC=0x1":             "SIGABRT: abort",
		"log\njava.lang.IllegalStateException: x": "java.lang.IllegalStateException: x",
	}
	for in, want := range cases {
		if got := Title(in); got != want {
			t.Errorf("Title(%q) = %q, want %q", in, got, want)
		}
	}
	long := "panic: " + strings.Repeat("я", 200)
	if got := Title(long); utf8.RuneCountInString(got) != 161 {
		t.Fatalf("title not cut: %d", utf8.RuneCountInString(got))
	}
}

func TestSignatureSkipsFrameworkFrames(t *testing.T) {
	java := "java.lang.RuntimeException: boom\n" +
		"\tat java.lang.Thread.run(Thread.java:1)\n" +
		"\tat kotlinx.coroutines.Job.x(Job.kt:2)\n" +
		"\tat net.veilon.app.A.a(A.kt:3)\n\tat net.veilon.app.B.b(B.kt:4)\n\tat net.veilon.app.C.c(C.kt:5)\n" +
		"\tat net.veilon.app.D.d(D.kt:6)\n\tat net.veilon.app.E.e(E.kt:7)\n\tat net.veilon.app.F.f(F.kt:8)\n"
	frames := framesForSignature(java)
	if len(frames) != 5 || frames[0] != "net.veilon.app.A.a" {
		t.Fatalf("frames %v", frames)
	}
	moved := strings.ReplaceAll(java, "A.kt:3", "A.kt:300")
	if Signature("android", KindException, java) != Signature("android", KindException, moved) {
		t.Fatal("line move changed the signature")
	}
	if Signature("android", KindException, java) == Signature("desktop", KindException, java) {
		t.Fatal("component not part of the signature")
	}
	// Without frames the digit-free title groups reports.
	if Signature("xray", KindSignal, "exit status 2") != Signature("xray", KindSignal, "exit status 9") {
		t.Fatal("digits in the title split the group")
	}
}

func TestFaultSignalAndToday(t *testing.T) {
	for _, s := range []string{"SIGSEGV", "SIGBUS", "SIGILL", "SIGFPE", "SIGABRT", "SIGTRAP", "SIGSYS"} {
		if !FaultSignal(s) {
			t.Errorf("%s not a fault", s)
		}
	}
	for _, s := range []string{"SIGTERM", "SIGKILL", "SIGINT", ""} {
		if FaultSignal(s) {
			t.Errorf("%s reported as a fault", s)
		}
	}
	loc := time.FixedZone("UTC+3", 3*3600)
	if got := Today(time.Date(2026, 11, 2, 1, 0, 0, 0, loc)); got != "2026-11-01" {
		t.Fatalf("Today must use UTC: %s", got)
	}
}
