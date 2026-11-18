// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Package crash turns crash output (Go tracebacks, JVM stack traces, the
// tail of a core process) into anonymous reports.
//
// Sanitize keeps the structure a developer needs (function names, short
// source paths, line numbers) and removes what could identify a user or a
// destination: argument words, addresses and program counters, absolute
// paths (home directories), and every free-text line goes through the
// hostname-aware redactor (IPs, hosts, e-mails, UUIDs, tokens, long
// numbers). The device sanitizes before storing or sending; the server
// sanitizes again and recomputes the signature.
package crash

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/veilon/veil-shared/pkg/apitypes"
	"github.com/veilon/veil-shared/pkg/redact"
)

// Components that may report.
const (
	ComponentVeilond = "veilond"
	ComponentSingBox = "sing-box"
	ComponentXray    = "xray"
	ComponentNaive   = "naive"
	ComponentDesktop = "desktop"
	ComponentAndroid = "android"
)

// Kinds of crash.
const (
	KindPanic     = "panic"     // Go panic or fatal error with a traceback
	KindSignal    = "signal"    // killed by a fault signal / exception code
	KindException = "exception" // uncaught JVM exception
)

// Limits.
const (
	MaxText    = 32 << 10 // bytes of sanitized text
	MaxLines   = 400
	MaxLine    = 300 // runes per free-text line
	MaxAgeDays = 30  // older reports are refused and pruned on the device
	MaxQueued  = 10  // reports kept on the device
)

var (
	components = map[string]bool{ComponentVeilond: true, ComponentSingBox: true, ComponentXray: true, ComponentNaive: true, ComponentDesktop: true, ComponentAndroid: true}
	kinds      = map[string]bool{KindPanic: true, KindSignal: true, KindException: true}
	oses       = map[string]bool{"linux": true, "darwin": true, "windows": true, "android": true}
	arches     = map[string]bool{"amd64": true, "arm64": true, "386": true, "arm": true}
	reID       = regexp.MustCompile(`^[0-9a-f]{32}$`)
	reVersion  = regexp.MustCompile(`^[0-9A-Za-z][0-9A-Za-z.+-]{0,31}$`)
)

// ErrInvalid reports a malformed report.
var ErrInvalid = errors.New("crash: invalid report")

// Validate checks the shape of r (not its text, which Sanitize rewrites).
func Validate(r apitypes.CrashReport, now time.Time) error {
	bad := func(f string) error { return fmt.Errorf("%w: %s", ErrInvalid, f) }
	switch {
	case !reID.MatchString(r.ID):
		return bad("id")
	case !components[r.Component]:
		return bad("component")
	case !kinds[r.Kind]:
		return bad("kind")
	case !reVersion.MatchString(r.AppVersion):
		return bad("app_version")
	case r.ComponentVersion != "" && !reVersion.MatchString(r.ComponentVersion):
		return bad("component_version")
	case !oses[r.OS]:
		return bad("os")
	case !arches[r.Arch]:
		return bad("arch")
	case strings.TrimSpace(r.Text) == "" || len(r.Text) > 2*MaxText:
		return bad("text")
	}
	d, err := time.Parse(time.DateOnly, r.Day)
	if err != nil {
		return bad("day")
	}
	today := now.UTC().Truncate(24 * time.Hour)
	if d.After(today.AddDate(0, 0, 1)) || d.Before(today.AddDate(0, 0, -MaxAgeDays)) {
		return bad("day out of range")
	}
	return nil
}

var scrub = redact.New(redact.Options{Hostnames: true})

var (
	reGoroutine = regexp.MustCompile(`^goroutine (\d+)(?: [^\[]*)?\[([^\]]{1,64})\]:$`)
	reGoFile    = regexp.MustCompile(`^\t(.+?):(\d+)(?: \+0x[0-9a-f]+)?$`)
	reGoArgs    = regexp.MustCompile(`\((?:0x[0-9a-f]+|\.\.\.|\{[^}]*\}|[0-9a-fx?, ]+)*\)$`)
	reGoFunc    = regexp.MustCompile(`^[A-Za-z0-9_./*()\[\]{},$~\-]+$`)
	reSignal    = regexp.MustCompile(`^\[signal (SIG[A-Z]+)[^\]]*\]$`)
	reRegister  = regexp.MustCompile(`^(?:[a-z]{1,3}[0-9]{0,2}|rip|rflags|PC|pc|lr|sp|fp)\s*[=:]?\s+0x[0-9a-f]+\b|^PC=0x|^signal arrived during`)
	reJavaAt    = regexp.MustCompile(`^\s*at ([A-Za-z_$][\w$.<>\-]*)\(([\w$.\-]+:\d+|Native Method|Unknown Source)\)$`)
	reJavaMore  = regexp.MustCompile(`^\s*\.\.\. \d+ more$`)
	reJavaHead  = regexp.MustCompile(`^(\s*)(Caused by: |Suppressed: |Exception in thread "[^"]{0,64}" )?([A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)+)(?:: (.*))?$`)
	reExitCode  = regexp.MustCompile(`^exit (?:status|code) -?\d+$`)
	reGoSignal  = regexp.MustCompile(`^SIG[A-Z]{2,7}: [a-z ]{2,40}$`)
)

// Sanitize rewrites crash text as described in the package comment.
func Sanitize(text string) string {
	text = strings.ToValidUTF8(strings.ReplaceAll(text, "\r\n", "\n"), "?")
	lines := strings.Split(text, "\n")
	if len(lines) > MaxLines {
		lines = lines[:MaxLines]
	}
	var out []string
	for i, l := range lines {
		next := ""
		if i+1 < len(lines) {
			next = lines[i+1]
		}
		if s, ok := sanitizeLine(l, next); ok {
			out = append(out, s)
		}
	}
	res := strings.TrimSpace(strings.Join(out, "\n"))
	if len(res) > MaxText {
		res = res[:MaxText]
		for !utf8.ValidString(res) {
			res = res[:len(res)-1]
		}
	}
	return res
}

func sanitizeLine(l, next string) (string, bool) {
	l = strings.TrimRight(l, " \t")
	if l == "" {
		return "", true
	}
	if m := reGoroutine.FindStringSubmatch(l); m != nil {
		return "goroutine " + m[1] + " [" + scrubShort(m[2]) + "]:", true
	}
	if m := reGoFile.FindStringSubmatch(l); m != nil {
		return "\t" + shortPath(m[1]) + ":" + m[2], true
	}
	if m := reSignal.FindStringSubmatch(l); m != nil {
		return "[signal " + m[1] + "]", true
	}
	if reRegister.MatchString(l) {
		return "", false
	}
	if reExitCode.MatchString(l) {
		return l, true
	}
	if !strings.HasPrefix(l, "\t") && reGoFile.MatchString(next) {
		if name, ok := goFunc(l); ok {
			return name, true
		}
	}
	if m := reJavaAt.FindStringSubmatch(l); m != nil {
		return "\tat " + m[1] + "(" + m[2] + ")", true
	}
	if reJavaMore.MatchString(l) {
		return "\t" + strings.TrimSpace(l), true
	}
	if m := reJavaHead.FindStringSubmatch(l); m != nil && isThrowable(m[3]) {
		// The thread name of "Exception in thread ..." is dropped.
		s := m[1] + m[3]
		if strings.HasPrefix(m[2], "Caused by") || strings.HasPrefix(m[2], "Suppressed") {
			s = m[1] + m[2] + m[3]
		}
		if m[4] != "" {
			s += ": " + scrubShort(m[4])
		}
		return s, true
	}
	return scrubShort(strings.TrimLeft(l, "\t ")), true
}

// goFunc parses a traceback function line: "pkg.Func(0x1, 0x2)",
// "created by pkg.F in goroutine 7", "panic({0x5a, 0xc0})".
func goFunc(l string) (string, bool) {
	prefix := ""
	if s, ok := strings.CutPrefix(l, "created by "); ok {
		prefix, l = "created by ", s
	}
	if i := strings.Index(l, " in goroutine "); i > 0 {
		l = l[:i]
	}
	args := ""
	if loc := reGoArgs.FindStringIndex(l); loc != nil {
		l, args = l[:loc[0]], "(...)"
	}
	if !reGoFunc.MatchString(l) || len(l) > 200 {
		return "", false
	}
	return prefix + l + args, true
}

func isThrowable(class string) bool {
	last := class[strings.LastIndexByte(class, '.')+1:]
	return strings.HasSuffix(last, "Exception") || strings.HasSuffix(last, "Error") || last == "Throwable"
}

// shortPath keeps the last three path elements: enough to find the file
// in the source tree, never the build machine's or user's home directory.
func shortPath(p string) string {
	p = strings.ReplaceAll(p, `\`, "/")
	parts := strings.Split(p, "/")
	if len(parts) > 3 {
		parts = parts[len(parts)-3:]
	}
	s := strings.Join(parts, "/")
	if !reGoFunc.MatchString(strings.ReplaceAll(s, "@", "")) {
		return "[PATH]"
	}
	return s
}

func scrubShort(s string) string {
	s = scrub.String(s)
	if utf8.RuneCountInString(s) > MaxLine {
		s = string([]rune(s)[:MaxLine]) + "…"
	}
	return s
}

// Title is a one-line summary of sanitized text for lists.
func Title(text string) string {
	first := ""
	for _, l := range strings.Split(text, "\n") {
		t := strings.TrimSpace(l)
		if t == "" {
			continue
		}
		if first == "" {
			first = t
		}
		if strings.HasPrefix(t, "panic: ") || strings.HasPrefix(t, "fatal error: ") || strings.HasPrefix(t, "[signal ") || reGoSignal.MatchString(t) ||
			(reJavaHead.MatchString(t) && !strings.HasPrefix(t, "at ")) {
			first = t
			break
		}
	}
	if utf8.RuneCountInString(first) > 160 {
		first = string([]rune(first)[:160]) + "…"
	}
	return first
}

// framesForSignature lists up to five application frames: runtime and
// framework frames are skipped so that the same bug groups together even
// if it is reached through a different runtime path.
func framesForSignature(text string) []string {
	lines := strings.Split(text, "\n")
	var out []string
	for i, l := range lines {
		var name string
		if m := reJavaAt.FindStringSubmatch(l); m != nil {
			name = m[1]
		} else if i+1 < len(lines) && !strings.HasPrefix(l, "\t") && reGoFile.MatchString(lines[i+1]) {
			name = strings.TrimSuffix(strings.TrimPrefix(l, "created by "), "(...)")
		} else {
			continue
		}
		if skipFrame(name) {
			continue
		}
		out = append(out, name)
		if len(out) == 5 {
			break
		}
	}
	return out
}

func skipFrame(name string) bool {
	for _, p := range []string{"runtime.", "runtime/", "panic", "java.lang.Thread.", "java.lang.reflect.", "kotlin.", "kotlinx.coroutines.", "android.os.", "com.android.internal.", "dalvik."} {
		if strings.HasPrefix(name, p) {
			return true
		}
	}
	return false
}

var reDigits = regexp.MustCompile(`[0-9]+`)

// Signature groups reports of the same bug: component, kind and the top
// application frames (function names only, so line moves between
// versions keep the group); without frames, the digit-free title.
func Signature(component, kind, text string) string {
	key := strings.Join(framesForSignature(text), "\n")
	if key == "" {
		key = reDigits.ReplaceAllString(Title(text), "N")
	}
	sum := sha256.Sum256([]byte(component + "\x00" + kind + "\x00" + key))
	return hex.EncodeToString(sum[:16])
}

// goMarks start a Go runtime crash report: a panic, a fatal error, or a
// fatal signal caught by the runtime ("SIGSEGV: segmentation violation").
var goMarks = []string{"panic: ", "fatal error: ", "SIGSEGV: ", "SIGBUS: ", "SIGILL: ", "SIGFPE: ", "SIGABRT: ", "SIGTRAP: ", "SIGSYS: "}

// FromGoOutput extracts the traceback from the tail of a Go program's
// output: from the first line starting a runtime crash report to the end.
// ok is false when there is no traceback (a normal error exit).
func FromGoOutput(tail string) (string, bool) {
	best := -1
	for _, mark := range goMarks {
		for off := 0; ; {
			i := strings.Index(tail[off:], mark)
			if i < 0 {
				break
			}
			at := off + i
			if at == 0 || tail[at-1] == '\n' {
				if best < 0 || at < best {
					best = at
				}
				break
			}
			off = at + len(mark)
		}
	}
	if best < 0 {
		return "", false
	}
	return tail[best:], true
}

// FaultSignal reports whether a signal name means the process crashed
// (as opposed to being stopped).
func FaultSignal(name string) bool {
	switch name {
	case "SIGSEGV", "SIGBUS", "SIGILL", "SIGFPE", "SIGABRT", "SIGTRAP", "SIGSYS":
		return true
	}
	return false
}

// Today is the report day for now (UTC).
func Today(now time.Time) string { return now.UTC().Format(time.DateOnly) }
