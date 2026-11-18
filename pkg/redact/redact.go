// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Package redact removes personal data and secrets from text and structured
// logs. It is mandatory in every VeilOn binary: servers wrap their
// slog handler with Handler, the client filters sing-box output through Writer,
// and the support module uses Scrubber before sending text to an LLM.
package redact

import (
	"net/netip"
	"regexp"
	"strings"
	"unicode"
)

// Placeholder values. Kept short and greppable.
const (
	Redacted = "[REDACTED]"
	tagIP    = "[IP]"
	tagEmail = "[EMAIL]"
	tagUUID  = "[UUID]"
	tagJWT   = "[JWT]"
	tagNum   = "[NUM]"
	tagBlob  = "[BLOB]"
	tagHost  = "[HOST]"
)

// Options select optional, more aggressive rules.
type Options struct {
	// Hostnames also replaces DNS names. Enabled for client logs and
	// diagnostics (no destinations may survive); disabled on servers
	// where log messages are code-controlled.
	Hostnames bool
	// KeepHosts lists hostnames that may stay visible (e.g. our API domains).
	KeepHosts []string
}

// Scrubber applies the rules. Safe for concurrent use.
type Scrubber struct {
	opts Options
	keep map[string]bool
}

// New returns a Scrubber.
func New(opts Options) *Scrubber {
	keep := make(map[string]bool, len(opts.KeepHosts))
	for _, h := range opts.KeepHosts {
		keep[strings.ToLower(h)] = true
	}
	return &Scrubber{opts: opts, keep: keep}
}

// Default is the server-side scrubber.
var Default = New(Options{})

var (
	reKeyValueSecret = regexp.MustCompile(`(?i)\b(password|passwd|pwd|secret|token|api[_-]?key|private[_-]?key|access[_-]?key|cookie|set-cookie|sign|signature|authorization)(["']?\s*[:=]\s*)("[^"]*"|'[^']*'|(?:bearer\s+|basic\s+)?[^\s,;&"']+)`)
	reBearer         = regexp.MustCompile(`(?i)\b(bearer|basic)(\s+)[A-Za-z0-9._~+/=-]{8,}`)
	reJWT            = regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]*`)
	reEmail          = regexp.MustCompile(`(?i)[a-z0-9._%+-]+@[a-z0-9-]+(?:\.[a-z0-9-]+)*\.[a-z]{2,}`)
	reUUID           = regexp.MustCompile(`(?i)\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b`)
	reIPv4           = regexp.MustCompile(`\b(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}\b`)
	reIPv6Candidate  = regexp.MustCompile(`(?i)\[?[0-9a-f]{0,4}(?::[0-9a-f]{0,4}){2,7}(?:%[0-9a-z]+)?\]?`)
	reLongDigits     = regexp.MustCompile(`\b\d(?:[ -]?\d){11,22}\b`)
	reBlob           = regexp.MustCompile(`[A-Za-z0-9+/_-]{40,}={0,2}`)
	reHostname       = regexp.MustCompile(`(?i)\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:[a-z][a-z0-9-]{0,61}[a-z0-9])\b`)
)

// String scrubs free text. Order matters: secrets and structured tokens first,
// generic patterns last.
func (s *Scrubber) String(in string) string {
	if in == "" {
		return in
	}
	out := reKeyValueSecret.ReplaceAllString(in, "$1$2"+Redacted)
	out = reBearer.ReplaceAllString(out, "$1$2"+Redacted)
	out = reJWT.ReplaceAllString(out, tagJWT)
	out = reEmail.ReplaceAllString(out, tagEmail)
	out = reUUID.ReplaceAllString(out, tagUUID)
	out = reIPv6Candidate.ReplaceAllStringFunc(out, func(m string) string {
		trimmed := strings.Trim(m, "[]")
		if i := strings.IndexByte(trimmed, '%'); i >= 0 {
			trimmed = trimmed[:i]
		}
		if a, err := netip.ParseAddr(trimmed); err == nil && a.Is6() {
			return tagIP
		}
		return m
	})
	out = reIPv4.ReplaceAllString(out, tagIP)
	out = reLongDigits.ReplaceAllString(out, tagNum)
	out = reBlob.ReplaceAllString(out, tagBlob)
	if s.opts.Hostnames {
		out = reHostname.ReplaceAllStringFunc(out, func(m string) string {
			if s.keep[strings.ToLower(m)] || isPlaceholderLike(m) {
				return m
			}
			return tagHost
		})
	}
	return out
}

// isPlaceholderLike keeps Go file references such as "conn.go" readable.
func isPlaceholderLike(m string) bool {
	return strings.HasSuffix(m, ".go")
}

// denyTokens: any key containing one of these tokens is fully redacted.
var denyTokens = map[string]bool{
	"password": true, "passwd": true, "pwd": true, "secret": true, "token": true,
	"authorization": true, "cookie": true, "email": true, "ip": true, "ips": true,
	"ua": true, "useragent": true, "uuid": true, "seed": true, "signature": true,
	"sig": true, "otp": true, "totp": true, "pin": true, "pepper": true,
	"credential": true, "credentials": true, "dsn": true, "phone": true, "addr": true,
}

// denyPairs: adjacent token pairs that mark a secret/PII key.
var denyPairs = map[[2]string]bool{
	{"api", "key"}: true, {"private", "key"}: true, {"secret", "key"}: true, {"access", "key"}: true,
	{"user", "agent"}: true, {"remote", "addr"}: true, {"account", "number"}: true,
	{"forwarded", "for"}: true, {"real", "ip"}: true, {"client", "ip"}: true,
}

// SensitiveKey reports whether a structured-log key must have its value removed.
func SensitiveKey(key string) bool {
	toks := tokenize(key)
	for i, t := range toks {
		if denyTokens[t] {
			return true
		}
		if i+1 < len(toks) && denyPairs[[2]string{t, toks[i+1]}] {
			return true
		}
	}
	return false
}

// tokenize splits snake_case, kebab-case, dotted and camelCase keys.
func tokenize(key string) []string {
	var toks []string
	var cur []rune
	flush := func() {
		if len(cur) > 0 {
			toks = append(toks, strings.ToLower(string(cur)))
			cur = cur[:0]
		}
	}
	runes := []rune(key)
	for i, r := range runes {
		switch {
		case !unicode.IsLetter(r) && !unicode.IsDigit(r):
			flush()
		case unicode.IsUpper(r) && i > 0 && (unicode.IsLower(runes[i-1]) || (i+1 < len(runes) && unicode.IsLower(runes[i+1]) && unicode.IsUpper(runes[i-1]))):
			flush()
			cur = append(cur, r)
		default:
			cur = append(cur, r)
		}
	}
	flush()
	return toks
}
