// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Package tmpl implements the node config templates of the raw config
// editor: a template is an ordinary core config (Xray or
// sing-box JSON) in which some values are tokens. A token is a JSON string
// that is exactly "$veilon:<name>"; rendering replaces it with the value of
// <name> (any JSON type: a string, a number, a list of users). Secrets and
// user lists therefore never appear in a template, and a template follows
// the panel's parameters (domain, ports, keys) without being edited again.
//
// Two special forms keep optional parts expressible in plain JSON:
//   - a value of Omit removes the member (or list element) that holds it;
//   - an object with the member "$veilon:when": "<name>" is kept only when
//     the value of <name> is true (the member itself is removed).
//
// The package also implements JSON Merge Patch (RFC 7396), used for the
// client outbound patches.
package tmpl

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// Prefix starts every token.
const Prefix = "$veilon:"

// MaxSize bounds a template or patch (bytes).
const MaxSize = 256 << 10

// When is the member name of a conditional object.
const When = Prefix + "when"

type omitT struct{}

// Omit as a token value removes the member or list element.
var Omit any = omitT{}

// ErrTemplate reports an invalid template or patch.
var ErrTemplate = errors.New("tmpl: invalid template")

var reName = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)

// Token returns the token string for name.
func Token(name string) string { return Prefix + name }

// Doc is a decoded JSON object.
type Doc = map[string]any

// Parse decodes a template: one JSON object, numbers kept exact, size
// bounded, no trailing data.
func Parse(raw []byte) (Doc, error) {
	if len(raw) > MaxSize {
		return nil, fmt.Errorf("%w: larger than %d KiB", ErrTemplate, MaxSize>>10)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrTemplate, err)
	}
	if dec.More() {
		return nil, fmt.Errorf("%w: trailing data after the JSON object", ErrTemplate)
	}
	if _, err := dec.Token(); err == nil {
		return nil, fmt.Errorf("%w: trailing data after the JSON object", ErrTemplate)
	}
	d, ok := v.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("%w: must be a JSON object", ErrTemplate)
	}
	return d, nil
}

// Tokens lists the token names used in v (sorted, unique) and reports
// malformed ones ("$veilon:" followed by an invalid name).
func Tokens(v any) ([]string, error) {
	seen := map[string]bool{}
	var bad []string
	walk(v, func(s string) {
		if !strings.HasPrefix(s, Prefix) {
			return
		}
		n := strings.TrimPrefix(s, Prefix)
		if s == When {
			return
		}
		if !reName.MatchString(n) {
			bad = append(bad, s)
			return
		}
		seen[n] = true
	})
	out := make([]string, 0, len(seen))
	for n := range seen {
		out = append(out, n)
	}
	sort.Strings(out)
	if len(bad) > 0 {
		return out, fmt.Errorf("%w: malformed token %q", ErrTemplate, bad[0])
	}
	return out, nil
}

func walk(v any, f func(string)) {
	switch x := v.(type) {
	case string:
		f(x)
	case map[string]any:
		for k, e := range x {
			if k == When {
				if n, ok := e.(string); ok {
					f(Prefix + n)
				}
				continue
			}
			walk(e, f)
		}
	case []any:
		for _, e := range x {
			walk(e, f)
		}
	}
}

// Render returns a deep copy of tpl with every token replaced by its value.
// Unknown tokens are an error. Values are converted to plain JSON values
// first (structs and typed slices become maps and lists).
func Render(tpl Doc, values map[string]any) (Doc, error) {
	plain := make(map[string]any, len(values))
	for k, v := range values {
		if v == Omit {
			plain[k] = v
			continue
		}
		p, err := toPlain(v)
		if err != nil {
			return nil, fmt.Errorf("%w: value %s: %w", ErrTemplate, k, err)
		}
		plain[k] = p
	}
	var missing []string
	out := render(tpl, plain, &missing)
	if len(missing) > 0 {
		sort.Strings(missing)
		return nil, fmt.Errorf("%w: unknown token %s%s", ErrTemplate, Prefix, missing[0])
	}
	m, ok := out.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("%w: the root object is conditional", ErrTemplate)
	}
	return m, nil
}

// keep evaluates the "$veilon:when" member of an object.
func keep(x map[string]any, values map[string]any, missing *[]string) bool {
	w, ok := x[When]
	if !ok {
		return true
	}
	n, _ := w.(string)
	v, ok := values[n]
	if !ok {
		*missing = append(*missing, n)
		return true
	}
	b, _ := v.(bool)
	return b
}

func render(v any, values map[string]any, missing *[]string) any {
	switch x := v.(type) {
	case string:
		if !strings.HasPrefix(x, Prefix) {
			return x
		}
		n := strings.TrimPrefix(x, Prefix)
		val, ok := values[n]
		if !ok {
			*missing = append(*missing, n)
			return x
		}
		return deepCopy(val)
	case map[string]any:
		if !keep(x, values, missing) {
			return Omit
		}
		m := make(map[string]any, len(x))
		for k, e := range x {
			if k == When {
				continue
			}
			if r := render(e, values, missing); r != Omit {
				m[k] = r
			}
		}
		return m
	case []any:
		l := make([]any, 0, len(x))
		for _, e := range x {
			if r := render(e, values, missing); r != Omit {
				l = append(l, r)
			}
		}
		return l
	default:
		return x
	}
}

func deepCopy(v any) any {
	switch x := v.(type) {
	case map[string]any:
		m := make(map[string]any, len(x))
		for k, e := range x {
			m[k] = deepCopy(e)
		}
		return m
	case []any:
		l := make([]any, len(x))
		for i, e := range x {
			l[i] = deepCopy(e)
		}
		return l
	default:
		return x
	}
}

func toPlain(v any) (any, error) {
	switch v.(type) {
	case nil, string, bool, json.Number, map[string]any, []any:
		return v, nil
	}
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var out any
	if err := dec.Decode(&out); err != nil {
		return nil, err
	}
	return out, nil
}

// FromValue converts a Go value (typically a typed config struct) to a Doc.
func FromValue(v any) (Doc, error) {
	p, err := toPlain(v)
	if err != nil {
		return nil, err
	}
	d, ok := p.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("%w: not an object", ErrTemplate)
	}
	return d, nil
}

// Marshal renders d as indented JSON with sorted keys and a final newline.
func Marshal(d any) ([]byte, error) {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(d); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

// MergePatch applies an RFC 7396 JSON Merge Patch to target and returns the
// result (target is not modified). null in the patch deletes a member.
func MergePatch(target, patch Doc) Doc {
	out := deepCopy(target).(map[string]any)
	for k, pv := range patch {
		if pv == nil {
			delete(out, k)
			continue
		}
		if pm, ok := pv.(map[string]any); ok {
			tm, _ := out[k].(map[string]any)
			if tm == nil {
				tm = map[string]any{}
			}
			out[k] = MergePatch(tm, pm)
			continue
		}
		out[k] = deepCopy(pv)
	}
	return out
}

// Get walks a path of object keys and returns the value (nil if absent).
func Get(d Doc, path ...string) any {
	var cur any = d
	for _, p := range path {
		m, ok := cur.(map[string]any)
		if !ok {
			return nil
		}
		cur = m[p]
	}
	return cur
}

// Objects returns the elements of the list at d[key] that are objects.
func Objects(d Doc, key string) []Doc {
	l, _ := d[key].([]any)
	var out []Doc
	for _, e := range l {
		if m, ok := e.(map[string]any); ok {
			out = append(out, m)
		}
	}
	return out
}

// FindKey reports the first path at which key occurs anywhere in v with a
// value accepted by match ("" if none).
func FindKey(v any, key string, match func(any) bool) string {
	var found string
	var rec func(any, string)
	rec = func(v any, path string) {
		if found != "" {
			return
		}
		switch x := v.(type) {
		case map[string]any:
			keys := make([]string, 0, len(x))
			for k := range x {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			for _, k := range keys {
				p := path + "." + k
				if k == key && match(x[k]) {
					found = strings.TrimPrefix(p, ".")
					return
				}
				rec(x[k], p)
			}
		case []any:
			for i, e := range x {
				rec(e, fmt.Sprintf("%s[%d]", path, i))
			}
		}
	}
	rec(v, "")
	return found
}

// Truthy reports a JSON true, a non-zero number or a non-empty string.
func Truthy(v any) bool {
	switch x := v.(type) {
	case bool:
		return x
	case string:
		return x != ""
	case json.Number:
		return x.String() != "0"
	case float64:
		return x != 0
	case nil:
		return false
	default:
		return true
	}
}
