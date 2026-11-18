// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package tmpl

import (
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
)

func TestParse(t *testing.T) {
	for _, bad := range []string{`[]`, `"x"`, `{"a":1} {"b":2}`, `{"a":`, strings.Repeat(" ", MaxSize+1)} {
		if _, err := Parse([]byte(bad)); err == nil {
			t.Errorf("accepted %q", bad[:min(len(bad), 20)])
		}
	}
	d, err := Parse([]byte(`{"n": 12345678901234567890, "s": "$veilon:x"}`))
	if err != nil {
		t.Fatal(err)
	}
	if d["n"].(json.Number).String() != "12345678901234567890" {
		t.Fatal("number not kept exact")
	}
}

func TestRender(t *testing.T) {
	d, _ := Parse([]byte(`{"a":"$veilon:port","b":["$veilon:users",{"c":"$veilon:key"}],"d":"$veilonx","e":"keep"}`))
	type u struct {
		ID string `json:"id"`
	}
	out, err := Render(d, map[string]any{"port": 443, "users": []u{{"x"}}, "key": "k"})
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(out)
	want := `{"a":443,"b":[[{"id":"x"}],{"c":"k"}],"d":"$veilonx","e":"keep"}`
	if string(b) != want {
		t.Fatalf("got %s", b)
	}
	if d["a"] != "$veilon:port" {
		t.Fatal("template modified")
	}
	if _, err := Render(d, map[string]any{"port": 1}); err == nil || !strings.Contains(err.Error(), "unknown token") {
		t.Fatalf("missing value accepted: %v", err)
	}
}

func TestTokens(t *testing.T) {
	d, _ := Parse([]byte(`{"a":"$veilon:b_1","c":["$veilon:a"],"d":"$veilon:a"}`))
	n, err := Tokens(d)
	if err != nil || !reflect.DeepEqual(n, []string{"a", "b_1"}) {
		t.Fatalf("%v %v", n, err)
	}
	d, _ = Parse([]byte(`{"a":"$veilon:Bad Name"}`))
	if _, err := Tokens(d); err == nil {
		t.Fatal("malformed token accepted")
	}
}

// RFC 7396 appendix A examples.
func TestMergePatchRFC(t *testing.T) {
	cases := [][3]string{
		{`{"a":"b"}`, `{"a":"c"}`, `{"a":"c"}`},
		{`{"a":"b"}`, `{"b":"c"}`, `{"a":"b","b":"c"}`},
		{`{"a":"b"}`, `{"a":null}`, `{}`},
		{`{"a":"b","b":"c"}`, `{"a":null}`, `{"b":"c"}`},
		{`{"a":["b"]}`, `{"a":"c"}`, `{"a":"c"}`},
		{`{"a":"c"}`, `{"a":["b"]}`, `{"a":["b"]}`},
		{`{"a":{"b":"c"}}`, `{"a":{"b":"d","c":null}}`, `{"a":{"b":"d"}}`},
		{`{"a":[{"b":"c"}]}`, `{"a":[1]}`, `{"a":[1]}`},
		{`{"e":null}`, `{"a":1}`, `{"a":1,"e":null}`},
		{`{}`, `{"a":{"bb":{"ccc":null}}}`, `{"a":{"bb":{}}}`},
	}
	for _, c := range cases {
		var tg, p Doc
		_ = json.Unmarshal([]byte(c[0]), &tg)
		_ = json.Unmarshal([]byte(c[1]), &p)
		got, _ := json.Marshal(MergePatch(tg, p))
		var a, b any
		_ = json.Unmarshal(got, &a)
		_ = json.Unmarshal([]byte(c[2]), &b)
		if !reflect.DeepEqual(a, b) {
			t.Errorf("merge(%s, %s) = %s, want %s", c[0], c[1], got, c[2])
		}
	}
}

func TestFindKey(t *testing.T) {
	d, _ := Parse([]byte(`{"x":[{"y":{"show":false}},{"z":{"show":true}}]}`))
	if p := FindKey(d, "show", Truthy); p != "x[1].z.show" {
		t.Fatalf("path %q", p)
	}
}

func TestOmitAndWhen(t *testing.T) {
	d, _ := Parse([]byte(`{"l":[{"$veilon:when":"on","a":1},{"$veilon:when":"off","b":2},"$veilon:gone"],"m":"$veilon:gone","o":{"$veilon:when":"off"}}`))
	out, err := Render(d, map[string]any{"on": true, "off": false, "gone": Omit})
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(out)
	if string(b) != `{"l":[{"a":1}]}` {
		t.Fatalf("got %s", b)
	}
	n, _ := Tokens(d)
	if !reflect.DeepEqual(n, []string{"gone", "off", "on"}) {
		t.Fatalf("tokens %v", n)
	}
	if _, err := Render(d, map[string]any{"on": true, "gone": Omit}); err == nil {
		t.Fatal("unknown condition accepted")
	}
}

func TestTokenHelper(t *testing.T) {
	if Token("port") != "$veilon:port" {
		t.Fatal(Token("port"))
	}
}

func TestParseRejectsAll(t *testing.T) {
	cases := map[string]string{
		"too big":                 `{"a":"` + strings.Repeat("x", MaxSize) + `"}`,
		"bad json":                `{"a":`,
		"two objects":             `{} {}`,
		"trailing":                `{} ]`,
		"trailing ws ok but text": `{} x`,
		"array root":              `[1]`,
	}
	for name, raw := range cases {
		if _, err := Parse([]byte(raw)); !errors.Is(err, ErrTemplate) {
			t.Errorf("%s: want ErrTemplate, got %v", name, err)
		}
	}
}

func TestTokensWhenAndMalformed(t *testing.T) {
	d, err := Parse([]byte(`{"a":{"$veilon:when":"flag","b":"$veilon:x"},"c":["$veilon:y","plain",1],"d":"$veilon:Bad-Name"}`))
	if err != nil {
		t.Fatal(err)
	}
	got, err := Tokens(d)
	if !errors.Is(err, ErrTemplate) || !strings.Contains(err.Error(), "Bad-Name") {
		t.Fatalf("malformed token not reported: %v", err)
	}
	if strings.Join(got, ",") != "flag,x,y" {
		t.Fatalf("tokens %v", got)
	}
	// A bare "$veilon:when" string value is not a token.
	if got, err := Tokens([]any{When}); err != nil || len(got) != 0 {
		t.Fatalf("bare when: %v %v", got, err)
	}
}

func TestRenderErrors(t *testing.T) {
	tpl, _ := Parse([]byte(`{"a":"$veilon:v"}`))
	if _, err := Render(tpl, map[string]any{"v": func() {}}); !errors.Is(err, ErrTemplate) {
		t.Fatalf("unmarshalable value: %v", err)
	}
	if _, err := Render(tpl, nil); err == nil || !strings.Contains(err.Error(), "unknown token $veilon:v") {
		t.Fatalf("missing value: %v", err)
	}
	cond, _ := Parse([]byte(`{"$veilon:when":"on","a":1}`))
	if _, err := Render(cond, map[string]any{"on": false}); err == nil || !strings.Contains(err.Error(), "root object is conditional") {
		t.Fatalf("conditional root: %v", err)
	}
	if _, err := Render(cond, nil); err == nil {
		t.Fatal("unknown condition accepted")
	}
	// Typed values become plain JSON values; numbers stay exact.
	type pair struct {
		N int64  `json:"n"`
		S string `json:"s"`
	}
	tpl2, _ := Parse([]byte(`{"p":"$veilon:p","l":["$veilon:p"],"keep":true}`))
	out, err := Render(tpl2, map[string]any{"p": pair{N: 9007199254740993, S: "x"}})
	if err != nil {
		t.Fatal(err)
	}
	if n := Get(out, "p", "n"); n != json.Number("9007199254740993") {
		t.Fatalf("number not exact: %#v", n)
	}
	// Render deep-copies: mutating the output never changes the value.
	out["p"].(map[string]any)["s"] = "changed"
	if Get(out, "l").([]any)[0].(map[string]any)["s"] != "x" {
		t.Fatal("values shared between substitutions")
	}
}

func TestFromValueAndMarshal(t *testing.T) {
	d, err := FromValue(struct {
		A string `json:"a"`
	}{"<&>"})
	if err != nil || d["a"] != "<&>" {
		t.Fatalf("FromValue: %v %v", d, err)
	}
	if _, err := FromValue([]int{1}); !errors.Is(err, ErrTemplate) {
		t.Fatalf("non-object accepted: %v", err)
	}
	if _, err := FromValue(func() {}); err == nil {
		t.Fatal("function accepted")
	}
	b, err := Marshal(Doc{"b": 1, "a": "<&>"})
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != "{\n  \"a\": \"<&>\",\n  \"b\": 1\n}\n" {
		t.Fatalf("Marshal: %q", b)
	}
	if _, err := Marshal(func() {}); err == nil {
		t.Fatal("Marshal accepted a function")
	}
}

func TestGetAndObjects(t *testing.T) {
	d, _ := Parse([]byte(`{"a":{"b":{"c":1}},"s":"x","l":[{"t":1},2,{"t":3}]}`))
	if Get(d, "a", "b", "c") != json.Number("1") {
		t.Fatal("Get nested")
	}
	if Get(d, "s", "x") != nil || Get(d, "missing") != nil {
		t.Fatal("Get through non-object or missing key")
	}
	if objs := Objects(d, "l"); len(objs) != 2 || objs[1]["t"] != json.Number("3") {
		t.Fatalf("Objects: %v", objs)
	}
	if Objects(d, "s") != nil {
		t.Fatal("Objects of a string")
	}
}

func TestTruthy(t *testing.T) {
	cases := []struct {
		v    any
		want bool
	}{
		{true, true}, {false, false}, {"", false}, {"x", true}, {json.Number("0"), false}, {json.Number("2"), true},
		{0.0, false}, {1.5, true}, {nil, false}, {[]any{}, true}, {map[string]any{}, true},
	}
	for _, c := range cases {
		if Truthy(c.v) != c.want {
			t.Errorf("Truthy(%#v) != %v", c.v, c.want)
		}
	}
}

func TestParseAllowsTrailingWhitespace(t *testing.T) {
	if _, err := Parse([]byte("{\"a\":1}\n\t ")); err != nil {
		t.Fatal(err)
	}
}

func TestFindKeyInLists(t *testing.T) {
	d, _ := Parse([]byte(`{"x":[{"y":1},{"k":true}],"k":false}`))
	if p := FindKey(d, "k", Truthy); p != "x[1].k" {
		t.Fatalf("path %q", p)
	}
	if p := FindKey(d, "none", Truthy); p != "" {
		t.Fatalf("path %q", p)
	}
}
