// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package tmpl

import (
	"encoding/json"
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
