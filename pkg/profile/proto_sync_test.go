// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package profile

import (
	"os"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// TestProtoInSync guards the proto mirror: it mirror must have exactly the same
// field names as the JSON (canonical) struct tags.
func TestProtoInSync(t *testing.T) {
	src, err := os.ReadFile("../../proto/veilon/profile/v1/profile.proto")
	if err != nil {
		t.Fatal(err)
	}
	msgRe := regexp.MustCompile(`(?s)message (\w+) \{(.*?)\n\}`)
	fieldRe := regexp.MustCompile(`(?m)^\s+(?:repeated\s+)?[\w.]+\s+(\w+)\s*=\s*\d+;`)
	protoFields := map[string][]string{}
	for _, m := range msgRe.FindAllStringSubmatch(string(src), -1) {
		for _, f := range fieldRe.FindAllStringSubmatch(m[2], -1) {
			protoFields[m[1]] = append(protoFields[m[1]], f[1])
		}
	}
	types := map[string]any{
		"Profile": Profile{}, "Subscription": Subscription{}, "Node": Node{}, "NodeTransports": NodeTransports{},
		"VLESS": VLESS{}, "VLESSWire": VLESSWire{}, "TLSClient": TLSClient{}, "RealityPK": RealityPK{},
		"Hysteria2": Hysteria2{}, "Naive": Naive{}, "Fallback": Fallback{}, "RouteRule": RouteRule{},
		"DNS": DNS{}, "APIEndpoints": APIEndpoints{},
	}
	for name, v := range types {
		var jsonNames []string
		rt := reflect.TypeOf(v)
		for i := 0; i < rt.NumField(); i++ {
			tag := strings.Split(rt.Field(i).Tag.Get("json"), ",")[0]
			jsonNames = append(jsonNames, tag)
		}
		got := append([]string(nil), protoFields[name]...)
		sort.Strings(got)
		sort.Strings(jsonNames)
		if !reflect.DeepEqual(got, jsonNames) {
			t.Errorf("message %s out of sync:\n proto %v\n json  %v", name, got, jsonNames)
		}
	}
}
