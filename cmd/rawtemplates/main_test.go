// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"testing"
)

func TestRunPrintsTemplates(t *testing.T) {
	var b bytes.Buffer
	if err := run(&b); err != nil {
		t.Fatal(err)
	}
	var out map[string]map[string]any
	if err := json.Unmarshal(b.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	for _, core := range []string{"xray", "singbox"} {
		c, ok := out[core]
		if !ok {
			t.Fatalf("missing %s", core)
		}
		if s, _ := c["default"].(string); s == "" {
			t.Fatalf("%s: empty default template", core)
		}
		if c["tokens"] == nil {
			t.Fatalf("%s: no tokens", core)
		}
	}
}

type failWriter struct{}

func (failWriter) Write([]byte) (int, error) { return 0, errors.New("closed") }

func TestRunWriteError(t *testing.T) {
	if err := run(failWriter{}); err == nil {
		t.Fatal("expected a write error")
	}
}
