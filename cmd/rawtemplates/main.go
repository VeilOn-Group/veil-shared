// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Command rawtemplates prints the built-in node templates of the raw config
// editor (ADR-0067) and their tokens as JSON: used for the documentation and
// the panel's design-review mock data.
package main

import (
	"encoding/json"
	"os"

	"github.com/veilon/veil-shared/pkg/singbox"
	"github.com/veilon/veil-shared/pkg/tmpl"
	"github.com/veilon/veil-shared/pkg/xray"
)

func main() {
	x, _ := tmpl.Marshal(xray.DefaultServerTemplate())
	s, _ := tmpl.Marshal(singbox.DefaultServerTemplate())
	out := map[string]any{
		"xray":    map[string]any{"default": string(x), "tokens": xray.ServerTokens},
		"singbox": map[string]any{"default": string(s), "tokens": singbox.ServerTokens},
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	_ = enc.Encode(out)
}
