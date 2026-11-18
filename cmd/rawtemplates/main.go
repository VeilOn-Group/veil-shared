// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Command rawtemplates prints the built-in node templates of the raw config
// editor and their tokens as JSON: used for the documentation and
// the panel's design-review mock data.
package main

import (
	"encoding/json"
	"io"
	"os"

	"github.com/veilon/veil-shared/pkg/singbox"
	"github.com/veilon/veil-shared/pkg/tmpl"
	"github.com/veilon/veil-shared/pkg/xray"
)

func main() {
	if err := run(os.Stdout); err != nil {
		os.Exit(1)
	}
}

func run(w io.Writer) error {
	x, err := tmpl.Marshal(xray.DefaultServerTemplate())
	if err != nil {
		return err
	}
	s, err := tmpl.Marshal(singbox.DefaultServerTemplate())
	if err != nil {
		return err
	}
	out := map[string]any{
		"xray":    map[string]any{"default": string(x), "tokens": xray.ServerTokens},
		"singbox": map[string]any{"default": string(s), "tokens": singbox.ServerTokens},
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}
