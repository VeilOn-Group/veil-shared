// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Command tokensgen generates CSS variables, a Tailwind v4 theme and Kotlin
// colors from design-tokens.json, failing if any declared pair misses WCAG AA.
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/veilon/veil-shared/pkg/tokens"
)

func main() {
	in := flag.String("in", "design-tokens.json", "design tokens file")
	out := flag.String("out", "design/dist", "output directory")
	flag.Parse()

	data, err := os.ReadFile(*in)
	if err != nil {
		fail(err)
	}
	tk, err := tokens.Parse(data)
	if err != nil {
		fail(err)
	}
	v, err := tk.CheckContrast()
	if err != nil {
		fail(err)
	}
	if len(v) > 0 {
		for _, x := range v {
			fmt.Fprintf(os.Stderr, "contrast %s on %s = %.2f < %.1f\n", x.FG, x.BG, x.Ratio, x.Min)
		}
		os.Exit(1)
	}
	if err := os.MkdirAll(*out, 0o755); err != nil { //nolint:gosec // generated repo files are public
		fail(err)
	}
	files := map[string]string{
		"tokens.css":    tk.CSS(),
		"tailwind.css":  tk.TailwindTheme(),
		"VeilColors.kt": tk.Kotlin(),
		"tokens.json":   string(data),
	}
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(*out, name), []byte(content), 0o644); err != nil { //nolint:gosec // generated repo files are public
			fail(err)
		}
	}
	fmt.Println("tokensgen: OK")
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "tokensgen:", err)
	os.Exit(1)
}
