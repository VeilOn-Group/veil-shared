// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Command tokensgen generates CSS variables, a Tailwind v4 theme and Kotlin
// colors from design-tokens.json, failing if any declared pair misses WCAG AA.
package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/veilon/veil-shared/pkg/tokens"
)

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }

func run(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("tokensgen", flag.ContinueOnError)
	fs.SetOutput(stderr)
	in := fs.String("in", "design-tokens.json", "design tokens file")
	out := fs.String("out", "design/dist", "output directory")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	data, err := os.ReadFile(*in) //nolint:gosec // path from the command line
	if err != nil {
		return fail(stderr, err)
	}
	tk, err := tokens.Parse(data)
	if err != nil {
		return fail(stderr, err)
	}
	v, err := tk.CheckContrast()
	if err != nil {
		return fail(stderr, err)
	}
	if len(v) > 0 {
		for _, x := range v {
			fmt.Fprintf(stderr, "contrast %s on %s = %.2f < %.1f\n", x.FG, x.BG, x.Ratio, x.Min)
		}
		return 1
	}
	if err := os.MkdirAll(*out, 0o755); err != nil { //nolint:gosec // generated repo files are public
		return fail(stderr, err)
	}
	files := map[string]string{
		"tokens.css":    tk.CSS(),
		"tailwind.css":  tk.TailwindTheme(),
		"VeilColors.kt": tk.Kotlin(),
		"tokens.json":   string(data),
	}
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(*out, name), []byte(content), 0o644); err != nil { //nolint:gosec // generated repo files are public
			return fail(stderr, err)
		}
	}
	fmt.Fprintln(stdout, "tokensgen: OK")
	return 0
}

func fail(w io.Writer, err error) int {
	fmt.Fprintln(w, "tokensgen:", err)
	return 1
}
