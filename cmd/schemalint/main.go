// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Command schemalint checks SQL migrations against data-inventory.yaml.
// Exit code 1 on any finding (blocking step of the CI "nolog" suite).
package main

import (
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/veilon/veil-shared/pkg/inventory"
	"github.com/veilon/veil-shared/pkg/schemalint"
)

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }

func run(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("schemalint", flag.ContinueOnError)
	fs.SetOutput(stderr)
	invPath := fs.String("inventory", "data-inventory.yaml", "path to data-inventory.yaml")
	dir := fs.String("migrations", "../veil-api/server/migrations", "directory with *.sql migrations")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	data, err := os.ReadFile(*invPath) //nolint:gosec // path from the command line
	if err != nil {
		fmt.Fprintln(stderr, "schemalint:", err)
		return 2
	}
	inv, err := inventory.Parse(data)
	if err != nil {
		fmt.Fprintln(stderr, "schemalint:", err)
		return 2
	}
	findings, err := schemalint.LintDir(inv, *dir)
	if err != nil {
		fmt.Fprintln(stderr, "schemalint:", err)
		return 2
	}
	for _, f := range findings {
		fmt.Fprintln(stdout, f)
	}
	if len(findings) > 0 {
		fmt.Fprintf(stderr, "schemalint: %d finding(s)\n", len(findings))
		return 1
	}
	fmt.Fprintln(stdout, "schemalint: OK")
	return 0
}
