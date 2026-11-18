// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Command schemalint checks SQL migrations against data-inventory.yaml.
// Exit code 1 on any finding (blocking step of the CI "nolog" suite).
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/veilon/veil-shared/pkg/inventory"
	"github.com/veilon/veil-shared/pkg/schemalint"
)

func main() {
	invPath := flag.String("inventory", "data-inventory.yaml", "path to data-inventory.yaml")
	dir := flag.String("migrations", "../veil-api/server/migrations", "directory with *.sql migrations")
	flag.Parse()

	data, err := os.ReadFile(*invPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "schemalint:", err)
		os.Exit(2)
	}
	inv, err := inventory.Parse(data)
	if err != nil {
		fmt.Fprintln(os.Stderr, "schemalint:", err)
		os.Exit(2)
	}
	findings, err := schemalint.LintDir(inv, *dir)
	if err != nil {
		fmt.Fprintln(os.Stderr, "schemalint:", err)
		os.Exit(2)
	}
	for _, f := range findings {
		fmt.Println(f)
	}
	if len(findings) > 0 {
		fmt.Fprintf(os.Stderr, "schemalint: %d finding(s)\n", len(findings))
		os.Exit(1)
	}
	fmt.Println("schemalint: OK")
}
