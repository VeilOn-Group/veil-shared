// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Command inventorygen renders the public "What we store" summary (RU/SR/EN)
// from data-inventory.yaml as JSON for the client privacy screen and the site.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/veilon/veil-shared/pkg/inventory"
)

// Output is the generated document.
type Output struct {
	InventoryVersion string                  `json:"inventory_version"`
	Updated          string                  `json:"updated"`
	Summary          inventory.PublicSummary `json:"summary"`
	Retention        []RetentionLine         `json:"retention"`
	Processors       []inventory.Processor   `json:"processors"`
}

// RetentionLine is a compact retention schedule row.
type RetentionLine struct {
	ID        string `json:"id"`
	Category  string `json:"category"`
	Retention string `json:"retention"`
	Purpose   string `json:"purpose"`
}

func main() {
	in := flag.String("in", "data-inventory.yaml", "inventory file")
	out := flag.String("out", "design/dist/what-we-store.json", "output file")
	flag.Parse()

	data, err := os.ReadFile(*in)
	if err != nil {
		fail(err)
	}
	inv, err := inventory.Parse(data)
	if err != nil {
		fail(err)
	}
	doc := Output{InventoryVersion: inv.Version, Updated: inv.Updated, Summary: inv.PublicSummary, Processors: inv.Processors}
	for _, e := range inv.Entries {
		if e.Retention == "" {
			continue
		}
		doc.Retention = append(doc.Retention, RetentionLine{ID: e.ID, Category: e.Category, Retention: e.Retention, Purpose: e.Purpose})
	}
	b, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		fail(err)
	}
	if err := os.MkdirAll(filepath.Dir(*out), 0o755); err != nil { //nolint:gosec // generated repo files are public
		fail(err)
	}
	if err := os.WriteFile(*out, append(b, '\n'), 0o644); err != nil { //nolint:gosec // generated repo files are public
		fail(err)
	}
	fmt.Println("inventorygen: OK")
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "inventorygen:", err)
	os.Exit(1)
}
