// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package schemalint

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/veilon/veil-shared/pkg/inventory"
)

// Finding is one problem.
type Finding struct {
	File    string
	Message string
}

func (f Finding) String() string { return f.File + ": " + f.Message }

// LintDir lints every *.sql file in dir (sorted) against inv.
func LintDir(inv *inventory.Inventory, dir string) ([]Finding, error) {
	files, err := filepath.Glob(filepath.Join(dir, "*.sql"))
	if err != nil {
		return nil, err
	}
	sort.Strings(files)
	srcs := make(map[string]string, len(files))
	for _, f := range files {
		b, err := os.ReadFile(f) //nolint:gosec // migration files from the repository
		if err != nil {
			return nil, err
		}
		srcs[filepath.Base(f)] = string(b)
	}
	return Lint(inv, srcs)
}

// Lint lints migration sources (file name -> SQL).
func Lint(inv *inventory.Inventory, sources map[string]string) ([]Finding, error) {
	names := make([]string, 0, len(sources))
	for n := range sources {
		names = append(names, n)
	}
	sort.Strings(names)

	declared := inv.Tables()
	seenTables := map[string]bool{}
	var findings []Finding
	add := func(file, format string, a ...any) {
		findings = append(findings, Finding{File: file, Message: fmt.Sprintf(format, a...)})
	}
	checkColumn := func(c Column) {
		fq := c.Table + "." + c.Name
		if inv.ColumnForbidden(fq) {
			add(c.File, "column %s is forbidden by zero-log policy", fq)
		}
		schema := c.Table[:strings.IndexByte(c.Table, '.')]
		if IsTimestampType(c.Type) && !inv.TimestampAllowed(schema) {
			add(c.File, "column %s has exact-time type %q in user-data schema %q; use DATE (zero-log: no activity timestamps)", fq, c.Type, schema)
		}
		cols, ok := declared[c.Table]
		if !ok {
			add(c.File, "table %s is not declared in data-inventory.yaml", c.Table)
			return
		}
		if !cols[c.Name] {
			add(c.File, "column %s is not declared in data-inventory.yaml", fq)
		}
	}
	for _, n := range names {
		tables, added, err := ParseMigration(n, sources[n])
		if err != nil {
			return nil, err
		}
		for _, t := range tables {
			seenTables[t.Name] = true
			for _, c := range t.Columns {
				checkColumn(c)
			}
		}
		for _, c := range added {
			checkColumn(c)
		}
	}
	for t := range declared {
		if !seenTables[t] {
			findings = append(findings, Finding{File: "data-inventory.yaml", Message: fmt.Sprintf("table %s is declared but not created by any migration", t)})
		}
	}
	sort.Slice(findings, func(i, j int) bool { return findings[i].String() < findings[j].String() })
	return findings, nil
}
