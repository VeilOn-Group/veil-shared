// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package profile

import (
	"fmt"
	"strconv"
	"strings"
)

// Semver is a minimal MAJOR.MINOR.PATCH version (pre-release/build ignored for ordering).
type Semver struct{ Major, Minor, Patch int }

// ParseSemver parses "1.2.3", optionally with "-pre" or "+build" suffixes.
func ParseSemver(s string) (Semver, error) {
	core := s
	if i := strings.IndexAny(core, "-+"); i >= 0 {
		core = core[:i]
	}
	parts := strings.Split(core, ".")
	if len(parts) != 3 {
		return Semver{}, fmt.Errorf("semver %q: want MAJOR.MINOR.PATCH", s)
	}
	var out [3]int
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 || (len(p) > 1 && p[0] == '0') {
			return Semver{}, fmt.Errorf("semver %q: bad component %q", s, p)
		}
		out[i] = n
	}
	return Semver{out[0], out[1], out[2]}, nil
}

// SemverMajor returns the major component.
func SemverMajor(s string) (int, error) {
	v, err := ParseSemver(s)
	return v.Major, err
}

// Compare returns -1, 0, 1.
func (a Semver) Compare(b Semver) int {
	for _, d := range [3]int{a.Major - b.Major, a.Minor - b.Minor, a.Patch - b.Patch} {
		if d < 0 {
			return -1
		}
		if d > 0 {
			return 1
		}
	}
	return 0
}

func (a Semver) String() string { return fmt.Sprintf("%d.%d.%d", a.Major, a.Minor, a.Patch) }
