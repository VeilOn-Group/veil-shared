// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package nonroot

import (
	"errors"
	"testing"
)

func TestCheck(t *testing.T) {
	defer func(g string, e, u func() int) { goos, geteuid, getuid = g, e, u }(goos, geteuid, getuid)
	id := func(n int) func() int { return func() int { return n } }
	cases := []struct {
		name     string
		goos     string
		euid, ui int
		want     error
	}{
		{"user", "linux", 1000, 1000, nil},
		{"root euid", "linux", 0, 1000, ErrRoot},
		{"root uid", "darwin", 1000, 0, ErrRoot},
		{"windows ignores uid", "windows", 0, 0, nil},
	}
	for _, c := range cases {
		goos, geteuid, getuid = c.goos, id(c.euid), id(c.ui)
		if err := Check(); !errors.Is(err, c.want) {
			t.Errorf("%s: got %v, want %v", c.name, err, c.want)
		}
	}
}
