// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Package nonroot makes server-side binaries refuse to run as root (ADR-0057):
// even if a container runtime or an operator starts them with UID 0, they
// exit instead of serving. Client daemons (veilond) are exempt: they need
// network privileges and are hardened differently (ADR-0007).
package nonroot

import (
	"errors"
	"os"
	"runtime"
)

// ErrRoot is returned when the process runs with effective UID 0.
var ErrRoot = errors.New("refusing to run as root: start with a non-root user (e.g. --user 65532:65532)")

// Check returns ErrRoot when running as root on Unix.
func Check() error {
	if runtime.GOOS == "windows" {
		return nil
	}
	if os.Geteuid() == 0 || os.Getuid() == 0 {
		return ErrRoot
	}
	return nil
}
