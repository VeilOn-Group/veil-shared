// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package mobile

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"runtime/debug"
	"time"

	"github.com/veilon/veil-shared/pkg/apitypes"
	"github.com/veilon/veil-shared/pkg/crash"
)

// Crash reports on Android (ADR-0077). Kotlin catches uncaught JVM
// exceptions; Go code inside the app (this bridge, libbox) writes its fatal
// traceback to the file given to InstallCrashOutput, which is read back on
// the next start. Reports are stored and sent only if the user opted in.

// InstallCrashOutput returns the traceback left in path by a previous run
// ("" if none), then truncates the file and makes the Go runtime write
// fatal errors of this process to it.
func InstallCrashOutput(path string) (string, error) {
	prev := ""
	if f, err := os.Open(path); err == nil { //nolint:gosec // app-private path from Kotlin
		b, _ := io.ReadAll(io.LimitReader(f, 4*crash.MaxText))
		_ = f.Close()
		prev = string(b)
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600) //nolint:gosec // app-private path
	if err != nil {
		return prev, err
	}
	// The runtime duplicates the descriptor: f can be closed here.
	err = debug.SetCrashOutput(f, debug.CrashOptions{})
	_ = f.Close()
	return prev, err
}

// NewCrashReport builds a sanitized report as JSON (apitypes.CrashReport)
// for component "android" (kind "exception") or a Go traceback found by
// InstallCrashOutput (kind "panic"). now is Unix seconds.
func NewCrashReport(kind, appVersion, arch, text string, now int64) (string, error) {
	id := make([]byte, 16)
	if _, err := rand.Read(id); err != nil {
		return "", err
	}
	t := time.Unix(now, 0)
	r := apitypes.CrashReport{
		ID: hex.EncodeToString(id), Component: crash.ComponentAndroid, Kind: kind,
		AppVersion: appVersion, OS: "android", Arch: arch, Day: crash.Today(t),
		Text: crash.Sanitize(text),
	}
	if err := crash.Validate(r, t); err != nil {
		return "", fmt.Errorf("%w: %w", ErrBadInput, err)
	}
	b, err := json.Marshal(r)
	return string(b), err
}

// CrashTitle is the one-line summary shown in the app's report list.
func CrashTitle(text string) string { return crash.Title(text) }
