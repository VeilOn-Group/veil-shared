// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Command trackerscan fails if any client/web dependency manifest references
// a known tracker/analytics/crash-reporting SDK (zero-log 7.4).
package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// denylist entries are matched case-insensitively as substrings of
// dependency lines in manifests and lockfiles.
var denylist = []string{
	"firebase-analytics", "firebase-crashlytics", "com.google.firebase", "@firebase/analytics",
	"crashlytics", "appsflyer", "adjust-sdk", "com.adjust.sdk", "amplitude", "mixpanel",
	"segment.io", "@segment/", "analytics-go", "sentry.io", "@sentry/", "getsentry/sentry-go",
	"bugsnag", "flurry", "yandex.metrica", "appmetrica", "posthog", "hotjar", "datadog",
	"newrelic", "google-analytics", "googletagmanager", "react-ga", "facebook-sdk", "onesignal",
	"branch.io", "io.branch",
}

var manifests = map[string]bool{
	"package.json": true, "package-lock.json": true, "pnpm-lock.yaml": true, "yarn.lock": true,
	"go.mod": true, "go.sum": true, "build.gradle": true, "build.gradle.kts": true,
	"libs.versions.toml": true, "settings.gradle.kts": true,
}

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }

func run(args []string, stdout, stderr io.Writer) int {
	fl := flag.NewFlagSet("trackerscan", flag.ContinueOnError)
	fl.SetOutput(stderr)
	root := fl.String("root", ".", "repository root")
	if err := fl.Parse(args); err != nil {
		return 2
	}
	hits, err := scan(*root)
	if err != nil {
		fmt.Fprintln(stderr, "trackerscan:", err)
		return 2
	}
	for _, h := range hits {
		fmt.Fprintln(stdout, h)
	}
	if len(hits) > 0 {
		return 1
	}
	fmt.Fprintln(stdout, "trackerscan: OK")
	return 0
}

// scan walks root and returns one line per denylist match.
func scan(root string) ([]string, error) {
	var hits []string
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case "node_modules", ".git", ".cache", "bin":
				return filepath.SkipDir
			}
			return nil
		}
		if !manifests[d.Name()] {
			return nil
		}
		f, err := os.Open(path) //nolint:gosec // repository manifests
		if err != nil {
			return err
		}
		defer f.Close()
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 0, 1<<20), 1<<24)
		line := 0
		for sc.Scan() {
			line++
			low := strings.ToLower(sc.Text())
			for _, bad := range denylist {
				if strings.Contains(low, bad) {
					hits = append(hits, fmt.Sprintf("%s:%d: %q matches tracker denylist entry %q", path, line, strings.TrimSpace(sc.Text()), bad))
				}
			}
		}
		return sc.Err()
	})
	return hits, err
}
