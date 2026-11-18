// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Package release defines signed client release metadata (self-update,
// ADR-0056). Metadata is signed OFFLINE with a release key (sign.PurposeRelease)
// listed in the root-signed keyset; the server only stores and serves it, so
// a compromised server cannot push a malicious update.
package release

import (
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/veilon/veil-shared/pkg/profile"
	"github.com/veilon/veil-shared/pkg/sign"
)

// Platforms with self-update. Linux builds name their package format
// (ADR-0069): the privileged helper installs only the format its own
// package was installed with.
var Platforms = []string{
	"windows-amd64", "windows-arm64", "darwin-universal", "linux-amd64", "linux-arm64", "android",
	"linux-amd64-deb", "linux-amd64-rpm", "linux-arm64-deb", "linux-arm64-rpm",
}

// Formats are the installer formats a release artifact may have.
var Formats = []string{"msi", "pkg", "deb", "rpm", "apk", "tar"}

// FormatOf returns the artifact format implied by a platform ("" when the
// platform has no silent install).
func FormatOf(platform string) string {
	switch {
	case strings.HasSuffix(platform, "-deb"):
		return "deb"
	case strings.HasSuffix(platform, "-rpm"):
		return "rpm"
	case strings.HasPrefix(platform, "windows-"):
		return "msi"
	case platform == "darwin-universal":
		return "pkg"
	case platform == "android":
		return "apk"
	}
	return "tar"
}

// Metadata describes one downloadable build.
type Metadata struct {
	Platform  string `json:"platform"`
	Channel   string `json:"channel"` // stable | beta
	Version   string `json:"version"` // semver x.y.z
	URL       string `json:"url"`     // https only
	SHA256    string `json:"sha256"`  // hex of the artifact
	Size      int64  `json:"size"`
	Notes     string `json:"notes,omitempty"`
	IssuedAt  int64  `json:"issued_at"`
	Mandatory bool   `json:"mandatory,omitempty"`
}

var reHex64 = regexp.MustCompile(`^[0-9a-f]{64}$`)

// ErrInvalid reports malformed metadata.
var ErrInvalid = errors.New("release: invalid metadata")

// Validate checks the fields.
func (m *Metadata) Validate() error {
	var errs []string
	if !slices.Contains(Platforms, m.Platform) {
		errs = append(errs, "platform")
	}
	if m.Channel != "stable" && m.Channel != "beta" {
		errs = append(errs, "channel")
	}
	if _, err := profile.ParseSemver(m.Version); err != nil {
		errs = append(errs, "version")
	}
	if u, err := url.Parse(m.URL); err != nil || u.Scheme != "https" || u.Host == "" {
		errs = append(errs, "url (https)")
	}
	if !reHex64.MatchString(m.SHA256) {
		errs = append(errs, "sha256")
	}
	if m.Size <= 0 || m.Size > 2<<30 {
		errs = append(errs, "size")
	}
	if len(m.Notes) > 4000 {
		errs = append(errs, "notes")
	}
	if m.IssuedAt <= 0 {
		errs = append(errs, "issued_at")
	}
	if len(errs) > 0 {
		return fmt.Errorf("%w: %s", ErrInvalid, strings.Join(errs, ", "))
	}
	return nil
}

// Verify checks a release envelope against a verified keyset and returns the
// metadata.
func Verify(ks *sign.Keyset, env *sign.Envelope, now func() time.Time) (*Metadata, error) {
	var m Metadata
	if err := sign.VerifierFromKeyset(ks, now).VerifyInto(env, sign.PurposeRelease, &m); err != nil {
		return nil, err
	}
	if err := m.Validate(); err != nil {
		return nil, err
	}
	return &m, nil
}

// Newer reports whether candidate is a newer version than current.
func Newer(current, candidate string) bool {
	a, err1 := profile.ParseSemver(current)
	b, err2 := profile.ParseSemver(candidate)
	return err1 == nil && err2 == nil && b.Compare(a) > 0
}
