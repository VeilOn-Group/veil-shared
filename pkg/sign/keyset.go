// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package sign

import (
	"errors"
	"time"
)

// Keyset lists the currently trusted profile/release keys. It is itself signed
// by the offline root key (PurposeKeyset) so keys can rotate without shipping
// a new client: the client pins only the root public key(s).
type Keyset struct {
	Version int64       `json:"version"` // monotonic; clients reject downgrades
	Keys    []PublicKey `json:"keys"`
}

// ErrKeysetDowngrade is returned when a keyset is older than the cached one.
var ErrKeysetDowngrade = errors.New("sign: keyset version downgrade")

// VerifyKeyset verifies a keyset envelope with the root verifier and rejects
// version downgrades relative to minVersion.
func VerifyKeyset(root *Verifier, env *Envelope, minVersion int64) (*Keyset, error) {
	var ks Keyset
	if err := root.VerifyInto(env, PurposeKeyset, &ks); err != nil {
		return nil, err
	}
	if ks.Version < minVersion {
		return nil, ErrKeysetDowngrade
	}
	for _, k := range ks.Keys {
		if k.Purpose == PurposeKeyset {
			return nil, errors.New("sign: keyset may not introduce root keys")
		}
	}
	return &ks, nil
}

// VerifierFromKeyset builds a verifier for documents signed by keyset keys.
func VerifierFromKeyset(ks *Keyset, now func() time.Time) *Verifier {
	return NewVerifier(ks.Keys, now)
}
