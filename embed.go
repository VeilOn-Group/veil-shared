// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Package veilshared exposes the canonical data files of the VeilOn project
// (data inventory, design tokens) so every binary embeds the same version.
package veilshared

import _ "embed"

// DataInventoryYAML is veil-shared/data-inventory.yaml.
//
//go:embed data-inventory.yaml
var DataInventoryYAML []byte

// DesignTokensJSON is veil-shared/design-tokens.json.
//
//go:embed design-tokens.json
var DesignTokensJSON []byte
