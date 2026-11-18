#!/bin/sh
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
# Update the bundled geosite-category-ru rule set to a sing-geosite commit
# (branch rule-set). Prints the decompiled list for review; rewrites the
# pinned SHA-256. Requires curl and a sing-box binary (SINGBOX_BIN).
set -eu
commit=${1:?usage: update.sh <sing-geosite rule-set commit>}
case $commit in *[!0-9a-f]*) echo "commit must be a hex sha" >&2; exit 2;; esac
here=$(cd "$(dirname "$0")/../../assets/rulesets" && pwd)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
curl -fsSL -o "$tmp/r.srs" "https://raw.githubusercontent.com/SagerNet/sing-geosite/$commit/geosite-category-ru.srs"
"${SINGBOX_BIN:?set SINGBOX_BIN}" rule-set decompile "$tmp/r.srs" -o "$tmp/r.json"
cat "$tmp/r.json"
cp "$tmp/r.srs" "$here/geosite-category-ru.srs"
(cd "$here" && sha256sum geosite-category-ru.srs > geosite-category-ru.srs.sha256)
echo "updated; set the commit in $here/SOURCE.md and review the list above" >&2
