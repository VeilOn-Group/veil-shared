# veil-shared: licence notice

Copyright (C) 2026 VeilOn.

Everything in this repository written by VeilOn is licensed under the
**Mozilla Public License, version 2.0** (`LICENSE`). Source files carry the
MPL-2.0 notice (Exhibit A), checked by `tools/license/mpl_headers.py --check`;
files without comment syntax (JSON, images, icons) are covered by `LICENSE`
and this notice. The files are not marked "Incompatible With Secondary
Licenses": they may be combined with GPL-3.0 code (veilon-app, the node agent)
as a Larger Work, and with proprietary code (veil-api) as long as the MPL
files themselves stay available under the MPL.

## Not relicensed (third-party content)

| File | Origin | Licence |
|---|---|---|
| `assets/rulesets/geosite-category-ru.srs` | SagerNet/sing-geosite (rule-set branch), data from v2fly/domain-list-community, see `assets/rulesets/SOURCE.md` | domain list MIT; [ПРОВЕРИТЬ] status of the generated file (LQ-LIC-5) |

## Trademarks

The MPL grants no rights to the VeilOn name, logo or icons in `brand/`
(MPL-2.0 section 2.3): forks must use their own branding.

## Dependencies

`github.com/gowebpki/jcs` (Apache-2.0), `github.com/goccy/go-yaml` (MIT).
