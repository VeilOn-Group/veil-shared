# geosite-category-ru.srs

Source: SagerNet/sing-geosite, branch `rule-set`, commit
`bb3e47eae5721c50bac20300acf2f382b5843b09`, file `geosite-category-ru.srs`
(sing-box binary rule set, built from v2fly/domain-list-community, list
`category-ru`). Downloaded 2026-10-22.

SHA-256: see `geosite-category-ru.srs.sha256`. Clients ship this file and
refuse to start the split-tunnelling rule set if the hash differs; the
domain suffixes in `singbox.RUZones` keep working without it (ADR-0068).

Contents at this commit (decompiled with sing-box 1.13.21 `rule-set
decompile`): 224 domains, 920 domain suffixes, including the zones
.ru .su .рф .рус .москва .онлайн .сайт .орг .дети .moscow .tatar .yandex
and Russian services on other zones (for example yandex.com, vk.com,
2gis.com).

Licences: the domain list is MIT (v2fly/domain-list-community); the
conversion tool sing-geosite is GPL-3.0. [ПРОВЕРИТЬ] that distributing the
generated data file carries no GPL obligation (see veil-api docs/LICENSES.md, LQ-LIC-5).

Update procedure: `tools/rulesets/update.sh <commit>` downloads the file at
a commit, decompiles it for review, and rewrites the hash; the diff of the
decompiled list is reviewed like code.
