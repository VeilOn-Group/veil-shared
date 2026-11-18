<p align="center">
  <img src="brand/dist/mark-128.png" width="96" alt="VeilOn">
</p>

<h1 align="center">veil-shared</h1>

<p align="center">
  The open core of VeilOn: signatures, configuration generators, privacy rules
  and design assets shared by the apps and the servers.
</p>

<p align="center">
  <a href="README.md"><img src="https://img.shields.io/badge/English-1f2937?style=for-the-badge" alt="English"></a>
  <a href="README.ru.md"><img src="https://img.shields.io/badge/%D0%A0%D1%83%D1%81%D1%81%D0%BA%D0%B8%D0%B9-6d28d9?style=for-the-badge" alt="Русский"></a>
</p>

<p align="center">
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MPL--2.0-blue" alt="MPL-2.0"></a>
  <img src="https://img.shields.io/badge/Go-1.24%2B-00ADD8" alt="Go 1.24+">
</p>

---

This repository holds the code that decides how a VeilOn connection is built
and what is allowed to be stored. The
[Veil Connect](https://github.com/VeilOn-Group/Veil-Connect) client, the VeilOn
servers and the VPN nodes all use this exact code, so reading it tells you
how the whole service behaves, not just one app.

## What is inside

| Package | What it does |
|---|---|
| `pkg/sign` | Ed25519 signatures over canonical JSON (RFC 8785), key sets and offline root keys |
| `pkg/profile` | the signed client profile: nodes, transports, DNS and routing, with validation and a protobuf mirror in `proto/` |
| `pkg/singbox`, `pkg/xray`, `pkg/tmpl` | client and node config generators for sing-box 1.13 and Xray 26.9, config templates, DNS over HTTPS presets |
| `pkg/redact`, `pkg/crash` | log redaction and crash report cleaning: IP addresses, domains, paths and identifiers are removed |
| `pkg/nonroot` | makes server binaries refuse to run as root |
| `pkg/release` | signed release metadata and version ordering for app updates |
| `pkg/apitypes`, `pkg/nodeproto` | request and response types of the API, and messages between the API and node agents |
| `pkg/inventory`, `pkg/schemalint` | the data inventory and the checks that keep it complete |
| `pkg/tokens`, `design/`, `brand/` | design tokens, colors and the VeilOn icons |
| `mobile/` | the gomobile bridge used by the Android app |
| `assets/rulesets/` | the pinned geosite `category-ru` rule set for split tunnelling |
| `build/*.lock` | the pinned sing-box and Xray releases with their SHA-256 hashes |

## Privacy guarantees in code

- **Data inventory.** [`data-inventory.yaml`](data-inventory.yaml) lists every
  piece of data VeilOn handles: database columns, log fields, metrics, cache
  keys, what the apps keep on the device and which outside services see
  what. CI fails if the database schema contains anything not listed here.
  The apps show a readable summary of it
  ([`design/dist/what-we-store.json`](design/dist/what-we-store.json)).
- **Zero-log configs.** The generators refuse to produce a config that logs
  traffic, keeps connection history or caches DNS answers on disk, and the
  same checks run on custom node templates. `make nolog` validates the
  golden configs with the real pinned sing-box and Xray binaries.
- **No trackers.** `cmd/trackerscan` fails the build if an analytics, tracking
  or crash reporting SDK shows up among the dependencies.
- **Signed everything.** Profiles, key sets and releases are signed. The
  root key stays offline, so a compromised server cannot hand out a fake
  profile or a malicious update.

## Using it

The module path is `github.com/veilon/veil-shared`. Projects that depend on it
expect a checkout next to them and use a `replace` directive:

```
workspace/
  veil-shared/
  Veil-Connect/
```

```go
// go.mod
require github.com/veilon/veil-shared v0.0.0
replace github.com/veilon/veil-shared => ../veil-shared
```

## Development

```bash
make test vet lint          # unit tests, go vet, golangci-lint
make singbox xray           # download the pinned cores and verify their hashes
make nolog                  # zero-log suite against those cores
make generate               # regenerate design tokens and the "what we store" summary
make license-check nodash   # MPL headers and typography checks
make ci                     # everything CI runs
```

`make help` lists every target.

## License

The code is released under the [Mozilla Public License 2.0](LICENSE). It can
be combined with GPL code (such as the client) and with proprietary code, as
long as the MPL files themselves stay open. Details and the third party
content that keeps its own license are in [NOTICE.md](NOTICE.md).

The VeilOn name, logo and icons in `brand/` are not covered by the license.
Forks should use their own branding.
