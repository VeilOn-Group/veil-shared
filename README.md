# veil-shared

Shared cryptographic primitives, configuration types, and protocol envelopes
for Veil Connect and Veil API.

Licence: **MPL-2.0** (see `LICENSE` and `NOTICE.md`).

| Package | What |
|---|---|
| `pkg/sign` | Ed25519 signatures over JCS (RFC 8785) envelopes, keysets, offline root keys |
| `pkg/profile` | the signed client profile (nodes, transports, DNS, routing), validation, proto mirror in `proto/` |
| `pkg/apitypes` | request and response types of the user API, the staff API and billing |
| `pkg/nodeproto` | desired state and reports between the API and node agents |
| `pkg/release` | signed release metadata, platforms, version ordering |
| `pkg/singbox`, `pkg/xray`, `pkg/tmpl` | client and node configuration generators (sing-box 1.13, Xray 26.9), templates with `$veilon:` tokens, DoH presets |
| `pkg/redact`, `pkg/nonroot` | mandatory log redaction, refusal to run as root |
| `pkg/inventory`, `pkg/schemalint`, `data-inventory.yaml` | the data inventory (zero-log source of truth) and its checks |
| `pkg/tokens`, `design/`, `brand/` | design tokens and brand assets used by the app, the admin panel and the support web |
| `mobile/` | gomobile bridge for the Android app |
| `assets/rulesets/` | the pinned geosite category-ru rule set |
| `build/*.lock` | pinned sing-box and Xray releases (one place for every repository) |

## Repositories

veil-shared is checked out next to the repositories that use it; their
`go.mod` files replace the module with `../veil-shared` (or `../../veil-shared`):

```
workspace/
  veil-shared/        this repository (MPL-2.0)
  veilon-app/         Veil Connect: veilond, desktop, Android (GPL-3.0)
  veil-api/           API, panel backend, node agent, deploy, docs (proprietary)
  veil-admin-panel/   admin panel SPA (proprietary)
  veil-support-web/   support cabinet SPA (proprietary)
```

## Development

```bash
make test lint nolog        # nolog needs SINGBOX_BIN / XRAY_BIN (make singbox xray)
make generate               # design tokens and the "what we store" summary
make license-check nodash   # MPL notices, typography
```
`make schemalint` checks the inventory against `../veil-api/server/migrations`.
