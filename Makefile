# veil-shared (MPL-2.0): developer entry points; CI calls the same targets.
SHELL := /bin/bash
.ONESHELL:
.DEFAULT_GOAL := help

include build/singbox.lock
include build/xray.lock

GO          ?= go
export GOWORK := off
API_DIR     ?= ../veil-api
SINGBOX_DIR := $(CURDIR)/.cache/sing-box
SINGBOX_BIN ?= $(SINGBOX_DIR)/sing-box-$(SINGBOX_VERSION)-linux-amd64/sing-box
XRAY_DIR    := $(CURDIR)/.cache/xray-$(XRAY_VERSION)
XRAY_BIN    ?= $(XRAY_DIR)/linux-amd64/xray

.PHONY: help
help: ## Show targets
	@grep -hE '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | awk 'BEGIN{FS=":.*?## "}{printf "  %-18s %s\n",$$1,$$2}'

.PHONY: test
test: ## Unit tests
	$(GO) test -race -count=1 ./...

.PHONY: vet
vet: ## go vet
	$(GO) vet ./...

.PHONY: lint
lint: ## golangci-lint
	golangci-lint run ./...

.PHONY: nolog
nolog: singbox xray ## Zero-log suite: golden configs checked by the pinned cores, redaction, inventory
	SINGBOX_BIN=$(SINGBOX_BIN) VEILON_XRAY=$(XRAY_BIN) $(GO) test -count=1 -run 'NoLog|Golden|Redact|Inventory|Schema|DNS' ./...
	$(GO) run ./cmd/trackerscan -root .

.PHONY: schemalint
schemalint: ## Inventory vs. the API migrations (needs the veil-api checkout)
	$(GO) run ./cmd/schemalint -inventory data-inventory.yaml -migrations $(API_DIR)/server/migrations

.PHONY: singbox
singbox: $(SINGBOX_BIN) ## Download the pinned sing-box and verify SHA-256

$(SINGBOX_BIN):
	mkdir -p $(SINGBOX_DIR)
	curl -fsSL -o $(SINGBOX_DIR)/sb.tgz $(SINGBOX_LINUX_AMD64_URL)
	echo "$(SINGBOX_LINUX_AMD64_SHA256)  $(SINGBOX_DIR)/sb.tgz" | sha256sum -c -
	tar -xzf $(SINGBOX_DIR)/sb.tgz -C $(SINGBOX_DIR)

.PHONY: xray
xray: $(XRAY_BIN) ## Download the pinned Xray-core and verify SHA-256

$(XRAY_BIN):
	mkdir -p $(XRAY_DIR)/linux-amd64
	curl -fsSL -o $(XRAY_DIR)/x.zip $(XRAY_BASE_URL)/$(XRAY_LINUX_AMD64_ZIP)
	echo "$(XRAY_LINUX_AMD64_ZIP_SHA256)  $(XRAY_DIR)/x.zip" | sha256sum -c -
	unzip -oq $(XRAY_DIR)/x.zip xray -d $(XRAY_DIR)/linux-amd64
	echo "$(XRAY_LINUX_AMD64_BIN_SHA256)  $(XRAY_BIN)" | sha256sum -c -

.PHONY: generate
generate: ## Regenerate design tokens and the "what we store" summary
	$(GO) run ./cmd/tokensgen -in design-tokens.json -out design/dist
	$(GO) run ./cmd/inventorygen -in data-inventory.yaml -out design/dist/what-we-store.json

.PHONY: check-generated
check-generated: generate ## Fail if generated files are stale
	git diff --exit-code -- design/dist

.PHONY: brand
brand: ## Regenerate brand/dist from the master mark (apps copy the icons: make brand in veilon-app)
	python3 tools/brand/gen.py
	python3 tools/license/mpl_headers.py --fix

.PHONY: license-check
license-check: ## Every source file carries the MPL-2.0 notice
	python3 tools/license/mpl_headers.py --check

.PHONY: nodash
nodash: ## Typography: no em dashes
	python3 tools/text/nodash.py --check

.PHONY: ci
ci: vet lint test nolog license-check nodash check-generated ## Everything CI runs here
