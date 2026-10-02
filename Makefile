# HappyMining OS - top-level commands. `make help` lists them.
#
# Requirements: Python 3.12+ with uv, Go 1.24+, PostgreSQL (Docker or local
# binaries; see scripts/dev-postgres.sh). Image and VM targets need more
# tools and say so when those are missing.

SHELL := /bin/bash
.SHELLFLAGS := -euo pipefail -c
.DEFAULT_GOAL := help

ROOT := $(abspath $(dir $(lastword $(MAKEFILE_LIST))))
PY := $(ROOT)/api/.venv/bin/python
PORT ?= 8000
SIGNING_HOME ?= $(ROOT)/.signing

# PostgreSQL refuses to run as root; when we are root the throwaway cluster
# lives in the postgres user's own directory.
ifeq ($(shell id -u),0)
ifneq ($(wildcard /var/lib/postgresql),)
export HM_DEV_PG_DIR ?= /var/lib/postgresql/hm-dev
endif
endif

DEMO_ENV = HM_MODE=demo HM_PROVIDER=fake \
	HM_SECRET_KEY=demo-secret-key-demo-secret-key-demo-secret-key \
	HM_FIELD_ENCRYPTION_KEY=ZGVtby1maWVsZC1lbmNyeXB0aW9uLWtleS0wMDAwMDA= \
	HM_DEMO_LOGIN_ENABLED=true HM_COOKIE_SECURE=false HM_PAYOUTS_ENABLED=true HM_PAYOUT_PROVIDER=mock \
	HM_PUBLIC_BASE_URL=http://127.0.0.1:$(PORT) HM_ALLOWED_HOSTS=127.0.0.1,localhost PYTHONPATH=$(ROOT)/api

.PHONY: help setup dev demo test test-api test-os test-agent test-appliance lint fmt build-agent build-installer \
        smoke-test checksums dev-signing-key db-start db-stop compose-config lock-export clean

help: ## Show this help
	@grep -hE '^[a-zA-Z_-]+:.*## ' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*## "} {printf "  %-18s %s\n", $$1, $$2}'

setup: ## Install the pinned Python dependencies into api/.venv
	cd api && uv sync --frozen

$(PY):
	$(MAKE) setup

db-start: ## Start (or reuse) the throwaway development PostgreSQL
	@scripts/dev-postgres.sh start

db-stop: ## Stop the development PostgreSQL and delete its data
	@scripts/dev-postgres.sh stop

dev: $(PY) ## Run the API with demo data on http://127.0.0.1:8000 (reloads on change)
	@url="$$(scripts/dev-postgres.sh start | tail -n 1)"; \
	export HM_DATABASE_URL="$$url" $(DEMO_ENV); \
	$(PY) -m happymining.cli migrate; \
	$(PY) -m happymining.cli seed-demo >/dev/null; \
	echo "DEMO mode, synthetic data: http://127.0.0.1:$(PORT)/login"; \
	exec $(PY) -m uvicorn happymining.main:app_factory --factory --reload --reload-dir api --reload-dir dashboard \
	  --host 127.0.0.1 --port $(PORT)

demo: $(PY) dist/bin/hm-simulator ## Run the seven-step acceptance demo end to end (synthetic data)
	scripts/run-demo.sh

dist/bin/hm-simulator: $(shell find agent -name '*.go' 2>/dev/null) agent/go.mod
	agent/scripts/build.sh

test: test-agent test-api test-os test-appliance ## Run every test suite

test-agent: ## Go agent tests (race detector on)
	cd agent && go vet ./... && go test ./... -race -count=1

test-api: $(PY) dist/bin/hm-simulator ## API, ledger, security and end-to-end tests against real PostgreSQL
	$(PY) -m pytest tests/api

test-os: $(PY) ## Installer and image tooling tests
	$(PY) -m pytest tests/os

test-appliance: $(PY) ## Plugin catalog rules, the vectorizer, browser sealing and panel templates (no database)
	$(PY) -m pytest tests/appliance

lint: $(PY) ## Static checks: ruff, gofmt, go vet, shellcheck, compose file
	cd api && $(PY) -m ruff check happymining ../tests/api ../tests/appliance ../tests/os/test_dev_postgres.py \
	  ../tests/os/test_proxy_body_limits.py ../scripts ../migrations ../deploy ../integrations ../appliance
	cd api && $(PY) -m ruff format --check happymining ../migrations ../appliance ../tests/appliance
	@# The hash-pinned requirements used by deploy/hostinger must match the lockfile.
	cd api && uv export --frozen --no-dev --no-emit-project --format requirements-txt -q \
	  | grep -v '^ *#' | diff -q - <(grep -v '^ *#' requirements.lock.txt) >/dev/null \
	  || { echo "api/requirements.lock.txt is stale: run 'make lock-export'"; exit 1; }
	cd agent && test -z "$$(gofmt -l .)" && go vet ./...
	@if command -v shellcheck >/dev/null 2>&1; then \
	  shellcheck -x scripts/*.sh agent/scripts/*.sh $$(find os -name '*.sh'); \
	else echo "shellcheck not installed: shell scripts were NOT linted"; fi
	@$(MAKE) --no-print-directory compose-config

compose-config: ## Validate the Docker Compose files against the example configuration (no daemon needed)
	@if command -v docker >/dev/null 2>&1 && docker compose version >/dev/null 2>&1; then \
	  cd deploy && export HM_ENV_FILE=.env.example HM_BASIC_AUTH_USER=validate HM_BASIC_AUTH_HASH=validate && \
	  docker compose --env-file .env.example -f docker-compose.yml config --quiet && \
	  docker compose --env-file .env.example -f docker-compose.yml -f docker-compose.demo.yml config --quiet && \
	  HM_GIT_REF=0000000000000000000000000000000000000000 \
	    docker compose --env-file hostinger/.env.example -f hostinger/docker-compose.yml config --quiet && \
	  echo "compose files are valid"; \
	else echo "docker compose not installed: compose files were NOT validated"; fi

lock-export: ## Regenerate api/requirements.lock.txt (hash-pinned) from api/uv.lock
	cd api && uv export --frozen --no-dev --no-emit-project --format requirements-txt -q -o requirements.lock.txt

fmt: $(PY) ## Format Python and Go sources
	cd api && $(PY) -m ruff format happymining ../migrations ../tests/api ../scripts
	cd agent && gofmt -w .

build-agent: ## Build the agent binaries and dist/happymining-agent_<version>_amd64.deb
	agent/scripts/build-deb.sh

build-installer: ## Build the installer bundles and, where xorriso and a verified base ISO exist, the ISO
	@# Exit 77 means the ISO was not built because a prerequisite is missing.
	@# HM_ALLOW_PARTIAL=1 accepts the bundles alone and says which artifacts were not produced.
	os/image/build-installer.sh $(if $(HM_ALLOW_PARTIAL),--allow-partial,) \
	  $(if $(HM_BASE_ISO),--base-iso $(HM_BASE_ISO),) \
	  $(if $(wildcard $(SIGNING_HOME)),--signing-key-home $(SIGNING_HOME),--allow-unsigned-dev)

smoke-test: ## Boot the built ISO in QEMU and check the installed system (exit 77 if QEMU/ISO are missing)
	os/smoke/qemu-smoke.sh

dev-signing-key: ## Create a local DEVELOPMENT signing key in .signing/ (never committed)
	os/release/gen-dev-signing-key.sh --signing-key-home $(SIGNING_HOME)

checksums: ## Write and sign dist/SHA256SUMS with the key in .signing/
	os/release/make-checksums.sh --signing-key-home $(SIGNING_HOME)

clean: ## Remove build output
	rm -rf dist
	find . -name __pycache__ -type d -prune -exec rm -rf {} +
