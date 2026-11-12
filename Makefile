# UbuntuGuard - native builds, no Docker.
#
# `make` itself comes from build-essential and is not installed on this machine
# yet; every target below is a one-line command you can also run by hand, and
# README.md lists them.
#
# Targets the brief asks for: db, api, dash, agent, test. Those still unbuilt
# fail with a message naming the phase they belong to, rather than "no rule to
# make target".

SHELL := /bin/bash
.DEFAULT_GOAL := help

UV        ?= $(HOME)/.local/bin/uv
PY_TOOLS  := .venv-tools/bin/python
PY_SERVER := server/.venv/bin/python
SERVER    := server

# Resolved rather than assumed to be on PATH. Node and Go are installed under
# ~/.local by tools/install_toolchain.py, and ~/.local/bin is only added to PATH
# by ~/.profile - which a non-login interactive shell never reads. Falling back
# to the absolute path means these targets work either way.
NPM       ?= $(shell command -v npm 2>/dev/null || echo $(HOME)/.local/bin/npm)
GO        ?= $(shell command -v go  2>/dev/null || echo $(HOME)/.local/bin/go)
HOST      ?= 127.0.0.1
PORT      ?= 8000

.PHONY: help
help: ## Show available targets
	@grep -hE '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) \
	  | awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-16s\033[0m %s\n", $$1, $$2}'

# --------------------------------------------------------------------------- #
# Setup
# --------------------------------------------------------------------------- #
.PHONY: tools
tools: ## Create the schema-validation venv (CPython 3.12)
	$(UV) venv --python 3.12 .venv-tools
	$(UV) pip install --python $(PY_TOOLS) -r tools/requirements-phase0.txt

.PHONY: server-venv
server-venv: ## Create the server venv and install it editable with dev extras
	$(UV) venv --python 3.12 $(SERVER)/.venv
	cd $(SERVER) && $(UV) pip install --python .venv/bin/python -e ".[dev]"

.PHONY: setup
setup: tools server-venv ## Everything needed to run the test suites

# --------------------------------------------------------------------------- #
# Database
# --------------------------------------------------------------------------- #
.PHONY: db
db: ## Create and migrate the local dev database (no sudo, port 55432)
	cd $(SERVER) && ./scripts/dev_db.sh up

.PHONY: db-status
db-status: ## Show cluster, roles and database state
	cd $(SERVER) && ./scripts/dev_db.sh status

.PHONY: db-stop
db-stop: ## Stop the local dev cluster
	cd $(SERVER) && ./scripts/dev_db.sh stop

.PHONY: db-psql
db-psql: ## Open a superuser psql shell on the dev database
	cd $(SERVER) && ./scripts/dev_db.sh psql

.PHONY: db-migrate
db-migrate: ## Re-run migrations, then re-apply the least-privilege grants
	cd $(SERVER) && ./scripts/dev_db.sh migrate

.PHONY: db-destroy
db-destroy: ## Delete the dev cluster entirely (asks for confirmation)
	cd $(SERVER) && ./scripts/dev_db.sh destroy

# --------------------------------------------------------------------------- #
# Run
# --------------------------------------------------------------------------- #
.PHONY: api
api: ## Run the API server (bound to localhost by design; see device_auth.py)
	@test -x $(PY_SERVER) || { echo "run 'make server-venv' first"; exit 1; }
	cd $(SERVER) && .venv/bin/python -m uvicorn ubuntuguard.main:create_app \
	  --factory --host $(HOST) --port $(PORT) --reload --no-proxy-headers

.PHONY: dash
dash: ## Run the dashboard dev server (proxies /api to the backend)
	cd dashboard && $(NPM) run dev

.PHONY: dash-build
dash-build: ## Type-check and build the dashboard for production
	cd dashboard && $(NPM) run build

.PHONY: dash-install
dash-install: ## Install dashboard dependencies
	cd dashboard && $(NPM) install

.PHONY: seed
seed: ## Seed simulated devices. EMAIL=... PASSWORD=... [COUNT=50]
	@test -n "$(EMAIL)" && test -n "$(PASSWORD)" || { \
	  echo "usage: make seed EMAIL=<admin-email> PASSWORD='...' [COUNT=50]"; exit 1; }
	./tools/seed_devices.py --email '$(EMAIL)' --password '$(PASSWORD)' --count $(or $(COUNT),50)

.PHONY: toolchain
toolchain: ## Install Go and Node under ~/.local (no sudo, checksums verified)
	python3 tools/install_toolchain.py

.PHONY: keys
keys: ## Generate the internal CA and the policy signing key (mode 0600)
	cd $(SERVER) && .venv/bin/python -m ubuntuguard.cli init-keys

.PHONY: admin
admin: ## Create an admin account. EMAIL=<your-email> ROLE=<role>
	@test -n "$(EMAIL)" && test -n "$(ROLE)" || { \
	  echo "usage: make admin EMAIL=<admin-email> ROLE=<role>"; \
	  echo "the CLI lists the valid roles:"; \
	  echo "  cd $(SERVER) && .venv/bin/python -m ubuntuguard.cli create-admin --help"; \
	  exit 1; }
	cd $(SERVER) && .venv/bin/python -m ubuntuguard.cli create-admin --email '$(EMAIL)' --role '$(ROLE)'

.PHONY: verify-audit
verify-audit: ## Recompute the audit hash chain from the command line
	cd $(SERVER) && .venv/bin/python -m ubuntuguard.cli verify-audit

.PHONY: bootstrap
bootstrap: db keys ## Database + key material, ready for `make admin EMAIL=...`

.PHONY: demo
demo: ## Security core walkthrough with live attacks (no server, no database)
	@test -x $(PY_SERVER) || { echo "run 'make server-venv' first"; exit 1; }
	$(PY_SERVER) tools/demo_security_core.py

.PHONY: demo-api
demo-api: ## API walkthrough against a running server. EMAIL=... [PASSWORD=...]
	@test -x $(PY_SERVER) || { echo "run 'make server-venv' first"; exit 1; }
	@test -n "$(EMAIL)" || { \
	  echo "usage: make demo-api EMAIL=<admin-email> [PASSWORD='...']"; exit 1; }
	$(PY_SERVER) tools/demo_api.py --email '$(EMAIL)' $(if $(PASSWORD),--password '$(PASSWORD)',)

# --------------------------------------------------------------------------- #
# Verification
# --------------------------------------------------------------------------- #
.PHONY: verify
verify: ## Validate schemas, examples and the committed signing vector
	@test -x $(PY_TOOLS) || { echo "run 'make tools' first"; exit 1; }
	$(PY_TOOLS) tools/validate_phase0.py

.PHONY: server-test
server-test: ## Run the server suite (database tests skip if no database)
	@test -x $(PY_SERVER) || { echo "run 'make server-venv' first"; exit 1; }
	cd $(SERVER) && .venv/bin/python -m pytest

.PHONY: db-test
db-test: ## Run only the database-backed tests (non-destructive)
	cd $(SERVER) && .venv/bin/python -m pytest -m postgres -v

.PHONY: db-test-destructive
db-test-destructive: ## Migration up/down tests. DROPS EVERY TABLE, then repairs.
	cd $(SERVER) && UG_ALLOW_DESTRUCTIVE_TESTS=1 .venv/bin/python -m pytest -m destructive -v
	@echo
	@echo "Schema was dropped and recreated. Restoring grants and the admin account:"
	cd $(SERVER) && ./scripts/dev_db.sh migrate
	@echo "Now re-create an admin: cd server && .venv/bin/python -m ubuntuguard.cli create-admin --email <your-email> --role <role>"

.PHONY: lint
lint: ## ruff check, ruff format --check and mypy --strict
	cd $(SERVER) && .venv/bin/ruff check . \
	  && .venv/bin/ruff format --check . \
	  && .venv/bin/mypy

.PHONY: test
test: verify server-test ## Every check that currently exists

.PHONY: vectors
vectors: ## Regenerate testdata/policy_vectors.json after an envelope change
	$(PY_TOOLS) tools/make_policy_vectors.py

.PHONY: migration
migration: ## Regenerate the initial migration from the models
	cd $(SERVER) && .venv/bin/python scripts/generate_initial_migration.py

.PHONY: spike-env
spike-env: ## Read-only USBGuard environment survey (no changes)
	cd spike/usbguard && ./spike.sh env

# --------------------------------------------------------------------------- #
# Not yet implemented
# --------------------------------------------------------------------------- #
.PHONY: agent
agent: ; @echo "Phase 2: Go agentd + enforcerd.";        exit 1
