# Aggregate targets. Each part adds its own targets in <part>/part.mk
# and registers them in the lists below.
SHELL := /bin/bash
.DEFAULT_GOAL := help

FMT_TARGETS  :=
LINT_TARGETS :=
TEST_TARGETS :=
SCAN_TARGETS :=

-include 0*/part.mk

.PHONY: help fmt lint test scan secrets
help: ## Show this help
	@grep -hE '^[a-zA-Z0-9_-]+:.*## ' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*## "}; {printf "  %-22s %s\n", $$1, $$2}' | sort

fmt: $(FMT_TARGETS) ## Format all code
lint: $(LINT_TARGETS) ## Run all linters
test: $(TEST_TARGETS) ## Run all tests, no credentials needed
scan: $(SCAN_TARGETS) ## Run all security scanners on the hardened files

secrets: ## Scan the full git history for secrets
	gitleaks detect --config .gitleaks.toml --redact --verbose
