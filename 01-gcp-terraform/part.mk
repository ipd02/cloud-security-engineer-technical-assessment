# Part 1: Secure GCP infrastructure with Terraform. Recipes run from the repo root.
# Standalone modules, one per directory under $(TF_DIR).
TF_DIR  := 01-gcp-terraform
TF_MODS := $(TF_DIR)/extended

FMT_TARGETS  += tf-fmt
LINT_TARGETS += tf-lint
TEST_TARGETS += tf-test
SCAN_TARGETS += tf-scan

.PHONY: tf-fmt tf-init tf-lint tf-test tf-scan

tf-fmt: ## Part 1: format Terraform files
	terraform fmt -recursive $(TF_DIR)

tf-init: ## Part 1: init without a backend (no credentials)
	for m in $(TF_MODS); do terraform -chdir=$$m init -backend=false -input=false || exit 1; done

tf-lint: tf-init ## Part 1: fmt check, validate and tflint
	terraform fmt -check -recursive $(TF_DIR)
	for m in $(TF_MODS); do terraform -chdir=$$m validate || exit 1; done
	tflint --chdir=$(TF_DIR) --config=$(CURDIR)/.tflint.hcl --recursive

tf-test: tf-init ## Part 1: terraform test with a mocked provider
	for m in $(TF_MODS); do terraform -chdir=$$m test || exit 1; done

tf-scan: ## Part 1: checkov on both modules
	checkov -d $(TF_DIR) --external-checks-dir $(TF_DIR)/policy/checkov
