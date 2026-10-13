# Part 1: Secure GCP infrastructure with Terraform. Recipes run from the repo root.
TF_DIR := 01-gcp-terraform

FMT_TARGETS  += tf-fmt
LINT_TARGETS += tf-lint
TEST_TARGETS += tf-test
SCAN_TARGETS += tf-scan

.PHONY: tf-fmt tf-init tf-lint tf-test tf-scan

tf-fmt: ## Part 1: format Terraform files
	terraform fmt -recursive $(TF_DIR)

tf-init: ## Part 1: init without a backend (no credentials)
	terraform -chdir=$(TF_DIR) init -backend=false -input=false

tf-lint: tf-init ## Part 1: fmt check, validate and tflint
	terraform fmt -check -recursive $(TF_DIR)
	terraform -chdir=$(TF_DIR) validate
	tflint --chdir=$(TF_DIR) --config=$(CURDIR)/.tflint.hcl --recursive

tf-test: tf-init ## Part 1: terraform test with a mocked provider
	terraform -chdir=$(TF_DIR) test

tf-scan: ## Part 1: checkov on the Terraform module
	checkov -d $(TF_DIR)
