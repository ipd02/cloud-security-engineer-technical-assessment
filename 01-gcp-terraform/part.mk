# Part 1: Secure GCP infrastructure with Terraform. Recipes run from the repo root.
# Two standalone versions, base and extended. Each has module/ (the Terraform
# module) and examples/basic (a caller).
TF_DIR      := 01-gcp-terraform
TF_MODS     := $(TF_DIR)/base/module $(TF_DIR)/extended/module
TF_EXAMPLES := $(TF_DIR)/base/examples/basic $(TF_DIR)/extended/examples/basic

FMT_TARGETS  += tf-fmt
LINT_TARGETS += tf-lint
TEST_TARGETS += tf-test
SCAN_TARGETS += tf-scan

.PHONY: tf-fmt tf-init tf-lint tf-test tf-scan

tf-fmt: ## Part 1: format Terraform files
	terraform fmt -recursive $(TF_DIR)

# -lockfile=readonly fails if a provider constraint and its lock file disagree.
tf-init: ## Part 1: init without a backend (no credentials)
	for m in $(TF_MODS); do terraform -chdir=$$m init -backend=false -input=false -lockfile=readonly || exit 1; done
	for e in $(TF_EXAMPLES); do terraform -chdir=$$e init -backend=false -input=false -lockfile=readonly || exit 1; done

tf-lint: tf-init ## Part 1: fmt check, validate (modules and examples) and tflint
	terraform fmt -check -recursive $(TF_DIR)
	for d in $(TF_MODS) $(TF_EXAMPLES); do terraform -chdir=$$d validate || exit 1; done
	tflint --chdir=$(TF_DIR) --config=$(CURDIR)/.tflint.hcl --recursive

tf-test: tf-init ## Part 1: terraform test with a mocked provider
	for m in $(TF_MODS); do terraform -chdir=$$m test || exit 1; done

tf-scan: ## Part 1: checkov on both versions
	checkov -d $(TF_DIR) --external-checks-dir $(TF_DIR)/policy/checkov
