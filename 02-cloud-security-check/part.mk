# Part 2: cloud security check. Recipes run from the repo root.
CC_DIR := 02-cloud-security-check

.PHONY: cloud-check-lint cloud-check-test cloud-check-scan cloud-check-build
LINT_TARGETS += cloud-check-lint
TEST_TARGETS += cloud-check-test
SCAN_TARGETS += cloud-check-scan

cloud-check-lint: ## Part 2: cfn-lint and hadolint on the hardened files
	cfn-lint $(CC_DIR)/cloudformation/hardened.yaml
	hadolint $(CC_DIR)/docker/Dockerfile.hardened

cloud-check-test: ## Part 2: originals must fail the scanners, hardened must pass
	$(CC_DIR)/tests/assert-originals-fail.sh

cloud-check-scan: ## Part 2: checkov and trivy config on the hardened files
	checkov -f $(CC_DIR)/cloudformation/hardened.yaml --framework cloudformation --quiet
	checkov -f $(CC_DIR)/docker/Dockerfile.hardened --framework dockerfile --quiet
	trivy config --exit-code 1 $(CC_DIR)/cloudformation/hardened.yaml
	trivy config --exit-code 1 --severity HIGH,CRITICAL $(CC_DIR)/docker/Dockerfile.hardened

cloud-check-build: ## Part 2: build the hardened image locally (needs docker)
	docker build -f $(CC_DIR)/docker/Dockerfile.hardened -t cloud-check-hardened:local $(CC_DIR)/docker
