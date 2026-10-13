# Part 4: dependency audit. Recipes run from the repository root.
DEP_AUDIT_DIR := 04-dependency-audit

FMT_TARGETS  += dep-audit-fmt
LINT_TARGETS += dep-audit-lint
TEST_TARGETS += dep-audit-test
SCAN_TARGETS += dep-audit-scan

.PHONY: dep-audit-fmt dep-audit-lint dep-audit-test dep-audit-scan dep-audit-report

dep-audit-fmt: ## Part 4: format the Python scripts with ruff
	ruff format $(DEP_AUDIT_DIR)

dep-audit-lint: ## Part 4: ruff check and format check
	ruff check $(DEP_AUDIT_DIR)
	ruff format --check $(DEP_AUDIT_DIR)

dep-audit-test: ## Part 4: unit tests for audit_report.py
	cd $(DEP_AUDIT_DIR) && python3 -m unittest discover -s tests -t . -v

# The fixed manifest must be clean and the original must still be caught.
# Both need the trivy vulnerability database (network on first run).
dep-audit-scan: ## Part 4: trivy passes on fixed/ and fails on vulnerable-input/
	trivy fs --quiet --scanners vuln --include-dev-deps --severity HIGH,CRITICAL --exit-code 1 $(DEP_AUDIT_DIR)/fixed
	@if trivy fs --quiet --scanners vuln --include-dev-deps --severity HIGH,CRITICAL --exit-code 1 $(DEP_AUDIT_DIR)/vulnerable-input >/dev/null; then \
		echo "ERROR: vulnerable-input was expected to fail the scan"; exit 1; \
	else \
		echo "vulnerable-input fails the scan as expected"; \
	fi

dep-audit-report: ## Part 4: rebuild the JSON and CSV from the saved npm audit output
	cd $(DEP_AUDIT_DIR)/reports && python3 ../audit_report.py npm-audit-before.json \
		--lockfile ../vulnerable-input/package-lock.json --trivy trivy-before.json \
		--json-out vulnerabilities-before.json --csv-out vulnerabilities-before.csv
	cd $(DEP_AUDIT_DIR)/reports && python3 ../audit_report.py npm-audit-after.json \
		--lockfile ../fixed/package-lock.json \
		--json-out vulnerabilities-after.json --csv-out vulnerabilities-after.csv
