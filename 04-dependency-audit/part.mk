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

dep-audit-test: ## Part 4: unit tests for audit_report.py and the extras
	cd $(DEP_AUDIT_DIR) && python3 -m unittest discover -s tests -t . -v
	cd $(DEP_AUDIT_DIR)/extras && python3 -m unittest discover -s tests -t . -v

# The fixed manifest must be clean and the original must still be caught.
# Both need the trivy vulnerability database (network on first run).
# The vulnerable scan uses exit code 5, which trivy only returns for findings.
# Any other non-zero code (bad path, no database, crash) is an error, not a pass.
TRIVY_SCAN := trivy fs --quiet --scanners vuln --include-dev-deps --severity HIGH,CRITICAL
VULN_EXIT := 5

dep-audit-scan: ## Part 4: trivy passes on fixed/ and finds issues in vulnerable-input/
	$(TRIVY_SCAN) --exit-code 1 $(DEP_AUDIT_DIR)/fixed
	@$(TRIVY_SCAN) --exit-code $(VULN_EXIT) $(DEP_AUDIT_DIR)/vulnerable-input >/dev/null; code=$$?; \
	if [ $$code -eq $(VULN_EXIT) ]; then \
		echo "vulnerable-input has findings, as expected"; \
	elif [ $$code -eq 0 ]; then \
		echo "ERROR: vulnerable-input was expected to have findings"; exit 1; \
	else \
		echo "ERROR: trivy failed with exit code $$code, the scan did not run"; exit 1; \
	fi

dep-audit-report: ## Part 4: rebuild the JSON and CSV from the saved reports
	cd $(DEP_AUDIT_DIR)/reports && python3 ../audit_report.py npm-audit-before.json \
		--lockfile ../vulnerable-input/package-lock.json --trivy trivy-before.json \
		--epss epss-before.json \
		--json-out vulnerabilities-before.json --csv-out vulnerabilities-before.csv \
		> audit_report-before-summary.txt
	cd $(DEP_AUDIT_DIR)/reports && python3 ../audit_report.py npm-audit-after.json \
		--lockfile ../fixed/package-lock.json \
		--json-out vulnerabilities-after.json --csv-out vulnerabilities-after.csv \
		> audit_report-after-summary.txt
