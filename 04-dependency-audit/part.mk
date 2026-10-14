# Part 4: dependency audit. Recipes run from the repository root.
DEP_AUDIT_DIR := 04-dependency-audit

FMT_TARGETS  += dep-audit-fmt
LINT_TARGETS += dep-audit-lint
TEST_TARGETS += dep-audit-test
SCAN_TARGETS += dep-audit-scan

.PHONY: dep-audit-fmt dep-audit-lint dep-audit-test dep-audit-scan dep-audit-trivy dep-audit-report

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
	@trivy --version

# Reruns trivy on both folders and saves JSON, text and a meta file in reports/before and
# reports/after. The meta file holds the trivy version and the vulnerability database
# version and update time, which decide the findings. Run it when you refresh the saved reports.
dep-audit-trivy: ## Part 4: rerun trivy on both folders and save the output with its versions
	@for pair in before:vulnerable-input after:fixed; do \
		name=$${pair%%:*}; dir=$${pair##*:}; out=$(CURDIR)/$(DEP_AUDIT_DIR)/reports/$$name/trivy; \
		(cd $(DEP_AUDIT_DIR)/$$dir && trivy fs --quiet --scanners vuln --include-dev-deps -f json -o $$out.json . \
			&& trivy fs --quiet --scanners vuln --include-dev-deps -o $$out.txt .) || exit 1; \
		{ echo "date_utc: $$(date -u +%Y-%m-%dT%H:%M:%SZ)"; \
		  echo "cmd: trivy fs --scanners vuln --include-dev-deps (run in $$dir/)"; \
		  trivy --version; } > $$out.meta.txt; \
	done

dep-audit-report: ## Part 4: rebuild the JSON, CSV and summaries from the saved reports
	cd $(DEP_AUDIT_DIR)/reports/before && python3 ../../audit_report.py npm-audit.json \
		--lockfile ../../vulnerable-input/package-lock.json --trivy trivy.json --epss epss.json \
		--json-out vulnerabilities.json --csv-out vulnerabilities.csv > summary.txt
	cd $(DEP_AUDIT_DIR)/reports/before && python3 ../../audit_report.py npm-audit.json \
		--lockfile ../../vulnerable-input/package-lock.json --trivy trivy.json --epss epss.json \
		--min-severity high --json-out high-critical.json --csv-out high-critical.csv > /dev/null
	cd $(DEP_AUDIT_DIR)/reports/after && python3 ../../audit_report.py npm-audit.json \
		--lockfile ../../fixed/package-lock.json \
		--json-out vulnerabilities.json --csv-out vulnerabilities.csv > summary.txt
