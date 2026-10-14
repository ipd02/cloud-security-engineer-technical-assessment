# Extras

The assessment asks for a scan, a list of vulnerabilities, fixes, a count of fixable issues and an optional script. That answer is in [../README.md](../README.md) and [../REPORT.md](../REPORT.md).

This folder holds work beyond that. None of it is needed to read the answer. Each extra below says what was done, why, and how to run it. The full write-up is in [REPORT.md](REPORT.md).

| # | Extra | What was done | Files |
|---|---|---|---|
| 1 | Second scanner comparison | Compared `npm audit` and `trivy` by advisory id, and wrote down what to do when they disagree. | `compare_scanners.py`, [REPORT.md section 1](REPORT.md#1-cross-check-with-trivy), `reports/scanner-comparison.txt` |
| 2 | EPSS scores | Added the FIRST exploit-probability score to the report, to order work inside a severity level. | [REPORT.md section 2](REPORT.md#2-epss-scores), `../reports/before/epss.json` |
| 3 | API probes | Called the APIs that change in `jsonwebtoken` and `mongoose` in the old and new versions, and ran one mocha test. | `breaking-change-probe.js`, [REPORT.md section 3](REPORT.md#3-what-breaks-in-the-major-upgrades-probe-results), `reports/breaking-change-probe-*.txt`, `reports/mocha-smoke.txt` |
| 4 | `overrides` experiment | Forced patched versions of two transitive packages without upgrading `express`. | [REPORT.md section 4](REPORT.md#4-forcing-a-transitive-version-with-overrides), `reports/npm-audit-overrides-applied.txt` |
| 5 | Accepted risks | A version of the script that skips risks someone has reviewed and accepted, for scans that run on a schedule. | `audit_report_accepted.py`, `accepted-risks.example.json`, [REPORT.md section 5](REPORT.md#5-accepted-risks) |

Unit tests for the two scripts are in `tests/`. `make dep-audit-test`, from the repository root, runs them with the main tests.

## 1. Scanner comparison

`npm audit` finds 46 advisories and `trivy` finds 45. 45 match by id with the same severity. The one difference is a mongoose advisory that only npm reports.

```sh
cd 04-dependency-audit
python3 extras/compare_scanners.py reports/before/npm-audit.json reports/before/trivy.json
```

## 2. EPSS scores

44 of the 46 advisories have a score. The two without a CVE id have none. Scores come from the public FIRST API, saved in `reports/before/epss.json` with its date. `audit_report.py --epss FILE` adds them to the report, and `--epss-fetch` asks the API directly.

## 3. API probes

Each major upgrade removes or changes something. The probe records which calls still work. It uses no database and no network.

```sh
probe_dir=$(mktemp -d)
cp fixed/package*.json extras/breaking-change-probe.js "$probe_dir"
cd "$probe_dir" && npm ci --ignore-scripts && node breaking-change-probe.js
```

Never run a normal `npm install` on `vulnerable-input/`.

## 4. `overrides` experiment

With `overrides` for `qs` and `path-to-regexp`, `npm audit` goes from 24 vulnerable packages to 22, with `express` still on 4.15.0. Output: `reports/npm-audit-overrides-applied.txt`.

## 5. Accepted risks

A scan that runs every week reports the same unfixable finding every week. `audit_report_accepted.py` reads a committed file of accepted risks. A finding on the list is left out of the report and out of the `--fail-on` gate, and it comes back when its acceptance expires.

```sh
cd 04-dependency-audit
python3 extras/audit_report_accepted.py tests/fixtures/custom-app/audit-npm11.json \
  --accepted extras/accepted-risks.example.json --accepted-out /tmp/accepted.json \
  --json-out /tmp/v.json --csv-out /tmp/v.csv --fail-on critical
```

It takes every option of `audit_report.py` and adds `--accepted FILE` (required), `--accepted-out FILE` (the findings left out, with their entries), `--today DATE` and `--warn-days N`. Each entry needs an advisory id, a package, a reason, the controls that make the risk acceptable, an owner and an expiry date. The file format and the rules for accepting a risk are in [REPORT.md, section 5](REPORT.md#5-accepted-risks).
