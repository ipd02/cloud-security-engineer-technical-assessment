# Extras

The assessment asks for a scan, a list of vulnerabilities, fixes, a count of fixable issues and an optional script. That is in [../README.md](../README.md) and [../REPORT.md](../REPORT.md).

This folder holds work that goes beyond that. None of it is needed to read the answer.

| Path | What it is |
|---|---|
| [REPORT.md](REPORT.md) | Second scanner comparison and how to handle disagreements, EPSS scores, API probe results for the major upgrades, an `overrides` experiment, accepted risks and their compensating controls |
| `compare_scanners.py` | Compares `npm audit --json` and `trivy fs` JSON by GHSA id |
| `breaking-change-probe.js` | Calls APIs that changed in `jsonwebtoken` and `mongoose`. No database or network |
| `audit_report_accepted.py` | `audit_report.py` plus a list of accepted risks. Findings on the list are no longer reported. For scans that run on a schedule |
| `accepted-risks.example.json` | Example list of accepted risks |
| `tests/` | Unit tests for `compare_scanners.py` and `audit_report_accepted.py` |
| `reports/` | Saved outputs: scanner comparison, probe runs, a mocha smoke test, the `overrides` run |

## Run

From the repository root, `make dep-audit-test` also runs the extras tests.

```sh
cd 04-dependency-audit
python3 extras/compare_scanners.py reports/npm-audit-before.json reports/trivy-before.json
```

The probe needs the packages installed in a scratch directory. Never run a normal `npm install` on `vulnerable-input/`:

```sh
probe_dir=$(mktemp -d)
cp fixed/package*.json extras/breaking-change-probe.js "$probe_dir"
cd "$probe_dir" && npm ci --ignore-scripts && node breaking-change-probe.js
```

## Accepted risks

A scan that runs every week reports the same unfixable finding every week. `audit_report_accepted.py` takes a file of accepted risks, so a finding someone has already reviewed is not reported again, and it comes back when the acceptance expires.

```sh
cd 04-dependency-audit
python3 extras/audit_report_accepted.py tests/fixtures/custom-app/audit-npm11.json   --accepted extras/accepted-risks.example.json --accepted-out /tmp/accepted.json   --json-out /tmp/v.json --csv-out /tmp/v.csv --fail-on critical
```

It takes every option of `audit_report.py` and adds `--accepted FILE` (required), `--accepted-out FILE` (the findings that were left out, with their entries), `--today DATE` and `--warn-days N`. The file format and the rules for accepting a risk are in [REPORT.md](REPORT.md), section 5.
