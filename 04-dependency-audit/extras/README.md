# Extras

The assessment asks for a scan, a list of vulnerabilities, fixes, a count of fixable issues and an optional script. That is in [../README.md](../README.md) and [../REPORT.md](../REPORT.md).

This folder holds work that goes beyond that. None of it is needed to read the answer.

| Path | What it is |
|---|---|
| [REPORT.md](REPORT.md) | Second scanner comparison and how to handle disagreements, EPSS scores, API probe results for the major upgrades, an `overrides` experiment |
| `compare_scanners.py` | Compares `npm audit --json` and `trivy fs` JSON by GHSA id |
| `breaking-change-probe.js` | Calls APIs that changed in `jsonwebtoken` and `mongoose`. No database or network |
| `tests/` | Unit tests for `compare_scanners.py` |
| `reports/` | Saved outputs: scanner comparison, probe runs, a mocha smoke test, the `overrides` run |

## Run

From the repository root, `make dep-audit-test` also runs the extras tests.

```sh
cd 04-dependency-audit
python3 extras/compare_scanners.py reports/npm-audit-before.json reports/trivy-before.json
```

The probe needs the packages installed in a scratch directory. Never run a normal `npm install` on `vulnerable-input/`:

```sh
mkdir /tmp/probe && cp fixed/package*.json extras/breaking-change-probe.js /tmp/probe
cd /tmp/probe && npm ci --ignore-scripts && node breaking-change-probe.js
```
