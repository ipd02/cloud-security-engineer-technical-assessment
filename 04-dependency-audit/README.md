# Part 4: third-party dependency audit

This part scans the `package.json` from the assessment, reports the vulnerable dependencies, proposes a fixed manifest and proves it with a second scan. A small Python script turns `npm audit --json` into JSON and CSV.

Read [REPORT.md](REPORT.md) for the findings, the fix and the remediation plan.

## Result

24 vulnerable packages (46 advisories) before. 0 after. The fix needs three semver-major upgrades (`mongoose`, `jsonwebtoken`, `mocha`) and two pin changes (`express`, `lodash`). Plain `npm audit fix` fixes none of the 24 because of the exact pins. Details and counts are in REPORT.md.

## Layout

| Path | Purpose |
|---|---|
| `vulnerable-input/package.json` | The task input, unchanged. Its lockfile is generated. |
| `fixed/package.json` | Proposed upgrades, with a lockfile. |
| `fixed/breaking-change-probe.js` | Calls changed APIs of `jsonwebtoken` and `mongoose` without a database. |
| `audit_report.py` | Bonus script, standard library only. |
| `compare_scanners.py` | Compares `npm audit` and `trivy fs` output by GHSA id. |
| `tests/` | Unit tests for `audit_report.py` with small fixtures. |
| `reports/` | Raw scanner output, with dates and tool versions, plus generated JSON and CSV. |
| `part.mk` | Make targets, picked up by the root `Makefile`. |

GitHub dependency alerts on `vulnerable-input/` are expected. The folder is the test input and is left out of Dependabot on purpose.

## Run it

From the repository root:

```sh
make dep-audit-test     # unit tests
make dep-audit-lint     # ruff check and format check
make dep-audit-scan     # trivy: fixed/ passes, vulnerable-input/ must fail (needs network for the trivy DB)
make dep-audit-report   # rebuild JSON and CSV from the saved reports
```

To repeat the scan yourself (needs network, never run a normal `npm install` on the vulnerable folder):

```sh
cd 04-dependency-audit/vulnerable-input
npm install --package-lock-only --ignore-scripts
npm audit --json > /tmp/audit.json
python3 ../audit_report.py /tmp/audit.json --lockfile package-lock.json \
  --json-out /tmp/v.json --csv-out /tmp/v.csv --min-severity high --fail-on critical
```

The probe script needs the fixed packages installed in a scratch directory, with `npm ci --ignore-scripts`.

## audit_report.py

```
audit_report.py INPUT [--lockfile package-lock.json] [--trivy trivy.json]
                [--json-out F] [--csv-out F] [--min-severity LEVEL] [--fail-on LEVEL]
```

- Reads the npm 7 and later format (`vulnerabilities`). Falls back to the npm 6 format (`advisories`). `-` reads stdin.
- Writes one row per advisory, plus one row for packages that are vulnerable only through a dependency. Fields: package, severity, direct or not, installed versions, GHSA id, CVE, CWE, CVSS score, range, fix package and version, whether the fix is a major bump.
- `--lockfile` adds installed versions. `--trivy` adds CVE ids by matching GHSA ids.
- `--min-severity` filters the output and the summary. `--fail-on` exits 1 if any remaining finding is at that level or above. Exit 2 means unreadable input.
- Prints counts by severity (packages and advisories) and how many packages are fixable with and without a major bump.
- Missing fields, empty results, `null` sections and `fixAvailable` as bool or object are handled. Tests cover each case.

## What was verified

Run in this session on 2026-10-13 (npm 11.19.1, Node v26.10.0, trivy 0.75.0, Python 3.12.1, ruff 0.17.0):

- `npm audit` and `npm audit --json` on both lockfiles. Raw output is in `reports/`.
- `trivy fs` on both lockfiles, and the comparison with npm audit.
- `npm audit fix` and `npm audit fix --force` on scratch copies, lockfile only.
- `fixed/breaking-change-probe.js` against the old and new `jsonwebtoken` and `mongoose`, installed with `--ignore-scripts`.
- `make dep-audit-test`, `make dep-audit-lint`, `make dep-audit-scan`.

Not verified: the behaviour of a real application after the upgrades (no application code is provided), and any live database. The scan results depend on the advisory databases at that date.

## About the input file

The task text was taken from the PDF as plain text, so the indentation of `package.json` is not preserved. The file is kept as extracted. Do not run whitespace fixers on `vulnerable-input/` or `reports/` (the pre-commit config already excludes both).
