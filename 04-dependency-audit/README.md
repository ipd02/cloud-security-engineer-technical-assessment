# Part 4: third-party dependency audit

This part scans the `package.json` from the assessment, reports the vulnerable dependencies, proposes a fixed manifest and proves it with a second scan. A small Python script turns `npm audit --json` into JSON and CSV.

Read [REPORT.md](REPORT.md) for the findings, the fix and the remediation plan. Section 9 covers what to do when an upgrade is not possible or breaks things. Extra checks (second scanner, EPSS, API probes) are in [extras/](extras/README.md).

## Result

24 vulnerable packages (46 advisories) before. 0 after. The fix needs three semver-major upgrades (`mongoose`, `jsonwebtoken`, `mocha`) and two pin changes (`express`, `lodash`). Plain `npm audit fix` fixes none of the 24. Half need a new range for the exact pins on `express` and `lodash`. The other half need a major bump, which `npm audit fix` never does. Details and counts are in REPORT.md.

## Layout

| Path | Purpose |
|---|---|
| `vulnerable-input/package.json` | The task input, content as given (whitespace reconstructed). Its lockfile is generated. |
| `fixed/package.json` | Proposed upgrades, with a lockfile. |
| `audit_report.py` | Bonus script, standard library only. |
| `extras/` | Checks beyond the task: second scanner comparison, EPSS, API probes, a script version that honours accepted risks. See [extras/README.md](extras/README.md). |
| `tests/` | Unit tests for `audit_report.py`, with small fixtures. |
| `reports/` | Raw scanner output, with dates and tool versions, plus generated JSON and CSV. |
| `part.mk` | Make targets, picked up by the root `Makefile`. |

GitHub dependency alerts on `vulnerable-input/` and `tests/fixtures/custom-app/` are expected. The folder is the test input and is left out of `dependabot.yml`, which stops version update PRs. If Dependabot security updates are switched on for the repository, GitHub can still open security PRs for it. Keep them off, or dismiss the alerts.

## Run it

From the repository root:

```sh
make dep-audit-test     # unit tests
make dep-audit-lint     # ruff check and format check
make dep-audit-scan     # trivy: fixed/ passes, vulnerable-input/ must return exit code 5 (findings). Any other failure is an error
make dep-audit-report   # rebuild JSON, CSV and summaries from the saved reports (only meta.generated_at changes)
```

To repeat the scan yourself (needs network, never run a normal `npm install` on the vulnerable folder):

```sh
cd 04-dependency-audit/vulnerable-input
npm install --package-lock-only --ignore-scripts
npm audit --json > /tmp/audit.json
python3 ../audit_report.py /tmp/audit.json --lockfile package-lock.json \
  --json-out /tmp/v.json --csv-out /tmp/v.csv --min-severity high --fail-on critical
```

## audit_report.py

```
audit_report.py INPUT [--lockfile package-lock.json] [--trivy trivy.json]
                [--epss F | --epss-fetch] [--min-epss P]
                [--json-out F] [--csv-out F] [--min-severity LEVEL] [--fail-on LEVEL]
```

- Reads the npm 7 and later format (`vulnerabilities`). Falls back to the npm 6 format (`advisories`). `-` reads stdin.
- Writes one row per package and advisory, plus one row for packages that are vulnerable only through a dependency. The summary counts these rows, so an advisory that hits two packages counts twice. Fields: package, severity, direct or not, installed versions, GHSA id, CVE, CWE, CVSS score, range, fix package and version, whether the fix is a major bump.
- A version that also reads a list of accepted risks, so reviewed findings are not reported again, is in [extras/](extras/README.md#accepted-risks).
- `--lockfile` adds installed versions. `--trivy` adds CVE ids by matching GHSA ids.
- `--epss` adds the EPSS score and percentile from a saved FIRST EPSS API response. `--epss-fetch` asks `api.first.org` for the CVE ids instead (public, no key, needs network). EPSS needs CVE ids, and `npm audit` only gives GHSA ids, so pass `--trivy` too. Without it the script warns and adds no scores. The highest score of a row's CVEs is used. `--min-epss` drops advisories whose known score is below the value. Advisories with no score are kept, so a missing score never hides a finding.
- `--min-severity` filters the output and the summary. `--fail-on` exits 1 if any remaining finding is at that level or above. Exit 2 means unreadable or malformed input, a failed EPSS lookup, or a write error.
- A severity label the script does not know never lowers a finding. It falls back to the package severity, then to `critical`, and prints a warning.
- CSV cells that start with `=`, `+`, `-`, `@`, tab or carriage return get a leading `'` so spreadsheets do not read them as formulas. The JSON is not changed. The JSON has a `meta` block with the tool, time, input name and EPSS source and date.
- Prints counts by severity (packages and advisories) and how many packages are fixable with and without a major bump.
- Missing fields, empty results, `null` sections and `fixAvailable` as bool or object are handled, as are an empty file, non-UTF-8 input, wrong-shaped entries and an unwritable output path. Tests cover each case.
- The npm 6 reader is tested with real `npm audit --json` output from npm 6.14.18 and npm 11.19.1 for a `package.json` written for this tool (`tests/fixtures/custom-app/`). Both outputs list the same 21 advisories, and the tests check that our parser gives the same package, severity and advisory id for each. Hand-written files (`tests/fixtures/audit_v6*.json`) cover malformed shapes. Rows are sorted by package, then advisory id. A package counts as fixable only if all its advisories have a fix.
- In the npm 6 format a fix means the advisory has a patched version. npm 7 and later also check that the dependency tree can reach it, so the same input gives more packages without a fix. In `custom-app`, npm 6 shows 1 package without a fix and npm 11 shows 5.

## What was verified

`npm audit` ran on 2026-10-13 and trivy on 2026-10-14 (npm 11.19.1, Node v26.10.0, trivy 0.75.0, Python 3.12.1, ruff 0.17.0). EPSS scores are from 2026-10-14. The saved trivy output was made on 2026-10-14 with vulnerability database version 2, updated 2026-10-14 13:10 UTC (see `reports/trivy-*.meta.txt`). `make dep-audit-trivy` repeats it and records the versions:

- `npm audit` and `npm audit --json` on both lockfiles. Raw output is in `reports/`.
- `trivy fs` on both lockfiles.
- `npm audit fix` and `npm audit fix --force` on scratch copies, lockfile only.
- The extra checks in `extras/` (see its README).
- `make dep-audit-test`, `make dep-audit-lint`, `make dep-audit-scan`.
- The audit was repeated on 2026-10-14 in scratch copies. Same 24 packages and 46 advisories.
- `audit_report.py` was checked with single-line changes to the code (mutation checks). Each one is caught by a test.

Scope: the scans cover the dependency tree in `package.json`. The task provides no application code, so the report says which upgrades change which APIs and does not claim the application runs after them. Scan results depend on the advisory databases at the scan date.

## About the input file

The task text was taken from the PDF as plain text, so the indentation of `package.json` is not preserved. The file has the content as given, with no indentation and one trailing newline. Both are a reconstruction. Do not run whitespace fixers on `vulnerable-input/` or `reports/` (the pre-commit config already excludes both).
