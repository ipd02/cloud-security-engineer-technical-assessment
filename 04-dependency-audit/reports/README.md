# Saved reports

These files are evidence. Every number and advisory id in [../README.md](../README.md) and [../REPORT.md](../REPORT.md) comes from them. The raw scanner files are long. You do not need to read them to review the part.

If you want to look at one file, open [`before/high-critical.csv`](before/high-critical.csv). It lists the 25 high and critical advisories, plus the packages that are vulnerable through them, and opens in a spreadsheet.

## Folders

| Folder | What it holds |
|---|---|
| `before/` | The scan of the task input (`../vulnerable-input/`). |
| `after/` | The scan of the proposed fix (`../fixed/`). It shows 0 findings. |
| `fix-experiments/` | Runs of `npm audit fix` on scratch copies of the input: as is, with `--force`, and with caret ranges on the two exact pins. They back the "how many can be fixed" answer. |

## Files in `before/` and `after/`

| File | What it is | Made by |
|---|---|---|
| `npm-audit.json`, `npm-audit.txt` | Raw output of `npm audit --json` and `npm audit`. | `npm audit` |
| `npm-audit.meta.txt` | Date, npm and Node versions, and the command. | by hand, at scan time |
| `trivy.json`, `trivy.txt` | Raw output of `trivy fs`, with dev dependencies included. | `make dep-audit-trivy` |
| `trivy.meta.txt` | Date, command, trivy version and the vulnerability database version and update time. | `make dep-audit-trivy` |
| `vulnerabilities.json`, `vulnerabilities.csv` | Every finding, one row per package and advisory, from `audit_report.py`. | `make dep-audit-report` |
| `summary.txt` | The counts that `audit_report.py` printed. | `make dep-audit-report` |

Only in `before/`:

| File | What it is |
|---|---|
| `high-critical.csv`, `high-critical.json` | The same report, limited to high and critical. |
| `epss.json`, `epss.meta.txt` | The FIRST EPSS response used for the `epss` columns, with its date. |

## Why they are saved

- The advisory databases change daily. The saved files fix the numbers to the scan dates.
- Each file can be rebuilt. `make dep-audit-report` rebuilds the `audit_report.py` output from the raw `npm-audit.json` and `trivy.json`. `make dep-audit-trivy` reruns trivy and records its database version.
- The `.meta.txt` files record which tool versions made the numbers.

Do not run whitespace fixers on this folder. The pre-commit config skips it.
