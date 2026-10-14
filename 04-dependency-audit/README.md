# Part 4: third-party dependency audit

The task gives a `package.json` with six dependencies and one dev dependency. This part scans it, lists the vulnerabilities, says how to fix them and how many can be fixed, and adds a script that turns the scan into JSON and CSV.

The sections below follow the order of the task. [REPORT.md](REPORT.md) has the full tables.

## 1. What we found, and with which tools

The input has **24 vulnerable packages with 46 advisories**.

| | Critical | High | Moderate | Low | Total |
|---|---|---|---|---|---|
| Packages | 10 | 8 | 3 | 3 | 24 |
| Advisories | 7 | 18 | 15 | 6 | 46 |

After the proposed upgrades both scanners report 0.

| Tool | Use | Why |
|---|---|---|
| `npm audit` | Main scan | Ships with npm and needs no account. It gives a fix for each package and says whether the fix is a major version bump. |
| `trivy fs` | Second scan | An independent database. It adds CVE ids and the fixed version for each advisory. |
| `yarn audit` | Not used | The project has no yarn lockfile. |
| `snyk test` | Not used | Needs an account and a token. |
| OWASP Dependency-Check | Not used | A Java tool with a large vulnerability feed, too heavy for one manifest. |

`npm audit` needs a lockfile, so one was generated with `npm install --package-lock-only --ignore-scripts`. The packages were never installed and no install script ran. `npm audit` ran on 2026-10-13 and trivy on 2026-10-14. The counts were the same on both days. Advisory databases change daily, so a later run can differ.

## 2. Detected vulnerabilities (high and critical)

25 advisories: 7 critical and 18 high, in 12 packages.

| Package | Installed | Critical | High | Types |
|---|---|---|---|---|
| mongoose (direct) | 4.13.21 | 3 | 3 | Prototype pollution, NoSQL search injection |
| lodash (direct) | 4.17.10 | 1 | 4 | Prototype pollution, command and code injection |
| bson | 1.0.9 | 1 | 0 | Deserialization of untrusted data |
| minimist | 0.0.8 | 1 | 0 | Prototype pollution |
| proxy-addr | 1.1.5 | 1 | 0 | IP spoofing through IPv4-mapped IPv6 addresses |
| path-to-regexp | 0.1.7 | 0 | 3 | Regular expression denial of service |
| qs | 6.3.1 | 0 | 2 | Prototype pollution |
| jsonwebtoken (direct) | 8.1.0 | 0 | 1 | Unrestricted key type allows legacy keys |
| async | 2.6.0 | 0 | 1 | Prototype pollution |
| debug, fresh, mime | 2.6.1, 0.5.0, 1.3.4 | 0 | 3 | Regular expression denial of service |
| mongodb | 2.2.34 | 0 | 1 | Denial of service |

One row for every advisory, with the advisory id, CVE, fixed-in version and the upgrade that fixes it, is in [REPORT.md, section 2](REPORT.md#2-high-and-critical-findings). The same data as a spreadsheet is in [`reports/before/high-critical.csv`](reports/before/high-critical.csv).

## 3. Which dependencies are vulnerable

5 of the 7 declared dependencies are vulnerable, and 19 more packages come in through them.

| Direct dependency | Advisories it brings in | Packages affected |
|---|---|---|
| express | 18 | 11: express, cookie, debug, fresh, mime, ms, path-to-regexp, proxy-addr, qs, send, serve-static |
| mongoose | 13 | 7: mongoose, bson, mongodb, mongodb-core, async, mpath, mquery |
| lodash | 9 | 1 |
| jsonwebtoken | 3 | 1 |
| mocha (dev only) | 3 | 4: mocha, minimist, mkdirp, diff |

`body-parser` and `dotenv` are not flagged.

## 4. How to fix

Upgrade the five direct dependencies. This clears all 46 advisories.

| Package | Now | Upgrade to | Kind | Advisories cleared | What to expect in the code |
|---|---|---|---|---|---|
| express | 4.15.0 | 4.22.3 | Same major | 18 | Test routes with unusual patterns and deeply nested query strings. |
| lodash | 4.17.10 | 4.18.1 | Same major | 9 | None expected. |
| jsonwebtoken | 8.1.0 | ^9.0.3 | Major | 3 | RSA keys under 2048 bits and keys of the wrong type are now rejected. |
| mongoose | ^4.2.4 | ^9.11.2 | Major | 13 | Callbacks, `count`, `update` and `remove` are removed. Needs Node 20.19 or later. |
| mocha (dev) | 5.0.5 | ^12.0.3 | Major | 3 | Needs Node 20.19 or later. |

`body-parser` and `dotenv` only get a higher minimum version, because they have no advisory.

The task suggests "upgrade lodash to 4.17.21". We use 4.18.1, because one of the five lodash advisories is only fixed from 4.18.0.

The proposed manifest is [`fixed/package.json`](fixed/package.json) with its lockfile. `npm audit` and `trivy` report 0 on it.

Suggested order: raise the Node runtime, change the `express` and `lodash` pins, upgrade `jsonwebtoken` after checking key sizes, upgrade `mongoose` (the largest change), then `mocha`. Add `npm audit --audit-level=high` to CI.

If an upgrade is not possible, or it breaks the code, [REPORT.md, section 9](REPORT.md#9-when-the-upgrade-is-not-possible-or-breaks-things) covers the options: a patched release of the old line, `overrides` for a transitive package, replacing the package, and accepting a risk with controls and an expiry date.

## 5. How many issues can be fixed

All of them: 24 of 24 packages and 46 of 46 advisories can be fixed by an upgrade.

| Method | Packages fixed |
|---|---|
| `npm audit fix` | 0 |
| `npm audit fix --force` | 24 |
| Edit `package.json` by hand (`fixed/`) | 24 |

12 packages need a bump inside the same major version (`express`, `lodash`). 12 need a new major version (`mongoose`, `jsonwebtoken`, `mocha`). None is left without a fix.

`npm audit fix` fixes nothing because it never leaves the range in `package.json`. `express` and `lodash` are pinned to exact versions, and the other three need a new major. With caret ranges on the two pins it would fix 12 and leave 12 (7 critical). The run is in [`reports/fix-experiments/`](reports/fix-experiments/npm-audit-fix-carets.txt).

## 6. The script (bonus)

`audit_report.py` reads `npm audit --json` and writes a JSON and a CSV report. It uses only the Python standard library.

```sh
cd 04-dependency-audit/vulnerable-input
npm install --package-lock-only --ignore-scripts      # never a normal npm install here
npm audit --json > /tmp/audit.json
python3 ../audit_report.py /tmp/audit.json --lockfile package-lock.json \
  --json-out /tmp/v.json --csv-out /tmp/v.csv --min-severity high --fail-on critical
```

What it does:

- Reads the npm 7 and later format, and the npm 6 format. `-` reads stdin.
- Writes one row per package and advisory, plus one row for each package that is vulnerable only through a dependency. Columns: package, severity, direct or not, installed versions, advisory id, CVE, CWE, CVSS score, EPSS score, affected range, fix package and version, and whether the fix is a major bump. The JSON also has a `meta` block and a summary.
- Prints counts by severity and how many packages are fixable with and without a major bump.
- `--lockfile` adds the installed versions. `--trivy` adds CVE ids. `--epss` or `--epss-fetch` adds EPSS scores, and `--min-epss` drops advisories with a known low score.
- `--min-severity` filters the output. `--fail-on LEVEL` exits 1 if a finding at that level or above remains. Exit 2 means unreadable or malformed input or a write error.
- An unknown severity label never lowers a finding: it falls back to the package severity, then to `critical`, with a warning.
- CSV cells that start with `=`, `+`, `-` or `@` get a leading `'`, so a spreadsheet does not read them as formulas.

Make targets, from the repository root:

```sh
make dep-audit-test     # unit tests
make dep-audit-lint     # ruff
make dep-audit-scan     # trivy: fixed/ is clean, vulnerable-input/ still has findings
make dep-audit-report   # rebuild the report files in reports/ from the saved scans
make dep-audit-trivy    # rerun trivy and save its output with the database version
```

How it was checked: 80 unit tests, including real `npm audit --json` output from npm 6 and npm 11 for a `package.json` written for this tool (`tests/fixtures/custom-app/`), and single-line changes to the code that each fail a test. CI runs lint, the tests and the scan.

## 7. Extras

Work beyond the task is in [`extras/`](extras/README.md), so it does not get in the way of the answer above:

- a comparison of `npm audit` and `trivy`, and what to do when they disagree
- EPSS exploit scores
- calls to the changed APIs of `jsonwebtoken` and `mongoose` in the old and new versions
- a version of the script that skips risks you have already accepted, for scheduled scans

## 8. Files

| Path | What it is |
|---|---|
| `vulnerable-input/` | The task `package.json` and its generated lockfile. |
| `fixed/` | The proposed `package.json` and its lockfile. |
| `audit_report.py`, `tests/` | The script and its tests. |
| `reports/` | Saved scan output and the script output, grouped as before, after and fix experiments. These are evidence. You do not need to read them. [reports/README.md](reports/README.md) says what each file is for. |
| `extras/` | Work beyond the task. |
| `part.mk` | Make targets, picked up by the root `Makefile`. |

Notes:

- GitHub dependency alerts on `vulnerable-input/` and `tests/fixtures/custom-app/` are expected, because they are test inputs. They are left out of `dependabot.yml`, which stops version update PRs. Keep Dependabot security updates off for them, or dismiss the alerts.
- The task text lost the indentation of `package.json`. The file has the content as given, with no indentation and one trailing newline. Do not run whitespace fixers on `vulnerable-input/` or `reports/`. The pre-commit config skips both.
