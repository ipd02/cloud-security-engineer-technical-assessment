# Dependency audit report

Input: the `package.json` from the assessment, in `vulnerable-input/`. The content is as given. The task text lost its indentation, so the whitespace is reconstructed (no indentation, one trailing newline).
All numbers and ids below come from the files in `reports/`. Scan date: 2026-10-13, npm 11.19.1, Node v26.10.0, trivy 0.75.0.
The advisory databases change daily, so a re-run later will give different numbers.

## 1. Result in one table

| | Before (`vulnerable-input/`) | After (`fixed/`) |
|---|---|---|
| Packages audited (`metadata.dependencies.total` in `npm audit --json`) | 149 | 128 |
| Vulnerable packages, `npm audit` | 24 | 0 |
| Critical / high / moderate / low (packages) | 10 / 8 / 3 / 3 | 0 / 0 / 0 / 0 |
| Advisories, `npm audit` | 46 | 0 |
| Critical / high / moderate / low (advisories) | 7 / 18 / 15 / 6 | 0 / 0 / 0 / 0 |
| `trivy fs` findings (all severities, dev deps included) | 45 | 0 |

Sources: `reports/npm-audit-before.txt`, `npm-audit-before.json`, `npm-audit-after.txt`, `npm-audit-after.json`, `trivy-before.json`, `trivy-after.txt`, and the summaries `audit_report-before-summary.txt` and `audit_report-after-summary.txt`.

How npm counts: a package is "vulnerable" if it has an advisory or depends on a vulnerable package, and its severity is the highest of its advisories. So 24 packages carry 46 advisories. Three of the 24 (`mkdirp`, `mocha`, `mongodb-core`) are listed only because they depend on something vulnerable.

Direct dependencies that are vulnerable: `express`, `lodash`, `jsonwebtoken`, `mongoose` and `mocha` (dev only). `body-parser` and `dotenv` are not flagged. The other 19 vulnerable packages are transitive.

## 2. High and critical findings

25 advisories (7 critical, 18 high), one row each, generated from `reports/vulnerabilities-before.json` by `audit_report.py`.
"Fixed in" is the patched version of that package as trivy lists it. "Upgrade that fixes it" is what npm audit proposes for the direct dependency that owns the package.
The vulnerability class is the advisory title. CVE ids come from trivy through the GHSA id. Two advisories have no CVE. `GHSA-mh5c-679w-hh4r` (mongodb) is in trivy under its GHSA id and has no CVE. `GHSA-h8hf-x3f4-xwgp` (mongoose) is not in trivy at all, so it has no CVE and no trivy fixed version.
EPSS is the FIRST.org estimate that a vulnerability is exploited in the next 30 days. It comes from `reports/epss-before.json`, dated 2026-10-14, and needs a CVE id. The two advisories above have none, so they show `n/a`.

| Sev | Package | Installed | Type | Advisory / CVE | EPSS | Class | Fixed in (trivy) | Upgrade that fixes it |
|---|---|---|---|---|---|---|---|---|
| critical | bson | 1.0.9 | transitive | GHSA-v8w9-2789-6hhr<br>CVE-2020-7610 | 2.3% | Deserialization of Untrusted Data in bson | 1.1.4 | `mongoose@9.11.2` **major** |
| critical | lodash | 4.17.10 | direct | GHSA-jf85-cpcp-j695<br>CVE-2019-10744 | 5.0% | Prototype Pollution in lodash | 4.17.12 | `lodash@4.18.1` same major |
| critical | minimist | 0.0.8 | transitive | GHSA-xvch-5gv4-984h<br>CVE-2021-44906 | 4.6% | Prototype Pollution in minimist | 1.2.6, 0.2.4 | `mocha@12.0.3` **major** |
| critical | mongoose | 4.13.21 | direct | GHSA-9m93-w8w6-76hh<br>CVE-2023-3696 | 1.2% | Mongoose Prototype Pollution vulnerability | 7.3.3, 6.11.3, 5.13.20 | `mongoose@9.11.2` **major** |
| critical | mongoose | 4.13.21 | direct | GHSA-h8hf-x3f4-xwgp<br>no CVE listed | n/a | Mongoose Vulnerable to Prototype Pollution in Schema Object | not listed by trivy | `mongoose@9.11.2` **major** |
| critical | mongoose | 4.13.21 | direct | GHSA-vg7j-7cwx-8wgw<br>CVE-2025-23061 | 7.3% | Mongoose search injection vulnerability | 8.9.5, 7.8.4, 6.13.6 | `mongoose@9.11.2` **major** |
| critical | proxy-addr | 1.1.5 | transitive | GHSA-jqcg-44mw-7w3h<br>CVE-2026-90711 | 0.3% | proxy-addr vulnerable to IP spoofing via IPv4-mapped IPv6 trust subnet | 2.0.8 | `express@4.22.3` same major |
| high | async | 2.6.0 | transitive | GHSA-fwr7-v2mv-hh25<br>CVE-2021-43138 | 3.3% | Prototype Pollution in async | 3.2.2, 2.6.4 | `mongoose@9.11.2` **major** |
| high | debug | 2.6.1 | transitive | GHSA-9vvw-cc9w-f27h<br>CVE-2017-20165 | 2.0% | debug Inefficient Regular Expression Complexity vulnerability | 3.1.0, 2.6.9 | `express@4.22.3` same major |
| high | fresh | 0.5.0 | transitive | GHSA-9qj9-36jm-prpv<br>CVE-2017-16119 | 1.6% | Regular Expression Denial of Service in fresh | 0.5.2 | `express@4.22.3` same major |
| high | jsonwebtoken | 8.1.0 | direct | GHSA-8cf7-32gw-wr33<br>CVE-2022-23539 | 0.5% | jsonwebtoken unrestricted key type could lead to legacy keys usage | 9.0.0 | `jsonwebtoken@9.0.3` **major** |
| high | lodash | 4.17.10 | direct | GHSA-35jh-r3h4-6jhm<br>CVE-2021-23337 | 21.3% | Command Injection in lodash | 4.17.21 | `lodash@4.18.1` same major |
| high | lodash | 4.17.10 | direct | GHSA-4xc9-xhrj-v574<br>CVE-2018-16487 | 1.6% | Prototype Pollution in lodash | >=4.17.11 | `lodash@4.18.1` same major |
| high | lodash | 4.17.10 | direct | GHSA-p6mc-m468-83gw<br>CVE-2020-8203 | 5.2% | Prototype Pollution in lodash | 4.17.19 | `lodash@4.18.1` same major |
| high | lodash | 4.17.10 | direct | GHSA-r5fr-rjxr-66jc<br>CVE-2026-4800 | 2.6% | lodash vulnerable to Code Injection via `_.template` imports key names | 4.18.0 | `lodash@4.18.1` same major |
| high | mime | 1.3.4 | transitive | GHSA-wrvr-8mpx-r7pp<br>CVE-2017-16138 | 2.1% | mime Regular Expression Denial of Service when MIME lookup performed on untrusted user input | 2.0.3, 1.4.1 | `express@4.22.3` same major |
| high | mongodb | 2.2.34 | transitive | GHSA-mh5c-679w-hh4r<br>no CVE listed | n/a | Denial of Service in mongodb | 3.1.13 | `mongoose@9.11.2` **major** |
| high | mongoose | 4.13.21 | direct | GHSA-f825-f98c-gj3g<br>CVE-2022-2564 | 33.5% | automattic/mongoose vulnerable to Prototype pollution via Schema.path | 6.4.6, 5.13.15 | `mongoose@9.11.2` **major** |
| high | mongoose | 4.13.21 | direct | GHSA-m7xq-9374-9rvx<br>CVE-2024-53900 | 4.0% | Mongoose search injection vulnerability | 8.8.3, 7.8.3, 6.13.5, 5.13.23 | `mongoose@9.11.2` **major** |
| high | mongoose | 4.13.21 | direct | GHSA-wpg9-53fq-2r8h<br>CVE-2026-42334 | 0.5% | Mongoose's Improper Sanitization of $nor in sanitizeFilter May Allow NoSQL Injection | 6.13.9, 7.8.9, 8.22.1, 9.1.6 | `mongoose@9.11.2` **major** |
| high | path-to-regexp | 0.1.7 | transitive | GHSA-37ch-88jc-xwx2<br>CVE-2026-4867 | 0.6% | path-to-regexp vulnerable to Regular Expression Denial of Service via multiple route parameters | 0.1.13 | `express@4.22.3` same major |
| high | path-to-regexp | 0.1.7 | transitive | GHSA-9wv6-86v2-598j<br>CVE-2024-45296 | 0.9% | path-to-regexp outputs backtracking regular expressions | 1.9.0, 0.1.10, 8.0.0, 3.3.0, 6.3.0 | `express@4.22.3` same major |
| high | path-to-regexp | 0.1.7 | transitive | GHSA-rhx6-c78j-4q9w<br>CVE-2024-52798 | 0.8% | path-to-regexp contains a ReDoS | 0.1.12 | `express@4.22.3` same major |
| high | qs | 6.3.1 | transitive | GHSA-gqgv-6jq5-jjj9<br>CVE-2017-1000048 | 2.4% | Prototype Pollution Protection Bypass in qs | 6.0.4, 6.1.2, 6.2.3, 6.3.2 | `express@4.22.3` same major |
| high | qs | 6.3.1 | transitive | GHSA-hrpp-h998-j3pp<br>CVE-2022-24999 | 15.6% | qs vulnerable to Prototype Pollution | 6.10.3, 6.9.7, 6.8.3, 6.7.3, 6.6.1, 6.5.3, 6.4.1, 6.3.3, 6.2.4 | `express@4.22.3` same major |

Other severities (15 moderate and 6 low advisories) are in `reports/vulnerabilities-before.csv`.

### EPSS

44 of the 46 advisories have an EPSS score (the two without a CVE have none). The scores are from 2026-10-14, one day after the scans, and change daily.

- All 44 are at or above 0.1%, so a `--min-epss 0.001` filter removes nothing here. 24 are at or above 1%, and 3 are at or above 10%: `mongoose` `GHSA-f825-f98c-gj3g` (33.5%), `lodash` `GHSA-35jh-r3h4-6jhm` (21.3%) and `qs` `GHSA-hrpp-h998-j3pp` (15.6%).
- EPSS ranks likelihood, not impact. A critical advisory with a low score still needs a fix. Use the score to order work inside a severity level, not to skip a fix.
- The score says nothing about whether the vulnerable code path is used by the application.

## 3. How many can be fixed

| Method | Packages fixed (of 24) | Evidence |
|---|---|---|
| `npm audit fix` | 0 | `reports/npm-audit-fix-applied.txt`: package.json and lockfile unchanged, still 24 |
| `npm audit fix` after changing only the `express` and `lodash` pins to caret ranges | 12 | `reports/npm-audit-fix-carets-applied.txt`: 12 vulnerabilities remain (1 low, 2 moderate, 2 high, 7 critical) |
| `npm audit fix --force` | 24 | `reports/npm-audit-fix-force-applied.txt`: "found 0 vulnerabilities" |
| Manual edit of `package.json` (`fixed/`) | 24 | `reports/npm-audit-after.txt` |

Why plain `npm audit fix` does nothing: every fix needs a version outside the range in `package.json`, and `npm audit fix` only stays inside the range. For 12 packages the range is the problem: `express` (`4.15.0`) and `lodash` (`4.17.10`) are exact pins. For the other 12 the fix is a new major of `mongoose`, `jsonwebtoken` or `mocha`, which no caret range on the old major can reach. Changing the two pins to carets would let plain `npm audit fix` clear 12 packages and leave 12, 7 of them critical (see the carets row above).

By type of change, from `fixAvailable` in `npm-audit-before.json`:

- 12 packages are fixed by a bump inside the same major line: `express` (4.15.0 to 4.22.3) fixes 11 packages (express, cookie, debug, fresh, mime, ms, path-to-regexp, proxy-addr, qs, send, serve-static), and `lodash` (4.17.10 to 4.18.1) fixes itself. Both need the exact pin changed.
- 12 packages need a semver-major bump of a direct dependency: `mongoose` 4 to 9 fixes 7 (mongoose, bson, mongodb, mongodb-core, async, mpath, mquery), `jsonwebtoken` 8 to 9 fixes 1, and `mocha` 5 to 12 fixes 4 (mocha, minimist, mkdirp, diff).
- 0 packages have no fix.

`--force` and the manual edit in `fixed/package.json` reach the same versions. The manual edit keeps `express` and `lodash` pinned exactly, as in the original, and raises the floor of `body-parser` and `dotenv` to the versions that were already resolved.

## 4. Fixed manifest

`fixed/package.json`:

| Package | Before | After | Change |
|---|---|---|---|
| express | 4.15.0 | 4.22.3 | same major, exact pin kept |
| lodash | 4.17.10 | 4.18.1 | same major, exact pin kept |
| jsonwebtoken | 8.1.0 | ^9.0.3 | major |
| mongoose | ^4.2.4 | ^9.11.2 | major (five majors) |
| mocha (dev) | 5.0.5 | ^12.0.3 | major |
| body-parser | ^1.19.0 | ^1.20.8 | floor raised, the lockfile already resolved 1.20.8 |
| dotenv | ^8.2.0 | ^8.6.0 | floor raised, no advisory, no major jump |

The lockfile was generated with `npm install --package-lock-only --ignore-scripts`. `npm audit` on it reports `found 0 vulnerabilities`, and `trivy fs --include-dev-deps` reports 0. The resolved versions are `express` 4.22.3, `lodash` 4.18.1, `jsonwebtoken` 9.0.3, `mongoose` 9.11.2, `mocha` 12.0.3, `mongodb` 7.7.0, `qs` 6.16.0 and `path-to-regexp` 0.1.13.

`fixed/package.json` also sets `"private": true` and `"engines": {"node": ">=20.19.0"}`, to match the Node floor in section 5. Only the root entry of the lockfile changed. `npm audit` still reports 0.

I stayed on the Express 4 line (`latest-4` is 4.22.3). Express 5 is not needed to clear any advisory.

## 5. What cannot be fully fixed, and what is not proven

1. **No application code was provided.** The task gives only `package.json`. A clean audit proves the dependency tree has no known advisory. It does not prove the app still runs after three major upgrades. I checked what changes by calling the APIs directly (section 6), not by running the app.
2. **A clean audit means no known advisory on the run date.** `npm audit` and trivy match versions against advisory databases. They do not check whether the vulnerable code path is reachable, and they do not see unreported bugs.
3. **Node version.** `mongoose` 9.11.2 requires Node `>=20.19.0` and `mocha` 12.0.3 requires `^20.19.0 || >=22.12.0` (both from `npm view ... engines.node`). The app cannot stay on an older runtime.
4. **`dotenv` 8.6.0 is current for the 8.x line only.** It has no advisory, so I did not force the jump to 18.x, which would be a change without a security reason. Review it separately.
5. **Dev dependency findings** (`mocha`, `minimist`, `mkdirp`, `diff`) do not ship in a production install. They still matter on a build machine or CI runner.

Every one of the 24 packages can be fixed by an upgrade. The upgrades need the code changes in section 6.

## 6. What breaks in the major upgrades

I installed the old and new versions with `--ignore-scripts` into scratch directories (not into the repo) and ran `fixed/breaking-change-probe.js`. It makes no database or network calls. Outputs are in `reports/breaking-change-probe-*.txt`.

**mongoose 4.13.21 to 9.11.2** (`breaking-change-probe-vulnerable.txt` against `breaking-change-probe-fixed.txt`)

- Callbacks are gone. `Model.find(cond, cb)` and `Model.findOne(cond, cb)` throw `MongooseError: ... no longer accepts a callback`. `doc.save(cb)` rejects with the same kind of error. All callback style code must move to `await` or `.then`.
- `Model.count()`, `Model.update()` and `Model.remove()` no longer exist (`TypeError: ... is not a function`). Replacements that exist in 9.11.2: `countDocuments()`, `updateOne()` / `updateMany()`, `deleteOne()` / `deleteMany()`.
- Not tested here: connection options, schema and middleware behaviour, population, and query casting. These need the real app and a database.
- A smaller step exists. `mongoose` 6.13.11 also gives `found 0 vulnerabilities` in my test (lockfile only, with the other fixed dependencies). On 6.13.11 the same calls do not throw and `doc.save(cb)` is not rejected (`breaking-change-probe-mongoose-6.13.11.txt`). With no database this only shows the API is still accepted. No query ran. On 7.8.12 the audit is also clean, but callbacks and `update`/`remove` are already gone (`breaking-change-probe-mongoose-7.8.12.txt`). Version 8.24.5 also audits clean. The 6.x route may be a smaller first step if the app is callback based, with a second step to 9 later. It still crosses two majors (4 to 6), and I did not test what changes between 4 and 6. `npm view mongoose time` shows 6.13.11 was published on 2026-08-10, so the 6.x line still gets patches. I did not check its official support status.

**jsonwebtoken 8.1.0 to 9.0.3** (`breaking-change-probe-vulnerable.txt`, `breaking-change-probe-fixed.txt`)

- Signing with an RSA key under 2048 bits now throws (`secretOrPrivateKey has a minimum key size of 2048 bits for RS256`). On 8.1.0 the same call succeeded. Any service that signs with a 1024-bit key breaks until the key is replaced.
- Signing with a key of the wrong type now throws. On 8.1.0 an EC key signed with `RS256` succeeded. On 9.0.3 it throws `"alg" parameter for "ec" key type must be one of: ES256, ES384, ES512`. This key type check is what the high advisory `GHSA-8cf7-32gw-wr33` is about. Both new checks have an opt-out in 9.0.3 (`allowInsecureKeySizes` and `allowInvalidAsymmetricKeyTypes`). With `allowInsecureKeySizes: true` the 1024-bit key signs again. 8.1.0 rejects that option, so do not add it before the upgrade. Use the options only as a short bridge.
- The other cases I probed behave the same on both versions: HS256 sign and verify, a token with `alg: none`, an HS256 token verified against an RSA public key, an empty secret, and bad `expiresIn` values. This does not cover every change in 9.0.0. Review the project release notes against your usage (algorithms lists, `verify` options).

**mocha 5.0.5 to 12.0.3**

- Needs Node `^20.19.0 || >=22.12.0`. A trivial `describe` / `it` test ran on 12.0.3 with Node v26.10.0 (`reports/mocha-smoke.txt`). Test config files, reporters and flags used by the real project were not tested.

**express 4.15.0 to 4.22.3, lodash 4.17.10 to 4.18.1, body-parser, dotenv**

- Same major line. I did not probe these. `express` brings newer `qs` and `path-to-regexp` (6.16.0 and 0.1.13 in the fixed lockfile), so routes with unusual patterns and query strings with deep nesting or large arrays need a test.

## 7. Recommended plan

1. Raise the Node runtime to a supported version (20.19 or 22.12 and later) in CI and in the deploy image.
2. Change `express` and `lodash` pins. Run the existing tests. This clears 12 packages, including the critical `proxy-addr` and the critical and high `lodash` advisories. They stay on the same major line. This report did not probe them (section 6), so run the existing tests.
3. Upgrade `jsonwebtoken` to 9.0.3. Check key sizes first (RSA at least 2048 bits). Re-issue tokens signed with weaker keys.
4. Upgrade `mongoose`. Either go straight to 9.11.2 and rewrite callbacks and removed methods, or go to 6.13.11 first. This is the largest change and clears 7 packages.
5. Upgrade `mocha` (dev only). Last, because it does not reach production.
6. Add `npm audit --audit-level=high` (or `audit_report.py --fail-on high`) to CI and enable dependency update automation, so the pins do not go stale again.
7. Replace exact pins with caret ranges for `express` and `lodash` if the team accepts lockfile-controlled updates. This lets plain `npm audit fix` clear 12 packages next time. The other 12 need a major bump of a direct dependency.
8. Use EPSS (section 2) to order work inside a severity level. The three advisories at 10% or more come first: `mongoose` `GHSA-f825-f98c-gj3g`, `lodash` `GHSA-35jh-r3h4-6jhm` and `qs` `GHSA-hrpp-h998-j3pp`. Do not use it to skip a fix.

## 8. Cross-check with trivy

`trivy fs --scanners vuln --include-dev-deps` on the same lockfile. Full output: `reports/trivy-before.json`, comparison in `reports/scanner-comparison.txt` (made by `compare_scanners.py`, matching on GHSA id).

- 45 trivy findings and 46 npm advisories. 45 advisories match by id.
- Severity matches on all 45. Trivy writes `MEDIUM` where npm writes `moderate`.
- One difference in advisories: `GHSA-h8hf-x3f4-xwgp` (mongoose, critical, "Prototype Pollution in Schema Object") is in npm audit only. Trivy lists other mongoose advisories but not this id.
- Difference in packages: npm lists 24 and trivy has findings on 21. The three extra (`mkdirp`, `mocha`, `mongodb-core`) are packages npm marks as vulnerable because their dependencies are, not because of an advisory of their own.
- By default trivy leaves out dev dependencies. Without `--include-dev-deps` the `mocha` chain is missing. I used the flag for every saved run.
- Trivy gives fixed versions per advisory. npm audit gives a fix per package instead.
- The trivy database version and update time were not recorded for the saved runs. Only the trivy version was. A re-run later can differ because of that.

After the fix both scanners report 0.

## 9. Files

| File | What it is |
|---|---|
| `vulnerable-input/package.json` | The task input, whitespace reconstructed |
| `vulnerable-input/package-lock.json` | Generated, `--package-lock-only --ignore-scripts` |
| `fixed/package.json`, `fixed/package-lock.json` | Proposed fix and its lockfile |
| `reports/npm-audit-*.txt`, `*.json`, `*.meta.txt` | Raw `npm audit` and `npm audit --json`, with date, npm and node versions |
| `reports/trivy-*.json`, `*.txt`, `*.meta.txt` | Raw trivy output |
| `reports/npm-audit-fix-applied.txt`, `npm-audit-fix-force-applied.txt`, `npm-audit-fix-carets-applied.txt` | `npm audit fix` runs on scratch copies |
| `reports/epss-before.json`, `epss-before.meta.txt` | Raw FIRST EPSS response for the CVE ids, with date |
| `reports/mocha-smoke.txt` | One trivial mocha test on 12.0.3 |
| `reports/vulnerabilities-before.*`, `vulnerabilities-after.*` | Output of `audit_report.py` (JSON and CSV), with a `meta` block in the JSON |
| `reports/breaking-change-probe-*.txt` | Output of `fixed/breaking-change-probe.js` |
| `reports/scanner-comparison.txt` | npm audit against trivy |
