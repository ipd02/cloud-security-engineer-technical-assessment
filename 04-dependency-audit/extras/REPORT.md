# Additional analysis

The assessment does not ask for any of this. The core answer is in [../REPORT.md](../REPORT.md). This file holds extra checks that support it.
Scan dates and tool versions are the same as in the main report. Paths such as `../reports/` are the main report's files. `reports/` is this folder's.

## 1. Cross-check with trivy

`trivy fs --scanners vuln --include-dev-deps` on the same lockfile. Full output: `../reports/trivy-before.json`, comparison in `reports/scanner-comparison.txt` (made by `compare_scanners.py`, matching on GHSA id).

- 45 trivy findings and 46 npm advisories. 45 advisories match by id.
- Severity matches on all 45. Trivy writes `MEDIUM` where npm writes `moderate`.
- One difference in advisories: `GHSA-h8hf-x3f4-xwgp` (mongoose, critical, "Prototype Pollution in Schema Object") is in npm audit only. Trivy lists other mongoose advisories but not this id.
- Difference in packages: npm lists 24 and trivy has findings on 21. The three extra (`mkdirp`, `mocha`, `mongodb-core`) are packages npm marks as vulnerable because their dependencies are, not because of an advisory of their own.
- By default trivy leaves out dev dependencies. Without `--include-dev-deps` the `mocha` chain is missing. I used the flag for every saved run.
- Trivy gives fixed versions per advisory. npm audit gives a fix per package instead.
- The trivy database version and update time were not recorded for the saved runs. Only the trivy version was. A re-run later can differ because of that.

After the fix both scanners report 0.

### When the two scanners disagree

Here they differ in four ways. Each one is a general pattern.

| Difference | What it was here | What to do in general |
|---|---|---|
| One tool reports an advisory, the other does not | `GHSA-h8hf-x3f4-xwgp` (mongoose, critical) is in npm only. Installed 4.13.21 is inside its range `<5.13.15`. I do not know why trivy lacks it. | Treat it as real until shown otherwise. Check the advisory page and its affected range against the installed version. Databases differ and update at different times. Record the decision. Here it is fixed anyway by the mongoose upgrade. |
| Different scope | Trivy skips dev dependencies by default. Without `--include-dev-deps` it reported 42 findings instead of 45 and missed the `mocha` chain. npm counts packages that are vulnerable only through a dependency. Trivy does not. | Run both with the same scope. Say which flags were used. |
| Different severity | None here. Severity matched on all 45. | Gate on the higher one. Keep both values in the report. Read the CVSS vector before downgrading. |
| Different fix advice | npm gives one target per package (`mongoose@9.11.2`, a new major). Trivy lists the patched version on each release line, for example `6.13.9, 7.8.9, 8.22.1, 9.1.6`. | Use trivy's list to find the smallest upgrade. For mongoose it shows patches on 6.x, 7.x and 8.x. Version 6.13.11 audits clean (section 3 below). Always confirm with a re-scan. |

Rule for a gate: fail if either tool reports an advisory at the chosen level. An advisory seen by only one tool can be accepted only with a written reason, an owner and an expiry date. `npm audit` has no ignore list. `trivy` does: a `.trivyignore` line `CVE-2019-10744 exp:2099-01-01` hid that finding, and the same line with a past date did not (tested on a scratch copy). `audit_report.py` has no ignore list.

## 2. EPSS scores

44 of the 46 advisories have an EPSS score (the two without a CVE have none). The scores are from 2026-10-14, one day after the scans, and change daily.

- All 44 are at or above 0.1%, so a `--min-epss 0.001` filter removes nothing here. 24 are at or above 1%, and 3 are at or above 10%: `mongoose` `GHSA-f825-f98c-gj3g` (33.5%), `lodash` `GHSA-35jh-r3h4-6jhm` (21.3%) and `qs` `GHSA-hrpp-h998-j3pp` (15.6%).
- EPSS ranks likelihood, not impact. A critical advisory with a low score still needs a fix. Use the score to order work inside a severity level, not to skip a fix.
- The score says nothing about whether the vulnerable code path is used by the application.

## 3. What breaks in the major upgrades (probe results)

I installed the old and new versions with `--ignore-scripts` into scratch directories (not into the repo) and ran `breaking-change-probe.js`. It makes no database or network calls. Outputs are in `reports/breaking-change-probe-*.txt` in this folder.

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

## 4. Forcing a transitive version with `overrides`

On a scratch copy of the task input I added `overrides` for `qs` 6.16.0 and `path-to-regexp` 0.1.13, with `express` still on 4.15.0. `npm audit` went from 24 vulnerable packages to 22, and neither `qs` nor `path-to-regexp` was flagged any more. Output: `reports/npm-audit-overrides-applied.txt`.

I did not test whether Express 4.15.0 still works with those versions. An override changes what the parent package runs against, so test the parent before relying on it.
