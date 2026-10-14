#!/usr/bin/env python3
"""Turn `npm audit --json` output into a flat JSON and CSV report.

Reads the v7+ format (top-level "vulnerabilities") and, as a fallback, the
npm 6 format (top-level "advisories"). Standard library only.

Exit codes: 0 ok, 1 findings at or above --fail-on, 2 unreadable or malformed input,
or a failed EPSS lookup.
"""

from __future__ import annotations

import argparse
import csv
import json
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
from datetime import UTC, datetime
from pathlib import Path

SEVERITIES = ("info", "low", "moderate", "high", "critical")
RANK = {name: index for index, name in enumerate(SEVERITIES)}
GHSA_RE = re.compile(r"GHSA(?:-[0-9a-z]{4}){3}")
EPSS_API = "https://api.first.org/data/v1/epss"
EPSS_BATCH = 50
CSV_FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")

CSV_FIELDS = (
    "package",
    "severity",
    "kind",
    "direct",
    "installed_versions",
    "advisory_id",
    "source_id",
    "cve",
    "title",
    "cwe",
    "cvss_score",
    "epss",
    "epss_percentile",
    "vulnerable_range",
    "via",
    "fix_available",
    "fix_package",
    "fix_version",
    "fix_semver_major",
    "url",
)


def normalise_severity(value: object) -> str:
    """Map a raw severity string to one of SEVERITIES. Empty or unknown values give ''."""
    text = str(value or "").strip().lower()
    if text == "medium":
        text = "moderate"
    return text if text in RANK else ""


def resolve_severity(*candidates: object, warnings: list[str] | None = None) -> str:
    """Pick the first known severity from the candidates, most specific first.

    Unknown values never lower a finding. If no candidate is known but one was
    present, the result is 'critical' so a --fail-on gate cannot be passed by a
    severity label this script does not know. If nothing was given, it is 'info'.
    """
    unknown = []
    for candidate in candidates:
        known = normalise_severity(candidate)
        if known:
            return known
        if str(candidate or "").strip():
            unknown.append(str(candidate))
            if warnings is not None:
                warnings.append(f"unknown severity {str(candidate)!r}")
    return "critical" if unknown else "info"


def load_json(path: str) -> object:
    """Load JSON from a file path, or from stdin when path is '-'."""
    if path == "-":
        return json.load(sys.stdin)
    with open(path, encoding="utf-8") as handle:
        return json.load(handle)


def installed_versions(nodes: list, lock: dict) -> list[str]:
    """Look up installed versions for node paths in a lockfile v2/v3 'packages' map."""
    packages = lock.get("packages") if isinstance(lock, dict) else None
    if not isinstance(packages, dict):
        return []
    found = []
    for node in nodes or []:
        version = (packages.get(node) or {}).get("version")
        if version and version not in found:
            found.append(version)
    return found


def ghsa_from_url(url: object) -> str:
    match = GHSA_RE.search(str(url or ""))
    return match.group(0) if match else ""


def parse_fix(fix: object) -> dict:
    """Normalise npm's fixAvailable, which is a bool or an object."""
    if isinstance(fix, dict):
        return {
            "fix_available": True,
            "fix_package": fix.get("name", ""),
            "fix_version": fix.get("version", ""),
            "fix_semver_major": bool(fix.get("isSemVerMajor", False)),
        }
    return {
        "fix_available": bool(fix),
        "fix_package": "",
        "fix_version": "",
        "fix_semver_major": False,
    }


def empty_row() -> dict:
    return {field: "" for field in CSV_FIELDS}


def rows_from_v7(
    report: dict, lock: dict, cve_map: dict, warnings: list[str] | None = None
) -> list[dict]:
    """One row per advisory, plus one row per package that is vulnerable through a dependency."""
    rows = []
    vulns = report.get("vulnerabilities") or {}
    for name in sorted(vulns):
        entry = vulns[name] or {}
        common = parse_fix(entry.get("fixAvailable"))
        common["package"] = entry.get("name") or name
        common["direct"] = bool(entry.get("isDirect", False))
        common["installed_versions"] = installed_versions(entry.get("nodes"), lock)
        common["vulnerable_range"] = entry.get("range") or ""
        advisories = [v for v in (entry.get("via") or []) if isinstance(v, dict)]
        via_names = [v for v in (entry.get("via") or []) if isinstance(v, str)]
        seen = set()
        for adv in advisories:
            key = adv.get("source") or adv.get("url") or adv.get("title")
            if key in seen:
                continue
            seen.add(key)
            row = empty_row()
            row.update(common)
            url = adv.get("url") or ""
            advisory_id = ghsa_from_url(url)
            cvss = adv.get("cvss") or {}
            row.update(
                kind="advisory",
                severity=resolve_severity(
                    adv.get("severity"), entry.get("severity"), warnings=warnings
                ),
                advisory_id=advisory_id,
                source_id=adv.get("source") or "",
                cve=", ".join(cve_map.get(advisory_id.lower(), [])),
                title=adv.get("title") or "",
                cwe=", ".join(adv.get("cwe") or []),
                cvss_score=cvss.get("score") if isinstance(cvss, dict) else "",
                vulnerable_range=adv.get("range") or common["vulnerable_range"],
                url=url,
            )
            rows.append(row)
        if via_names:
            row = empty_row()
            row.update(common)
            row.update(
                kind="transitive",
                severity=resolve_severity(entry.get("severity"), warnings=warnings),
                via=", ".join(sorted(set(via_names))),
            )
            rows.append(row)
    return rows


def rows_from_v6(report: dict, cve_map: dict, warnings: list[str] | None = None) -> list[dict]:
    """Fallback for the npm 6 'advisories' format. Fix details are limited there."""
    rows = []
    advisories = report.get("advisories") or {}
    for key in sorted(advisories, key=str):
        adv = advisories[key] or {}
        findings = [f for f in adv.get("findings") or [] if isinstance(f, dict)]
        versions = sorted({f.get("version") for f in findings if f.get("version")})
        row = empty_row()
        patched = adv.get("patched_versions") or ""
        advisory_id = ghsa_from_url(adv.get("url"))
        row.update(
            package=adv.get("module_name") or "",
            severity=resolve_severity(adv.get("severity"), warnings=warnings),
            kind="advisory",
            direct="",
            installed_versions=versions,
            advisory_id=advisory_id,
            source_id=adv.get("id") or key,
            cve=", ".join(adv.get("cves") or cve_map.get(advisory_id.lower(), [])),
            title=adv.get("title") or "",
            cwe=adv.get("cwe") or "",
            vulnerable_range=adv.get("vulnerable_versions") or "",
            fix_available=bool(patched) and patched != "<0.0.0",
            fix_version=patched,
            url=adv.get("url") or "",
        )
        rows.append(row)
    return rows


def build_rows(
    report: object, lock: dict, cve_map: dict, warnings: list[str] | None = None
) -> list[dict]:
    if not isinstance(report, dict):
        raise ValueError("audit JSON must be an object")
    if "error" in report and "vulnerabilities" not in report:
        raise ValueError("npm audit returned an error: " + json.dumps(report["error"])[:200])
    if "vulnerabilities" in report:
        return rows_from_v7(report, lock, cve_map, warnings)
    if "advisories" in report:
        return rows_from_v6(report, cve_map, warnings)
    return []


def summarise(rows: list[dict]) -> dict:
    """Count advisories and packages by severity, and packages by fix class.

    Packages are counted once, as npm does. Their severity is the highest of their rows.
    """
    by_severity = dict.fromkeys(SEVERITIES, 0)
    package_severity: dict[str, str] = {}
    package_fix: dict[str, dict] = {}
    for row in rows:
        if row["kind"] == "advisory":
            by_severity[row["severity"]] += 1
        name = row["package"]
        if name not in package_severity or RANK[row["severity"]] > RANK[package_severity[name]]:
            package_severity[name] = row["severity"]
        package_fix[name] = row
    packages_by_severity = dict.fromkeys(SEVERITIES, 0)
    for severity in package_severity.values():
        packages_by_severity[severity] += 1
    fix_major = sum(1 for r in package_fix.values() if r["fix_available"] and r["fix_semver_major"])
    fix_minor = sum(
        1 for r in package_fix.values() if r["fix_available"] and not r["fix_semver_major"]
    )
    no_fix = sum(1 for r in package_fix.values() if not r["fix_available"])
    return {
        "advisories_by_severity": by_severity,
        "packages_by_severity": packages_by_severity,
        "packages_total": len(package_severity),
        "packages_fixable_without_major_bump": fix_minor,
        "packages_fixable_with_major_bump": fix_major,
        "packages_without_fix": no_fix,
    }


def load_cve_map(path: str | None) -> dict:
    """Build {GHSA id: [CVE ids]} from a `trivy fs --format json` report."""
    if not path:
        return {}
    data = load_json(path)
    mapping: dict[str, list[str]] = {}
    for result in (data or {}).get("Results") or []:
        for vuln in result.get("Vulnerabilities") or []:
            vid = vuln.get("VulnerabilityID") or ""
            ids = [vid] + list(vuln.get("VendorIDs") or [])
            if not any(i.upper().startswith("GHSA-") for i in ids):
                # No vendor id: fall back to GitHub advisory links in the references.
                for ref in vuln.get("References") or []:
                    if "github.com/advisories/GHSA-" in ref:
                        ids.append(ref.rsplit("/", 1)[-1])
            ghsas = [i.lower() for i in ids if i.upper().startswith("GHSA-")]
            cves = [i for i in ids if i.upper().startswith("CVE-")]
            for ghsa in ghsas:
                for cve in cves:
                    if cve not in mapping.setdefault(ghsa, []):
                        mapping[ghsa].append(cve)
    return mapping


def parse_epss(data: object) -> dict[str, dict]:
    """Build {CVE id: {epss, percentile, date}} from a FIRST EPSS API response."""
    mapping: dict[str, dict] = {}
    entries = data.get("data") if isinstance(data, dict) else None
    for item in entries or []:
        if not isinstance(item, dict) or not item.get("cve"):
            continue
        try:
            score = float(item["epss"])
            percentile = float(item.get("percentile", ""))
        except (KeyError, TypeError, ValueError):
            continue
        mapping[str(item["cve"]).upper()] = {
            "epss": score,
            "percentile": percentile,
            "date": str(item.get("date") or ""),
        }
    return mapping


def fetch_epss(cves: list[str], timeout: float = 20.0) -> dict[str, dict]:
    """Look up EPSS scores at FIRST (public API, no key). Raises ValueError on failure."""
    mapping: dict[str, dict] = {}
    for start in range(0, len(cves), EPSS_BATCH):
        batch = cves[start : start + EPSS_BATCH]
        url = EPSS_API + "?" + urllib.parse.urlencode({"cve": ",".join(batch)}, safe=",")
        try:
            # The URL is the fixed https constant above, so no other scheme is possible.
            with urllib.request.urlopen(url, timeout=timeout) as response:  # noqa: S310
                mapping.update(parse_epss(json.load(response)))
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            raise ValueError(f"EPSS lookup failed: {exc}") from exc
    return mapping


def row_cves(row: dict) -> list[str]:
    return [c.strip().upper() for c in str(row.get("cve") or "").split(",") if c.strip()]


def apply_epss(rows: list[dict], epss_map: dict[str, dict]) -> int:
    """Add the highest EPSS score of a row's CVEs. Returns how many rows got a score."""
    scored = 0
    for row in rows:
        hits = [epss_map[c] for c in row_cves(row) if c in epss_map]
        if hits:
            best = max(hits, key=lambda h: h["epss"])
            row["epss"] = best["epss"]
            row["epss_percentile"] = best["percentile"]
            scored += 1
    return scored


def below_epss(row: dict, minimum: float) -> bool:
    """True only when a score is known and under the minimum. Unknown scores are kept."""
    return row["epss"] != "" and float(row["epss"]) < minimum


def neutralise_cell(value: object) -> object:
    """Stop spreadsheets from reading a text cell as a formula."""
    if isinstance(value, str) and value.startswith(CSV_FORMULA_PREFIXES):
        return "'" + value
    return value


def write_outputs(
    rows: list[dict], summary: dict, json_path: str, csv_path: str, meta: dict | None = None
) -> None:
    with open(json_path, "w", encoding="utf-8") as handle:
        json.dump({"meta": meta or {}, "summary": summary, "findings": rows}, handle, indent=2)
        handle.write("\n")
    with open(csv_path, "w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=CSV_FIELDS, lineterminator="\n")
        writer.writeheader()
        for row in rows:
            flat = {key: neutralise_cell(value) for key, value in row.items()}
            flat["installed_versions"] = ", ".join(row["installed_versions"] or [])
            writer.writerow(flat)


def print_summary(summary: dict, min_severity: str) -> None:
    print(f"Minimum severity shown: {min_severity}")
    print(f"Vulnerable packages: {summary['packages_total']}")
    for severity in reversed(SEVERITIES):
        pkgs = summary["packages_by_severity"][severity]
        rows = summary["advisories_by_severity"][severity]
        print(f"  {severity:<9} packages {pkgs:>3}   advisories {rows:>3}")
    print("Advisories are counted once per package and advisory.")
    print(f"Fixable without a major bump: {summary['packages_fixable_without_major_bump']}")
    print(f"Fixable only with a major bump: {summary['packages_fixable_with_major_bump']}")
    print(f"No fix available: {summary['packages_without_fix']}")
    if summary.get("advisories_with_epss") is not None:
        print(f"Advisories with an EPSS score: {summary['advisories_with_epss']}")


def parse_args(argv: list[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("input", help="npm audit --json file, or - for stdin")
    parser.add_argument("--lockfile", help="package-lock.json, used to add installed versions")
    parser.add_argument("--trivy", help="trivy fs JSON report, used to add CVE ids")
    parser.add_argument("--epss", help="saved FIRST EPSS API response (JSON), adds EPSS scores")
    parser.add_argument(
        "--epss-fetch",
        action="store_true",
        help="look up EPSS scores for the CVE ids at api.first.org (needs network)",
    )
    parser.add_argument(
        "--min-epss",
        type=float,
        help="drop advisories whose known EPSS score is below this value (0 to 1). "
        "Advisories without a score are kept. Needs --epss or --epss-fetch",
    )
    parser.add_argument("--json-out", default="vulnerabilities.json")
    parser.add_argument("--csv-out", default="vulnerabilities.csv")
    parser.add_argument("--min-severity", choices=SEVERITIES, default="info")
    parser.add_argument(
        "--fail-on",
        choices=SEVERITIES,
        help="exit 1 if any finding has this severity or higher",
    )
    args = parser.parse_args(argv)
    if args.min_epss is not None:
        if not 0 <= args.min_epss <= 1:
            parser.error("--min-epss must be between 0 and 1")
        if not (args.epss or args.epss_fetch):
            parser.error("--min-epss needs --epss or --epss-fetch")
    return args


def attach_epss(
    args: argparse.Namespace, rows: list[dict], warnings: list[str]
) -> tuple[str, set[str]]:
    """Add EPSS scores from --epss or --epss-fetch. Returns the source and the score dates."""
    if not (args.epss or args.epss_fetch):
        return "", set()
    if args.epss:
        epss_map = parse_epss(load_json(args.epss))
        source = "file:" + Path(args.epss).name
    else:
        wanted = sorted({c for row in rows for c in row_cves(row)})
        epss_map = fetch_epss(wanted) if wanted else {}
        source = EPSS_API
    apply_epss(rows, epss_map)
    if any(r["kind"] == "advisory" for r in rows) and not any(row_cves(r) for r in rows):
        warnings.append("no EPSS scores were added: npm audit has no CVE ids, pass --trivy")
    return source, {v["date"] for v in epss_map.values() if v["date"]}


def run(args: argparse.Namespace) -> int:
    warnings: list[str] = []
    report = load_json(args.input)
    lock = load_json(args.lockfile) if args.lockfile else {}
    cve_map = load_cve_map(args.trivy)
    rows = build_rows(report, lock, cve_map, warnings)
    epss_source, epss_dates = attach_epss(args, rows, warnings)
    floor = RANK[args.min_severity]
    rows = [r for r in rows if RANK[r["severity"]] >= floor]
    if args.min_epss is not None:
        rows = [r for r in rows if not below_epss(r, args.min_epss)]
    summary = summarise(rows)
    if epss_source:
        summary["advisories_with_epss"] = sum(
            1 for r in rows if r["kind"] == "advisory" and r["epss"] != ""
        )
    meta = {
        "tool": "audit_report.py",
        "generated_at": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "input": "stdin" if args.input == "-" else Path(args.input).name,
        "audit_report_version": report.get("auditReportVersion"),
        "epss_source": epss_source,
        "epss_date": ", ".join(sorted(epss_dates)),
        "warnings": sorted(set(warnings)),
    }
    write_outputs(rows, summary, args.json_out, args.csv_out, meta)
    for warning in meta["warnings"]:
        print(f"warning: {warning}", file=sys.stderr)
    print_summary(summary, args.min_severity)
    if args.fail_on:
        threshold = RANK[args.fail_on]
        if any(RANK[r["severity"]] >= threshold for r in rows):
            print(f"Failing: findings at or above {args.fail_on}.", file=sys.stderr)
            return 1
    return 0


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        return run(args)
    except (OSError, ValueError, TypeError, AttributeError, RecursionError) as exc:
        print(f"error: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
