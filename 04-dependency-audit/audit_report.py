#!/usr/bin/env python3
"""Turn `npm audit --json` output into a flat JSON and CSV report.

Reads the v7+ format (top-level "vulnerabilities") and, as a fallback, the
npm 6 format (top-level "advisories"). Standard library only.

Exit codes: 0 ok, 1 findings at or above --fail-on, 2 unreadable input.
"""

from __future__ import annotations

import argparse
import csv
import json
import re
import sys

SEVERITIES = ("info", "low", "moderate", "high", "critical")
RANK = {name: index for index, name in enumerate(SEVERITIES)}
GHSA_RE = re.compile(r"GHSA(?:-[0-9a-z]{4}){3}")

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
    "vulnerable_range",
    "via",
    "fix_available",
    "fix_package",
    "fix_version",
    "fix_semver_major",
    "url",
)


def normalise_severity(value: object) -> str:
    """Map a raw severity string to one of SEVERITIES. Unknown values become info."""
    text = str(value or "").strip().lower()
    if text == "medium":
        text = "moderate"
    return text if text in RANK else "info"


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


def rows_from_v7(report: dict, lock: dict, cve_map: dict) -> list[dict]:
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
                severity=normalise_severity(adv.get("severity") or entry.get("severity")),
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
                severity=normalise_severity(entry.get("severity")),
                via=", ".join(sorted(set(via_names))),
            )
            rows.append(row)
    return rows


def rows_from_v6(report: dict, cve_map: dict) -> list[dict]:
    """Fallback for the npm 6 'advisories' format. Fix details are limited there."""
    rows = []
    advisories = report.get("advisories") or {}
    for key in sorted(advisories, key=str):
        adv = advisories[key] or {}
        findings = adv.get("findings") or []
        versions = sorted({f.get("version") for f in findings if f.get("version")})
        row = empty_row()
        patched = adv.get("patched_versions") or ""
        advisory_id = ghsa_from_url(adv.get("url"))
        row.update(
            package=adv.get("module_name") or "",
            severity=normalise_severity(adv.get("severity")),
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


def build_rows(report: object, lock: dict, cve_map: dict) -> list[dict]:
    if not isinstance(report, dict):
        raise ValueError("audit JSON must be an object")
    if "error" in report and "vulnerabilities" not in report:
        raise ValueError("npm audit returned an error: " + json.dumps(report["error"])[:200])
    if "vulnerabilities" in report:
        return rows_from_v7(report, lock, cve_map)
    if "advisories" in report:
        return rows_from_v6(report, cve_map)
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


def write_outputs(rows: list[dict], summary: dict, json_path: str, csv_path: str) -> None:
    with open(json_path, "w", encoding="utf-8") as handle:
        json.dump({"summary": summary, "findings": rows}, handle, indent=2)
        handle.write("\n")
    with open(csv_path, "w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=CSV_FIELDS, lineterminator="\n")
        writer.writeheader()
        for row in rows:
            flat = dict(row)
            flat["installed_versions"] = ", ".join(row["installed_versions"] or [])
            writer.writerow(flat)


def print_summary(summary: dict, min_severity: str) -> None:
    print(f"Minimum severity shown: {min_severity}")
    print(f"Vulnerable packages: {summary['packages_total']}")
    for severity in reversed(SEVERITIES):
        pkgs = summary["packages_by_severity"][severity]
        rows = summary["advisories_by_severity"][severity]
        print(f"  {severity:<9} packages {pkgs:>3}   advisories {rows:>3}")
    print(f"Fixable without a major bump: {summary['packages_fixable_without_major_bump']}")
    print(f"Fixable only with a major bump: {summary['packages_fixable_with_major_bump']}")
    print(f"No fix available: {summary['packages_without_fix']}")


def parse_args(argv: list[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("input", help="npm audit --json file, or - for stdin")
    parser.add_argument("--lockfile", help="package-lock.json, used to add installed versions")
    parser.add_argument("--trivy", help="trivy fs JSON report, used to add CVE ids")
    parser.add_argument("--json-out", default="vulnerabilities.json")
    parser.add_argument("--csv-out", default="vulnerabilities.csv")
    parser.add_argument("--min-severity", choices=SEVERITIES, default="info")
    parser.add_argument(
        "--fail-on",
        choices=SEVERITIES,
        help="exit 1 if any finding has this severity or higher",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        report = load_json(args.input)
        lock = load_json(args.lockfile) if args.lockfile else {}
        cve_map = load_cve_map(args.trivy)
        rows = build_rows(report, lock, cve_map)
    except (OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    floor = RANK[args.min_severity]
    rows = [r for r in rows if RANK[r["severity"]] >= floor]
    summary = summarise(rows)
    write_outputs(rows, summary, args.json_out, args.csv_out)
    print_summary(summary, args.min_severity)
    if args.fail_on:
        threshold = RANK[args.fail_on]
        if any(RANK[r["severity"]] >= threshold for r in rows):
            print(f"Failing: findings at or above {args.fail_on}.", file=sys.stderr)
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
