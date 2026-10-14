#!/usr/bin/env python3
"""Compare an npm audit report with a trivy fs report by GHSA id. Standard library only.

Exit codes: 0 compared (differences are printed, not an error), 2 bad usage or unreadable input.
"""

from __future__ import annotations

import json
import sys


def npm_ids(path: str) -> dict[str, tuple[str, str]]:
    """Return {ghsa: (package, severity)} for npm audit advisories."""
    with open(path, encoding="utf-8") as handle:
        data = json.load(handle)
    found = {}
    for name, entry in (data.get("vulnerabilities") or {}).items():
        for via in entry.get("via") or []:
            if isinstance(via, dict) and via.get("url"):
                found[via["url"].rsplit("/", 1)[-1].lower()] = (name, via.get("severity", ""))
    return found


def trivy_ids(path: str) -> dict[str, tuple[str, str, str]]:
    """Return {ghsa: (package, severity, cve)} for trivy findings that carry a GHSA id."""
    with open(path, encoding="utf-8") as handle:
        data = json.load(handle)
    found = {}
    for result in data.get("Results") or []:
        for vuln in result.get("Vulnerabilities") or []:
            ids = [vuln.get("VulnerabilityID", "")] + list(vuln.get("VendorIDs") or [])
            if not any(i.lower().startswith("ghsa-") for i in ids):
                # No vendor id: fall back to GitHub advisory links in the references.
                for ref in vuln.get("References") or []:
                    if "github.com/advisories/GHSA-" in ref:
                        ids.append(ref.rsplit("/", 1)[-1])
            for item in ids:
                if item.lower().startswith("ghsa-"):
                    found[item.lower()] = (
                        vuln.get("PkgName", ""),
                        vuln.get("Severity", "").lower().replace("medium", "moderate"),
                        vuln.get("VulnerabilityID", ""),
                    )
    return found


def main(argv: list[str]) -> int:
    if len(argv) != 3:
        print("usage: compare_scanners.py npm-audit.json trivy.json", file=sys.stderr)
        return 2
    try:
        npm, trivy = npm_ids(argv[1]), trivy_ids(argv[2])
    except (OSError, ValueError, TypeError, AttributeError) as exc:
        print(f"error: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 2
    both = sorted(set(npm) & set(trivy))
    print(f"npm audit advisories: {len(npm)}")
    print(f"trivy findings with a GHSA id: {len(trivy)}")
    print(f"in both: {len(both)}")
    print("severity differs (npm vs trivy):")
    for ghsa in both:
        if npm[ghsa][1] != trivy[ghsa][1]:
            print(f"  {ghsa} {npm[ghsa][0]} npm={npm[ghsa][1]} trivy={trivy[ghsa][1]}")
    print("only in npm audit:")
    for ghsa in sorted(set(npm) - set(trivy)):
        print(f"  {ghsa} {npm[ghsa][0]} {npm[ghsa][1]}")
    print("only in trivy:")
    for ghsa in sorted(set(trivy) - set(npm)):
        print(f"  {ghsa} {trivy[ghsa][0]} {trivy[ghsa][1]} {trivy[ghsa][2]}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
