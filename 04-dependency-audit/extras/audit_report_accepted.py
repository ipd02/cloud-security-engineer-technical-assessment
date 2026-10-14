#!/usr/bin/env python3
"""audit_report.py with accepted risks: findings recorded in a file are no longer reported.

For a scan that runs on a schedule. An accepted risk is a committed JSON entry with an
advisory id, a package, a reason, the controls that make it acceptable, an owner and an
expiry date. While an entry is valid, its finding is moved out of the report and out of the
--fail-on gate, and listed in the accepted output. When it expires, the finding comes back.

Exit codes are those of audit_report.py: 0 ok, 1 findings at or above --fail-on, 2 bad input
or a bad accepted file.
"""

from __future__ import annotations

import json
import re
import sys
from datetime import UTC, date, datetime, timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import audit_report as ar  # noqa: E402

REQUIRED = ("advisory", "package", "reason", "owner", "expires", "controls")
OPTIONAL = ("accepted_on", "version")
GHSA = re.compile(r"^GHSA(?:-[0-9a-z]{4}){3}$", re.IGNORECASE)


def parse_date(value: object, label: str) -> date:
    try:
        return date.fromisoformat(str(value))
    except ValueError as exc:
        raise ValueError(f"{label}: {value!r} is not a date (use YYYY-MM-DD)") from exc


def load_accepted(path: str) -> list[dict]:
    """Read and check the accepted file. Raises ValueError listing every problem."""
    data = ar.load_json(path)
    entries = data.get("accepted") if isinstance(data, dict) else None
    if not isinstance(entries, list):
        raise ValueError('accepted file must be an object with an "accepted" list')
    problems: list[str] = []
    seen: set[tuple[str, str]] = set()
    checked = []
    for number, entry in enumerate(entries, start=1):
        label = f"accepted[{number}]"
        if not isinstance(entry, dict):
            problems.append(f"{label}: must be an object")
            continue
        for key in sorted(set(entry) - set(REQUIRED) - set(OPTIONAL)):
            problems.append(f"{label}: unknown field {key!r}")
        for key in REQUIRED:
            if not entry.get(key):
                problems.append(f"{label}: {key!r} is required")
        advisory = str(entry.get("advisory") or "")
        if advisory and not GHSA.match(advisory):
            problems.append(f"{label}: advisory {advisory!r} is not a GHSA id")
        controls = entry.get("controls")
        if controls and (
            not isinstance(controls, list) or not all(isinstance(c, str) and c for c in controls)
        ):
            problems.append(f"{label}: 'controls' must be a list of non-empty strings")
        for key in ("expires", "accepted_on"):
            if entry.get(key):
                try:
                    parse_date(entry[key], f"{label}.{key}")
                except ValueError as exc:
                    problems.append(str(exc))
        key = (advisory.lower(), str(entry.get("package") or ""))
        if key in seen:
            problems.append(f"{label}: {advisory} for {key[1]} is listed twice")
        seen.add(key)
        checked.append(entry)
    if problems:
        raise ValueError("accepted file is not valid:\n  " + "\n  ".join(problems))
    return checked


def matches(entry: dict, row: dict) -> bool:
    if row["kind"] != "advisory" or row["package"] != entry["package"]:
        return False
    if row["advisory_id"].lower() != entry["advisory"].lower():
        return False
    version = entry.get("version")
    installed = row["installed_versions"] or []
    return not (version and installed and version not in installed)


def drop_dead_transitive_rows(rows: list[dict]) -> list[dict]:
    """Drop 'vulnerable through a dependency' rows once none of those packages is vulnerable."""
    alive = {r["package"] for r in rows if r["kind"] == "advisory"}
    transitive = [r for r in rows if r["kind"] == "transitive"]
    changed = True
    while changed:
        changed = False
        for row in transitive:
            names = [n.strip() for n in row["via"].split(",") if n.strip()]
            if row["package"] not in alive and any(n in alive for n in names):
                alive.add(row["package"])
                changed = True
    return [r for r in rows if r["package"] in alive]


def split_rows(
    rows: list[dict], entries: list[dict], today: date
) -> tuple[list[dict], list[dict], list[dict], list[dict]]:
    """Return remaining rows, accepted findings, expired findings and unused entries."""
    remaining, accepted, expired = [], [], []
    used: set[int] = set()
    for row in rows:
        hit = next((i for i, e in enumerate(entries) if matches(e, row)), None)
        if hit is None:
            remaining.append(row)
            continue
        used.add(hit)
        entry = entries[hit]
        if today <= parse_date(entry["expires"], "expires"):
            accepted.append({"finding": row, "acceptance": entry})
        else:
            expired.append({"finding": row, "acceptance": entry})
            remaining.append(row)
    unused = [e for i, e in enumerate(entries) if i not in used]
    return drop_dead_transitive_rows(remaining), accepted, expired, unused


def make_hook():
    def hook(args, rows: list[dict], meta: dict) -> list[dict]:
        today = parse_date(args.today, "--today") if args.today else datetime.now(UTC).date()
        entries = load_accepted(args.accepted)
        remaining, accepted, expired, unused = split_rows(rows, entries, today)
        soon = [
            e
            for e in entries
            if today
            <= parse_date(e["expires"], "expires")
            <= today + timedelta(days=args.warn_days)
        ]
        notes = []
        for item in expired:
            e, f = item["acceptance"], item["finding"]
            notes.append(
                f"acceptance expired on {e['expires']}: {f['advisory_id']} in {f['package']}"
            )
        for e in unused:
            notes.append(
                f"accepted entry matches no finding, remove it: {e['advisory']} {e['package']}"
            )
        for e in soon:
            notes.append(f"acceptance expires on {e['expires']}: {e['advisory']} in {e['package']}")
        for note in notes:
            print(f"warning: {note}", file=sys.stderr)
        meta.update(
            accepted_file=Path(args.accepted).name,
            accepted_count=len(accepted),
            expired_acceptances=[
                {"advisory": i["acceptance"]["advisory"], "package": i["acceptance"]["package"]}
                for i in expired
            ],
            unused_entries=[{"advisory": e["advisory"], "package": e["package"]} for e in unused],
            as_of=today.isoformat(),
        )
        out = {
            "meta": {"as_of": today.isoformat(), "accepted_file": Path(args.accepted).name},
            "accepted": accepted,
            "expired": expired,
            "unused_entries": unused,
        }
        with open(args.accepted_out, "w", encoding="utf-8") as handle:
            json.dump(out, handle, indent=2)
            handle.write("\n")
        print(
            f"Accepted risks: {len(accepted)} findings not reported, "
            f"{len(expired)} expired and reported again, {len(unused)} unused entries."
        )
        return remaining

    return hook


def build_parser():
    parser = ar.build_parser()
    parser.description = "Like audit_report.py, but findings listed in --accepted are not reported."
    parser.add_argument("--accepted", required=True, help="JSON file of accepted risks")
    parser.add_argument("--accepted-out", default="accepted.json", help="list of accepted findings")
    parser.add_argument("--today", help="date to check expiry against, YYYY-MM-DD (default today)")
    parser.add_argument(
        "--warn-days", type=int, default=30, help="warn when an acceptance expires within N days"
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    return ar.main(argv, parser=build_parser(), rows_hook=make_hook())


if __name__ == "__main__":
    sys.exit(main())
