#!/usr/bin/env python3
"""Find risky IAM users from two read-only AWS exports.

Inputs (produce them with the AWS CLI, then run this script offline):

  aws iam generate-credential-report
  aws iam get-credential-report --query Content --output text | base64 -d > report.csv
  aws iam get-account-authorization-details --filter User Group LocalManagedPolicy \
      --output json > authz.json

Rules, highest severity first:

  critical  an Allow statement with Action "*" on Resource "*"
            (inline, attached managed policy, or inherited from a group)
  high      the user has AdministratorAccess attached
  high      console password enabled and no MFA
  medium    active access key older than --max-key-age days
  medium    active access key never used, or unused for --unused-days
  low       console password unused for --unused-days

A finding is a lead, not a verdict. Check what uses the identity before
you disable or delete it.

Exit code is 1 when a finding at or above --fail-on exists, otherwise 0.
"""

import argparse
import csv
import json
import sys
from datetime import datetime, timedelta, timezone
from urllib.parse import unquote

SEVERITIES = ["low", "medium", "high", "critical"]
ADMIN_POLICY_NAME = "AdministratorAccess"


def parse_time(value):
    """Return an aware datetime, or None for the report's N/A markers."""
    if not value or value in ("N/A", "no_information", "not_supported"):
        return None
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def as_list(value):
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def load_document(doc):
    """Policy documents are objects, but tolerate URL-encoded JSON strings."""
    if isinstance(doc, str):
        return json.loads(unquote(doc))
    return doc or {}


def has_wildcard_admin(doc):
    for stmt in as_list(load_document(doc).get("Statement")):
        if stmt.get("Effect") != "Allow" or "NotAction" in stmt:
            continue
        actions = as_list(stmt.get("Action"))
        resources = as_list(stmt.get("Resource"))
        if ("*" in actions or "*:*" in actions) and "*" in resources:
            return True
    return False


def default_version_document(policy):
    for version in policy.get("PolicyVersionList", []):
        if version.get("IsDefaultVersion"):
            return version.get("Document")
    return None


def policy_findings_for_user(user, groups, managed):
    """Yield (severity, message) for the policies that apply to one user."""
    sources = [(f"inline policy {p['PolicyName']}", p["PolicyDocument"])
               for p in user.get("UserPolicyList", [])]
    attached = list(user.get("AttachedManagedPolicies", []))
    for group_name in user.get("GroupList", []):
        group = groups.get(group_name, {})
        sources += [(f"group {group_name} inline policy {p['PolicyName']}", p["PolicyDocument"])
                    for p in group.get("GroupPolicyList", [])]
        attached += [dict(a, via=group_name) for a in group.get("AttachedManagedPolicies", [])]
    for att in attached:
        label = f"group {att['via']} attached policy {att['PolicyName']}" if "via" in att \
            else f"attached policy {att['PolicyName']}"
        if att["PolicyName"] == ADMIN_POLICY_NAME:
            yield "high", f"{label} grants full administrator access"
        doc = default_version_document(managed.get(att["PolicyArn"], {}))
        if doc is not None:
            sources.append((label, doc))
    for label, doc in sources:
        if has_wildcard_admin(doc):
            yield "critical", f"{label} allows Action * on Resource *"


def credential_findings(row, now, max_key_age, unused_days):
    unused_after = timedelta(days=unused_days)
    if row["password_enabled"] == "true":
        if row["mfa_active"] != "true":
            yield "high", "console password enabled and no MFA device"
        last = parse_time(row["password_last_used"])
        if last is not None and now - last > unused_after:
            yield "low", f"console password unused since {last.date()}"
    for n in ("1", "2"):
        if row[f"access_key_{n}_active"] != "true":
            continue
        rotated = parse_time(row[f"access_key_{n}_last_rotated"])
        used = parse_time(row[f"access_key_{n}_last_used_date"])
        if rotated is not None and now - rotated > timedelta(days=max_key_age):
            yield "medium", f"access key {n} is {(now - rotated).days} days old"
        if used is None:
            yield "medium", f"access key {n} is active and was never used"
        elif now - used > unused_after:
            yield "medium", f"access key {n} unused since {used.date()}"


def analyse(report_rows, authz, now, max_key_age=90, unused_days=90):
    users = {u["UserName"]: u for u in authz.get("UserDetailList", [])}
    groups = {g["GroupName"]: g for g in authz.get("GroupDetailList", [])}
    managed = {p["Arn"]: p for p in authz.get("Policies", [])}
    results = []
    names = [r["user"] for r in report_rows if r["user"] != "<root_account>"]
    names += [n for n in users if n not in names]
    rows = {r["user"]: r for r in report_rows}
    for name in names:
        found = []
        if name in rows:
            found += credential_findings(rows[name], now, max_key_age, unused_days)
        if name in users:
            found += policy_findings_for_user(users[name], groups, managed)
        if found:
            found.sort(key=lambda f: -SEVERITIES.index(f[0]))
            results.append({
                "user": name,
                "top_severity": found[0][0],
                "findings": [{"severity": s, "detail": d} for s, d in found],
            })
    results.sort(key=lambda r: (-SEVERITIES.index(r["top_severity"]), r["user"]))
    return results


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--credential-report", required=True, help="CSV from get-credential-report")
    parser.add_argument("--authorization-details", required=True, help="JSON from get-account-authorization-details")
    parser.add_argument("--max-key-age", type=int, default=90)
    parser.add_argument("--unused-days", type=int, default=90)
    parser.add_argument("--now", help="ISO time to use as now (for repeatable runs)")
    parser.add_argument("--format", choices=["text", "json"], default="text")
    parser.add_argument("--fail-on", choices=SEVERITIES, default="high")
    args = parser.parse_args(argv)

    now = parse_time(args.now) if args.now else datetime.now(timezone.utc)
    with open(args.credential_report, newline="", encoding="utf-8") as handle:
        rows = list(csv.DictReader(handle))
    with open(args.authorization_details, encoding="utf-8") as handle:
        authz = json.load(handle)

    results = analyse(rows, authz, now, args.max_key_age, args.unused_days)
    if args.format == "json":
        json.dump(results, sys.stdout, indent=2)
        print()
    else:
        for result in results:
            print(f"{result['user']}  [{result['top_severity']}]")
            for finding in result["findings"]:
                print(f"  {finding['severity']:<8} {finding['detail']}")
        print(f"{len(results)} user(s) with findings")
    threshold = SEVERITIES.index(args.fail_on)
    return 1 if any(SEVERITIES.index(r["top_severity"]) >= threshold for r in results) else 0


if __name__ == "__main__":
    sys.exit(main())
