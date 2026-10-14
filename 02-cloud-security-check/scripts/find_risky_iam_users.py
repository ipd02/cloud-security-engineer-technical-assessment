#!/usr/bin/env python3
"""Find risky IAM users, roles and root account settings from two AWS exports.

Get the exports with the AWS CLI, then run this script. It makes no AWS calls:

  aws iam generate-credential-report
  aws iam get-credential-report --query Content --output text | base64 -d > report.csv
  aws iam get-account-authorization-details --filter User Role Group LocalManagedPolicy \
      --output json > authz.json

Findings, worst first. Policy findings apply to users and roles, whether the
policy is inline, attached, or comes from a group:

  critical  a policy that allows Action "*" on Resource "*"
  critical  the AWS managed policy AdministratorAccess is attached
  critical  the root account has an active access key
  high      a policy that allows "iam:*" on Resource "*"
  high      the AWS managed policy IAMFullAccess is attached
  high      a console password without MFA
  high      the root account has no MFA device
  medium    a policy that allows another "service:*" action on Resource "*"
  medium    an active access key older than --max-key-age days
  medium    an active access key never used, or unused for --unused-days
  low       a console password unused for --unused-days

A finding is a lead to check, not a verdict. The credential report lags: a key
used a few minutes ago can still show no last use.

The script reads policies as they are written. It does not combine them with
Deny statements, conditions, permission boundaries or SCPs. To see the real
permissions of one principal, use the IAM policy simulator or IAM Access
Analyzer. Service-linked roles are skipped. The input is the AWS CLI v2 output,
which already joins long results into one document.

Exit code: 1 if a finding at or above --fail-on exists, 2 if an input file
cannot be read or is the wrong kind of file, otherwise 0.
"""

import argparse
import csv
import json
import sys
from datetime import datetime, timedelta, timezone
from urllib.parse import unquote

SEVERITIES = ["low", "medium", "high", "critical"]
MANAGED_POLICY_SEVERITY = {
    "AdministratorAccess": ("critical", "grants full administrator access"),
    "IAMFullAccess": ("high", "grants full IAM access, which can be used to grant any permission"),
}
ROOT_USER = "<root_account>"
REQUIRED_COLUMNS = {
    "user", "password_enabled", "password_last_used", "mfa_active",
    "access_key_1_active", "access_key_1_last_rotated", "access_key_1_last_used_date",
    "access_key_2_active", "access_key_2_last_rotated", "access_key_2_last_used_date",
}


class InputError(Exception):
    """An input file or value that the script cannot use."""


def parse_time(value):
    """Return an aware datetime, or None for the report's N/A markers.

    A time without an offset is read as UTC.
    """
    if not value or value in ("N/A", "no_information", "not_supported"):
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise InputError(f"unreadable time value: {value}") from exc
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def as_list(value):
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def load_document(doc):
    """Policy documents are objects, but tolerate URL-encoded JSON strings."""
    if isinstance(doc, str):
        return json.loads(unquote(doc))
    return doc or {}


def wildcard_findings(doc):
    """Yield (severity, text) for Allow statements that grant a wildcard on all resources."""
    for stmt in as_list(load_document(doc).get("Statement")):
        if stmt.get("Effect") != "Allow" or "NotAction" in stmt:
            continue
        if "*" not in as_list(stmt.get("Resource")):
            continue
        for action in as_list(stmt.get("Action")):
            action = action.lower()
            if action in ("*", "*:*"):
                yield "critical", "Action * on Resource *"
            elif action == "iam:*":
                yield "high", "Action iam:* on Resource *, which can grant any permission"
            elif action.endswith(":*"):
                yield "medium", f"Action {action} on Resource *"


def default_version_document(policy):
    for version in policy.get("PolicyVersionList", []):
        if version.get("IsDefaultVersion"):
            return version.get("Document")
    return None


def aws_managed_policy(arn):
    """Return the name if the ARN is an AWS managed policy we rate, else None."""
    for name in MANAGED_POLICY_SEVERITY:
        if arn.endswith(f":iam::aws:policy/{name}"):
            return name
    return None


def policy_findings(entity, inline_key, groups, managed):
    """Yield (severity, message) for the policies that apply to one user or role."""
    sources = [(f"inline policy {p['PolicyName']}", p["PolicyDocument"])
               for p in entity.get(inline_key, [])]
    attached = list(entity.get("AttachedManagedPolicies", []))
    for group_name in entity.get("GroupList", []):
        group = groups.get(group_name, {})
        sources += [(f"group {group_name} inline policy {p['PolicyName']}", p["PolicyDocument"])
                    for p in group.get("GroupPolicyList", [])]
        attached += [dict(a, via=group_name) for a in group.get("AttachedManagedPolicies", [])]
    for att in attached:
        label = f"group {att['via']} attached policy {att['PolicyName']}" if "via" in att \
            else f"attached policy {att['PolicyName']}"
        rated = aws_managed_policy(att["PolicyArn"])
        if rated:
            severity, text = MANAGED_POLICY_SEVERITY[rated]
            yield severity, f"{label} {text}"
        doc = default_version_document(managed.get(att["PolicyArn"], {}))
        if doc is not None:
            sources.append((label, doc))
    for label, doc in sources:
        for severity, text in wildcard_findings(doc):
            yield severity, f"{label} allows {text}"


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


def root_findings(row):
    if "true" in (row["access_key_1_active"], row["access_key_2_active"]):
        yield "critical", "root account has an active access key"
    if row["mfa_active"] != "true":
        yield "high", "root account has no MFA device"


def read_report(path):
    try:
        with open(path, newline="", encoding="utf-8") as handle:
            reader = csv.DictReader(handle)
            rows = list(reader)
            columns = set(reader.fieldnames or [])
    except (OSError, UnicodeDecodeError) as exc:
        raise InputError(f"cannot read {path}: {exc}") from exc
    missing = sorted(REQUIRED_COLUMNS - columns)
    if missing:
        raise InputError(f"{path} is not a credential report, missing columns: {', '.join(missing)}")
    return rows


def read_authorization_details(path):
    try:
        with open(path, encoding="utf-8") as handle:
            authz = json.load(handle)
    except (OSError, UnicodeDecodeError) as exc:
        raise InputError(f"cannot read {path}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise InputError(f"{path} is not valid JSON: {exc}") from exc
    if not isinstance(authz, dict) or not isinstance(authz.get("UserDetailList"), list):
        raise InputError(f"{path} is not get-account-authorization-details output: no UserDetailList")
    return authz


def analyse(report_rows, authz, now, max_key_age=90, unused_days=90):
    users = {u["UserName"]: u for u in authz.get("UserDetailList", [])}
    roles = {r["RoleName"]: r for r in authz.get("RoleDetailList", [])
             if not r.get("Path", "").startswith("/aws-service-role/")}
    groups = {g["GroupName"]: g for g in authz.get("GroupDetailList", [])}
    managed = {p["Arn"]: p for p in authz.get("Policies", [])}
    rows = {r["user"]: r for r in report_rows}
    names = [n for n in rows if n != ROOT_USER]
    names += [n for n in users if n not in names]
    findings = {}
    if ROOT_USER in rows:
        findings[("root", ROOT_USER)] = list(root_findings(rows[ROOT_USER]))
    for name in names:
        found = []
        if name in rows:
            found += credential_findings(rows[name], now, max_key_age, unused_days)
        if name in users:
            found += policy_findings(users[name], "UserPolicyList", groups, managed)
        findings[("user", name)] = found
    for name, role in roles.items():
        findings[("role", name)] = list(policy_findings(role, "RolePolicyList", groups, managed))
    results = []
    for (kind, name), found in findings.items():
        if found:
            found.sort(key=lambda f: -SEVERITIES.index(f[0]))
            results.append({
                "name": name,
                "kind": kind,
                "top_severity": found[0][0],
                "findings": [{"severity": s, "detail": d} for s, d in found],
            })
    results.sort(key=lambda r: (-SEVERITIES.index(r["top_severity"]), r["name"]))
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

    try:
        now = parse_time(args.now) if args.now else datetime.now(timezone.utc)
        if now is None:
            raise InputError(f"unreadable time value: {args.now}")
        rows = read_report(args.credential_report)
        authz = read_authorization_details(args.authorization_details)
        results = analyse(rows, authz, now, args.max_key_age, args.unused_days)
    except InputError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    if args.format == "json":
        json.dump(results, sys.stdout, indent=2)
        print()
    else:
        for result in results:
            print(f"{result['name']} ({result['kind']})  [{result['top_severity']}]")
            for finding in result["findings"]:
                print(f"  {finding['severity']:<8} {finding['detail']}")
        print(f"{len(results)} principal(s) with findings")
    threshold = SEVERITIES.index(args.fail_on)
    return 1 if any(SEVERITIES.index(r["top_severity"]) >= threshold for r in results) else 0


if __name__ == "__main__":
    sys.exit(main())
