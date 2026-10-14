"""Tests for scripts/find_risky_iam_users.py. Fixtures are invented data.

Run: python3 -m unittest discover -s 02-cloud-security-check/tests -p 'test_*.py'
"""

import contextlib
import csv
import io
import json
import sys
import unittest
from datetime import datetime, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "scripts"))

import find_risky_iam_users as tool  # noqa: E402

NOW = datetime(2026, 10, 14, tzinfo=timezone.utc)


def run():
    with open(HERE / "fixtures/credential-report.csv", newline="", encoding="utf-8") as handle:
        rows = list(csv.DictReader(handle))
    authz = json.loads((HERE / "fixtures/authorization-details.json").read_text(encoding="utf-8"))
    return {r["user"]: r for r in tool.analyse(rows, authz, NOW)}


class AnalyseTest(unittest.TestCase):
    def test_wildcard_inline_policy_is_critical(self):
        result = run()["UnrestrictedUser"]
        self.assertEqual(result["top_severity"], "critical")
        details = [f["detail"] for f in result["findings"]]
        self.assertTrue(any("FullAccess" in d for d in details))
        self.assertTrue(any("never used" in d for d in details))

    def test_admin_inherited_from_group(self):
        result = run()["group-admin-user"]
        self.assertEqual(result["top_severity"], "high")
        self.assertIn("group admins", result["findings"][0]["detail"])

    def test_console_user_without_mfa(self):
        result = run()["no-mfa-user"]
        self.assertEqual([f["severity"] for f in result["findings"]], ["high"])

    def test_scoped_policy_and_clean_user_are_not_reported(self):
        results = run()
        self.assertNotIn("healthy-user", results)
        self.assertNotIn("<root_account>", results)

    def test_order_is_most_severe_first(self):
        with open(HERE / "fixtures/credential-report.csv", newline="", encoding="utf-8") as handle:
            rows = list(csv.DictReader(handle))
        authz = json.loads((HERE / "fixtures/authorization-details.json").read_text(encoding="utf-8"))
        names = [r["user"] for r in tool.analyse(rows, authz, NOW)]
        self.assertEqual(names[0], "UnrestrictedUser")

    def test_wildcard_detection_edge_cases(self):
        allow_all = {"Statement": {"Effect": "Allow", "Action": ["*"], "Resource": ["*"]}}
        deny_all = {"Statement": [{"Effect": "Deny", "Action": "*", "Resource": "*"}]}
        scoped = {"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "arn:aws:s3:::b"}]}
        self.assertTrue(tool.has_wildcard_admin(allow_all))
        self.assertFalse(tool.has_wildcard_admin(deny_all))
        self.assertFalse(tool.has_wildcard_admin(scoped))

    def test_exit_code_follows_fail_on(self):
        args = ["--credential-report", str(HERE / "fixtures/credential-report.csv"),
                "--authorization-details", str(HERE / "fixtures/authorization-details.json"),
                "--now", "2026-10-14T00:00:00+00:00", "--format", "json"]
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(tool.main(args + ["--fail-on", "critical"]), 1)


if __name__ == "__main__":
    unittest.main()
