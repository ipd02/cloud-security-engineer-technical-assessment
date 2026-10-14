"""Tests for scripts/find_risky_iam_users.py. Fixtures are invented data.

Run: python3 -m unittest discover -s 02-cloud-security-check/tests -p 'test_*.py'
"""

import contextlib
import csv
import io
import json
import sys
import tempfile
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
    return {r["name"]: r for r in tool.analyse(rows, authz, NOW)}


class AnalyseTest(unittest.TestCase):
    def test_wildcard_inline_policy_is_critical(self):
        result = run()["UnrestrictedUser"]
        self.assertEqual(result["top_severity"], "critical")
        details = [f["detail"] for f in result["findings"]]
        self.assertTrue(any("FullAccess" in d for d in details))
        self.assertTrue(any("never used" in d for d in details))

    def test_admin_inherited_from_group(self):
        result = run()["group-admin-user"]
        self.assertEqual(result["top_severity"], "critical")
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
        names = [r["name"] for r in tool.analyse(rows, authz, NOW)]
        self.assertEqual(names[0], "UnrestrictedUser")

    def test_wildcard_detection_edge_cases(self):
        def severities(*statements):
            return [sev for sev, _ in tool.wildcard_findings({"Statement": list(statements)})]

        def allow(action, resource="*", effect="Allow"):
            return {"Effect": effect, "Action": action, "Resource": resource}

        self.assertEqual(severities(allow(["*"])), ["critical"])
        self.assertEqual(severities(allow("*:*")), ["critical"])
        self.assertEqual(severities(allow("iam:*")), ["high"])
        self.assertEqual(severities(allow("IAM:*")), ["high"])
        self.assertEqual(severities(allow("ec2:*")), ["medium"])
        self.assertEqual(severities(allow(["iam:*", "ec2:*"])), ["high", "medium"])
        self.assertEqual(severities(allow("*", effect="Deny")), [])
        self.assertEqual(severities(allow("*", resource="arn:aws:s3:::b")), [])
        self.assertEqual(severities(allow("s3:Get*")), [])
        self.assertEqual(severities({"Effect": "Allow", "NotAction": "s3:*", "Resource": "*"}), [])
        self.assertEqual(list(tool.wildcard_findings({"Statement": allow("*")}))[0][0], "critical")

    def test_exit_code_follows_fail_on(self):
        args = ["--credential-report", str(HERE / "fixtures/credential-report.csv"),
                "--authorization-details", str(HERE / "fixtures/authorization-details.json"),
                "--now", "2026-10-14T00:00:00+00:00", "--format", "json"]
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(tool.main(args + ["--fail-on", "critical"]), 1)


class RoleTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with open(HERE / "fixtures/credential-report.csv", newline="", encoding="utf-8") as handle:
            rows = list(csv.DictReader(handle))
        authz = json.loads((HERE / "fixtures/authorization-details.json").read_text(encoding="utf-8"))
        cls.roles = {r["name"]: r for r in tool.analyse(rows, authz, NOW) if r["kind"] == "role"}

    def test_inline_wildcard_on_a_role_is_critical(self):
        self.assertEqual(self.roles["ci-deployer"]["top_severity"], "critical")

    def test_administrator_access_on_a_role_is_critical(self):
        self.assertEqual(self.roles["ops-admin"]["top_severity"], "critical")

    def test_iam_wildcard_is_high_and_other_service_wildcard_is_medium(self):
        severities = [f["severity"] for f in self.roles["iam-manager"]["findings"]]
        self.assertEqual(severities, ["high", "medium"])

    def test_iam_full_access_is_high(self):
        self.assertEqual(self.roles["iam-full"]["top_severity"], "high")

    def test_service_linked_scoped_and_lookalike_roles_are_not_reported(self):
        for name in ("AWSServiceRoleForExample", "read-only", "lookalike"):
            self.assertNotIn(name, self.roles)


class InputHandlingTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.report = str(HERE / "fixtures/credential-report.csv")
        self.authz = str(HERE / "fixtures/authorization-details.json")

    def write(self, name, text):
        path = Path(self.tmp.name) / name
        path.write_text(text, encoding="utf-8")
        return str(path)

    def run_main(self, report=None, authz=None, extra=()):
        args = ["--credential-report", report or self.report,
                "--authorization-details", authz or self.authz, *extra]
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = tool.main(args)
        return code, out.getvalue(), err.getvalue()

    def test_time_without_offset_is_read_as_utc(self):
        code, _, err = self.run_main(extra=["--now", "2026-10-14"])
        self.assertEqual((code, err), (1, ""))

    def test_unreadable_now_value_exits_2(self):
        code, _, err = self.run_main(extra=["--now", "yesterday"])
        self.assertEqual(code, 2)
        self.assertIn("unreadable time value", err)

    def test_missing_file_exits_2_without_traceback(self):
        code, _, err = self.run_main(report=str(Path(self.tmp.name) / "nope.csv"))
        self.assertEqual(code, 2)
        self.assertTrue(err.startswith("error: cannot read"))

    def test_malformed_json_exits_2(self):
        code, _, err = self.run_main(authz=self.write("bad.json", "{"))
        self.assertEqual(code, 2)
        self.assertIn("not valid JSON", err)

    def test_json_of_the_wrong_shape_exits_2(self):
        code, _, err = self.run_main(authz=self.write("other.json", '{"Roles": []}'))
        self.assertEqual(code, 2)
        self.assertIn("no UserDetailList", err)

    def test_csv_with_missing_columns_exits_2(self):
        code, _, err = self.run_main(report=self.write("bad.csv", "user,arn\nbob,x\n"))
        self.assertEqual(code, 2)
        self.assertIn("missing columns", err)
        self.assertIn("password_enabled", err)

    def test_bad_date_in_report_exits_2(self):
        text = Path(self.report).read_text(encoding="utf-8").replace("2023-03-01T00:00:00+00:00", "not-a-date")
        code, _, err = self.run_main(report=self.write("dates.csv", text))
        self.assertEqual(code, 2)
        self.assertIn("unreadable time value", err)


class RootAccountTest(unittest.TestCase):
    def root_row(self, **changes):
        with open(HERE / "fixtures/credential-report.csv", newline="", encoding="utf-8") as handle:
            row = next(r for r in csv.DictReader(handle) if r["user"] == "<root_account>")
        return {**row, **changes}

    def analyse_root(self, row):
        results = tool.analyse([row], {"UserDetailList": []}, NOW)
        return {r["name"]: r for r in results}.get("<root_account>")

    def test_clean_root_is_not_reported(self):
        self.assertIsNone(self.analyse_root(self.root_row()))

    def test_active_root_access_key_is_critical(self):
        result = self.analyse_root(self.root_row(access_key_1_active="true"))
        self.assertEqual(result["top_severity"], "critical")
        self.assertIn("active access key", result["findings"][0]["detail"])

    def test_second_root_access_key_is_critical(self):
        result = self.analyse_root(self.root_row(access_key_2_active="true"))
        self.assertEqual(result["top_severity"], "critical")

    def test_root_without_mfa_is_high(self):
        result = self.analyse_root(self.root_row(mfa_active="false"))
        self.assertEqual(result["top_severity"], "high")
        self.assertIn("no MFA", result["findings"][0]["detail"])


if __name__ == "__main__":
    unittest.main()
