"""Unit tests for audit_report_accepted.py, using the real npm 11 output in tests/fixtures."""

from __future__ import annotations

import contextlib
import io
import json
import tempfile
import unittest
from datetime import date
from pathlib import Path

import audit_report_accepted as acc

ar = acc.ar  # audit_report_accepted puts the parent folder on sys.path
FIXTURE = Path(__file__).resolve().parents[2] / "tests" / "fixtures" / "custom-app"
REQUEST_SSRF = "GHSA-p8p7-x288-28g6"
MINIMIST = ("GHSA-vh95-rmgr-6w4m", "GHSA-xvch-5gv4-984h")
TODAY = date(2026, 10, 20)


def entry(advisory: str = REQUEST_SSRF, package: str = "request", **extra: object) -> dict:
    base = {
        "advisory": advisory,
        "package": package,
        "reason": "no patch exists",
        "controls": ["egress allowlist"],
        "owner": "team-a",
        "expires": "2027-01-14",
    }
    base.update(extra)
    return base


def rows() -> list[dict]:
    data = json.loads((FIXTURE / "audit-npm11.json").read_text(encoding="utf-8"))
    return ar.build_rows(data, {}, {})


class ValidationTests(unittest.TestCase):
    def load(self, content: object) -> list[dict]:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "accepted.json"
            path.write_text(json.dumps(content), encoding="utf-8")
            return acc.load_accepted(str(path))

    def problems(self, content: object) -> str:
        with self.assertRaises(ValueError) as ctx:
            self.load(content)
        return str(ctx.exception)

    def test_valid_file(self) -> None:
        self.assertEqual(len(self.load({"accepted": [entry(), entry(MINIMIST[0], "minimist")]})), 2)

    def test_empty_list_is_valid(self) -> None:
        self.assertEqual(self.load({"accepted": []}), [])

    def test_wrong_top_level(self) -> None:
        for content in ([], {}, {"accepted": "x"}):
            with self.subTest(content=content):
                self.assertIn('"accepted" list', self.problems(content))

    def test_required_fields(self) -> None:
        for key in acc.REQUIRED:
            with self.subTest(key=key):
                item = entry()
                del item[key]
                self.assertIn(f"{key!r} is required", self.problems({"accepted": [item]}))

    def test_empty_controls_are_rejected(self) -> None:
        self.assertIn("'controls' is required", self.problems({"accepted": [entry(controls=[])]}))
        self.assertIn("non-empty strings", self.problems({"accepted": [entry(controls=[""])]}))
        self.assertIn("non-empty strings", self.problems({"accepted": [entry(controls="x")]}))

    def test_bad_dates_and_ids(self) -> None:
        self.assertIn("not a date", self.problems({"accepted": [entry(expires="soon")]}))
        self.assertIn("not a date", self.problems({"accepted": [entry(accepted_on="13/13")]}))
        self.assertIn("not a GHSA id", self.problems({"accepted": [entry(advisory="CVE-2020-1")]}))

    def test_unknown_field_and_duplicates(self) -> None:
        self.assertIn("unknown field 'expiry'", self.problems({"accepted": [entry(expiry="x")]}))
        self.assertIn("listed twice", self.problems({"accepted": [entry(), entry()]}))

    def test_all_problems_are_listed_together(self) -> None:
        text = self.problems({"accepted": [entry(expires="x"), entry(MINIMIST[0], reason="")]})
        self.assertIn("accepted[1]", text)
        self.assertIn("accepted[2]", text)


class MatchingTests(unittest.TestCase):
    def test_matches_advisory_and_package(self) -> None:
        row = [r for r in rows() if r["advisory_id"] == REQUEST_SSRF][0]
        self.assertTrue(acc.matches(entry(), row))
        self.assertTrue(acc.matches(entry(REQUEST_SSRF.lower()), row))
        self.assertFalse(acc.matches(entry(package="other"), row))
        self.assertFalse(acc.matches(entry(MINIMIST[0]), row))

    def test_version_limits_the_acceptance_when_the_version_is_known(self) -> None:
        row = dict([r for r in rows() if r["advisory_id"] == REQUEST_SSRF][0])
        row["installed_versions"] = ["2.88.2"]
        self.assertTrue(acc.matches(entry(version="2.88.2"), row))
        self.assertFalse(acc.matches(entry(version="2.0.0"), row))
        row["installed_versions"] = []
        self.assertTrue(acc.matches(entry(version="2.0.0"), row))

    def test_transitive_rows_never_match(self) -> None:
        row = [r for r in rows() if r["kind"] == "transitive"][0]
        self.assertFalse(acc.matches(entry(package=row["package"]), row))


class SplitTests(unittest.TestCase):
    def test_no_entries_changes_nothing(self) -> None:
        for name in ("audit-npm11.json", "audit-npm6.json"):
            data = json.loads((FIXTURE / name).read_text(encoding="utf-8"))
            before = ar.build_rows(data, {}, {})
            with self.subTest(name=name):
                self.assertEqual(acc.split_rows(before, [], TODAY)[0], before)

    def test_accepted_finding_is_removed(self) -> None:
        remaining, accepted, expired, unused = acc.split_rows(rows(), [entry()], TODAY)
        self.assertEqual(len(accepted), 1)
        self.assertEqual((expired, unused), ([], []))
        self.assertNotIn(REQUEST_SSRF, [r["advisory_id"] for r in remaining])
        self.assertEqual(len(remaining), len(rows()) - 1)

    def test_expiry_day_is_still_valid_and_the_next_day_is_not(self) -> None:
        item = entry(expires="2026-10-20")
        self.assertEqual(len(acc.split_rows(rows(), [item], date(2026, 10, 20))[1]), 1)
        remaining, accepted, expired, _ = acc.split_rows(rows(), [item], date(2026, 10, 21))
        self.assertEqual((len(accepted), len(expired)), (0, 1))
        self.assertIn(REQUEST_SSRF, [r["advisory_id"] for r in remaining])

    def test_entry_without_a_finding_is_unused(self) -> None:
        stale = entry("GHSA-aaaa-bbbb-cccc", "gone")
        remaining, accepted, _, unused = acc.split_rows(rows(), [stale], TODAY)
        self.assertEqual((len(remaining), len(accepted)), (len(rows()), 0))
        self.assertEqual(unused, [stale])

    def test_dependents_of_fully_accepted_packages_are_dropped(self) -> None:
        both = [entry(a, "minimist") for a in MINIMIST]
        remaining, accepted, _, _ = acc.split_rows(rows(), both, TODAY)
        self.assertEqual(len(accepted), 2)
        names = {(r["package"], r["kind"]) for r in remaining}
        self.assertNotIn(("minimist", "advisory"), names)
        self.assertNotIn(("mkdirp", "transitive"), names)
        self.assertIn(("mocha", "transitive"), names)

    def test_dependents_stay_when_one_advisory_is_still_open(self) -> None:
        remaining, _, _, _ = acc.split_rows(rows(), [entry(MINIMIST[0], "minimist")], TODAY)
        self.assertIn(("mkdirp", "transitive"), {(r["package"], r["kind"]) for r in remaining})


class CliTests(unittest.TestCase):
    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.dir = Path(tmp.name)

    def run_cli(self, entries: list[dict], *extra: str) -> tuple[int, str, str]:
        accepted = self.dir / "accepted.json"
        accepted.write_text(json.dumps({"accepted": entries}), encoding="utf-8")
        args = [
            str(FIXTURE / "audit-npm11.json"),
            "--accepted",
            str(accepted),
            "--accepted-out",
            str(self.dir / "acc-out.json"),
            "--json-out",
            str(self.dir / "out.json"),
            "--csv-out",
            str(self.dir / "out.csv"),
            "--today",
            "2026-10-20",
            *extra,
        ]
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = acc.main(args)
        return code, out.getvalue(), err.getvalue()

    def read(self, name: str) -> dict:
        return json.loads((self.dir / name).read_text(encoding="utf-8"))

    def test_accepted_finding_leaves_the_report_and_is_listed(self) -> None:
        code, out, _ = self.run_cli([entry()])
        self.assertEqual(code, 0)
        self.assertIn("1 findings not reported", out)
        ids = [r["advisory_id"] for r in self.read("out.json")["findings"]]
        self.assertNotIn(REQUEST_SSRF, ids)
        listed = self.read("acc-out.json")["accepted"]
        self.assertEqual(listed[0]["finding"]["advisory_id"], REQUEST_SSRF)
        self.assertEqual(listed[0]["acceptance"]["owner"], "team-a")
        self.assertEqual(self.read("out.json")["meta"]["accepted_count"], 1)

    def test_gate_ignores_accepted_findings(self) -> None:
        every = [r for r in rows() if r["kind"] == "advisory"]
        entries = [entry(r["advisory_id"], r["package"]) for r in every]
        self.assertEqual(self.run_cli([], "--fail-on", "low")[0], 1)
        code, _, _ = self.run_cli(entries, "--fail-on", "low")
        self.assertEqual(code, 0)

    def test_expired_acceptance_fails_the_gate_again(self) -> None:
        every = [r for r in rows() if r["kind"] == "advisory"]
        entries = [entry(r["advisory_id"], r["package"], expires="2026-10-01") for r in every]
        code, _, err = self.run_cli(entries, "--fail-on", "low")
        self.assertEqual(code, 1)
        self.assertIn("acceptance expired on 2026-10-01", err)
        self.assertEqual(len(self.read("acc-out.json")["expired"]), len(every))

    def test_warnings_for_unused_and_soon_to_expire(self) -> None:
        stale = entry("GHSA-aaaa-bbbb-cccc", "gone")
        soon = entry(expires="2026-11-01")
        _, _, err = self.run_cli([stale, soon], "--warn-days", "30")
        self.assertIn("matches no finding, remove it: GHSA-aaaa-bbbb-cccc gone", err)
        self.assertIn("acceptance expires on 2026-11-01", err)
        _, _, quiet = self.run_cli([soon], "--warn-days", "5")
        self.assertNotIn("expires on", quiet)

    def test_min_severity_does_not_make_entries_look_unused(self) -> None:
        _, _, err = self.run_cli([entry()], "--min-severity", "critical")
        self.assertNotIn("matches no finding", err)

    def test_bad_accepted_file_returns_2(self) -> None:
        code, _, err = self.run_cli([entry(controls=[])])
        self.assertEqual(code, 2)
        self.assertIn("accepted file is not valid", err)

    def test_bad_today_returns_2(self) -> None:
        code, _, err = self.run_cli([entry()], "--today", "tomorrow")
        self.assertEqual(code, 2)
        self.assertIn("--today", err)

    def test_accepted_file_is_required(self) -> None:
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as ctx:
            acc.main([str(FIXTURE / "audit-npm11.json")])
        self.assertEqual(ctx.exception.code, 2)

    def test_the_example_file_is_valid(self) -> None:
        example = Path(__file__).resolve().parents[1] / "accepted-risks.example.json"
        self.assertEqual(len(acc.load_accepted(str(example))), 1)


if __name__ == "__main__":
    unittest.main()
