"""Unit tests for audit_report.py. Run: python3 -m unittest discover -s tests -t ."""

from __future__ import annotations

import contextlib
import csv
import io
import json
import tempfile
import unittest
from pathlib import Path

import audit_report as ar

FIXTURES = Path(__file__).parent / "fixtures"


def load(name: str) -> dict:
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


class BuildRowsTests(unittest.TestCase):
    def setUp(self) -> None:
        self.lock = load("package-lock.json")
        self.rows = ar.build_rows(load("audit_v7.json"), self.lock, {})

    def by_package(self, name: str, kind: str = "advisory") -> list[dict]:
        return [r for r in self.rows if r["package"] == name and r["kind"] == kind]

    def test_one_row_per_advisory(self) -> None:
        self.assertEqual(len(self.by_package("alpha")), 2)

    def test_ghsa_id_and_cwe_are_parsed(self) -> None:
        row = self.by_package("alpha")[0]
        self.assertEqual(row["advisory_id"], "GHSA-aaaa-bbbb-cccc")
        self.assertEqual(row["cwe"], "CWE-1321")
        self.assertEqual(row["cvss_score"], 9.8)

    def test_fix_object_is_normalised(self) -> None:
        row = self.by_package("alpha")[0]
        self.assertTrue(row["fix_available"])
        self.assertTrue(row["fix_semver_major"])
        self.assertEqual(row["fix_version"], "2.1.0")

    def test_fix_true_means_no_major(self) -> None:
        row = self.by_package("beta", "transitive")[0]
        self.assertTrue(row["fix_available"])
        self.assertFalse(row["fix_semver_major"])
        self.assertEqual(row["via"], "alpha")

    def test_fix_false(self) -> None:
        self.assertFalse(self.by_package("gamma")[0]["fix_available"])

    def test_installed_versions_come_from_lockfile(self) -> None:
        self.assertEqual(self.by_package("alpha")[0]["installed_versions"], ["1.4.0"])
        self.assertEqual(self.by_package("gamma")[0]["installed_versions"], ["2.0.0", "2.9.1"])

    def test_missing_fields_do_not_crash(self) -> None:
        row = self.by_package("delta")[0]
        self.assertEqual(row["severity"], "low")
        self.assertEqual(row["advisory_id"], "")
        self.assertFalse(row["fix_available"])
        self.assertEqual(row["installed_versions"], [])

    def test_cve_map_is_applied(self) -> None:
        rows = ar.build_rows(load("audit_v7.json"), {}, {"ghsa-aaaa-bbbb-cccc": ["CVE-2099-0001"]})
        alpha = [r for r in rows if r["advisory_id"] == "GHSA-aaaa-bbbb-cccc"][0]
        self.assertEqual(alpha["cve"], "CVE-2099-0001")


class OtherInputTests(unittest.TestCase):
    def test_empty_report(self) -> None:
        self.assertEqual(ar.build_rows(load("audit_empty.json"), {}, {}), [])

    def test_unknown_object_is_empty(self) -> None:
        self.assertEqual(ar.build_rows({}, {}, {}), [])

    def test_null_vulnerabilities(self) -> None:
        self.assertEqual(ar.build_rows({"vulnerabilities": None}, {}, {}), [])

    def test_non_object_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            ar.build_rows([], {}, {})

    def test_error_report_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            ar.build_rows({"error": {"code": "ENOLOCK"}}, {}, {})

    def test_v6_fallback(self) -> None:
        rows = ar.build_rows(load("audit_v6.json"), {}, {})
        self.assertEqual([r["package"] for r in rows], ["oldpkg", "unpatched"])
        self.assertEqual(rows[0]["cve"], "CVE-2016-0001")
        self.assertTrue(rows[0]["fix_available"])
        self.assertFalse(rows[1]["fix_available"])
        self.assertEqual(rows[1]["severity"], "moderate")

    def test_trivy_fallback_reads_reference_links(self) -> None:
        mapping = ar.load_cve_map(str(FIXTURES / "trivy.json"))
        self.assertEqual(mapping["ghsa-aaaa-bbbb-cccc"], ["CVE-2099-0001"])
        self.assertEqual(mapping["ghsa-gggg-hhhh-iiii"], ["CVE-2099-0002"])


class SeverityTests(unittest.TestCase):
    def test_normalise(self) -> None:
        self.assertEqual(ar.normalise_severity("MEDIUM"), "moderate")
        self.assertEqual(ar.normalise_severity("High"), "high")
        self.assertEqual(ar.normalise_severity(None), "info")
        self.assertEqual(ar.normalise_severity("weird"), "info")

    def test_summary_counts_packages_once(self) -> None:
        rows = ar.build_rows(load("audit_v7.json"), {}, {})
        summary = ar.summarise(rows)
        self.assertEqual(summary["packages_total"], 4)
        self.assertEqual(summary["packages_by_severity"]["critical"], 1)
        self.assertEqual(summary["advisories_by_severity"]["critical"], 1)
        self.assertEqual(summary["advisories_by_severity"]["moderate"], 1)
        self.assertEqual(summary["packages_fixable_with_major_bump"], 1)
        self.assertEqual(summary["packages_fixable_without_major_bump"], 1)
        self.assertEqual(summary["packages_without_fix"], 2)


class CliTests(unittest.TestCase):
    def run_cli(self, *args: str) -> tuple[int, str, str]:
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = ar.main(list(args))
        return code, out.getvalue(), err.getvalue()

    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.json_out = str(Path(tmp.name) / "out.json")
        self.csv_out = str(Path(tmp.name) / "out.csv")
        self.base = [
            str(FIXTURES / "audit_v7.json"),
            "--json-out",
            self.json_out,
            "--csv-out",
            self.csv_out,
        ]

    def test_writes_json_and_csv(self) -> None:
        code, out, _ = self.run_cli(*self.base, "--lockfile", str(FIXTURES / "package-lock.json"))
        self.assertEqual(code, 0)
        self.assertIn("Vulnerable packages: 4", out)
        data = json.loads(Path(self.json_out).read_text(encoding="utf-8"))
        self.assertEqual(len(data["findings"]), 5)
        with open(self.csv_out, encoding="utf-8", newline="") as handle:
            rows = list(csv.DictReader(handle))
        self.assertEqual(len(rows), 5)
        self.assertEqual(tuple(rows[0]), ar.CSV_FIELDS)

    def test_min_severity_filters_output(self) -> None:
        code, _, _ = self.run_cli(*self.base, "--min-severity", "high")
        self.assertEqual(code, 0)
        data = json.loads(Path(self.json_out).read_text(encoding="utf-8"))
        self.assertTrue(data["findings"])
        self.assertTrue(all(r["severity"] in ("high", "critical") for r in data["findings"]))

    def test_fail_on_triggers(self) -> None:
        code, _, err = self.run_cli(*self.base, "--fail-on", "critical")
        self.assertEqual(code, 1)
        self.assertIn("Failing", err)

    def test_fail_on_respects_min_severity_filter(self) -> None:
        code, _, _ = self.run_cli(*self.base, "--min-severity", "low", "--fail-on", "critical")
        self.assertEqual(code, 1)

    def test_fail_on_passes_when_empty(self) -> None:
        args = [str(FIXTURES / "audit_empty.json"), "--json-out", self.json_out]
        code, _, _ = self.run_cli(*args, "--csv-out", self.csv_out, "--fail-on", "low")
        self.assertEqual(code, 0)

    def test_missing_file_returns_2(self) -> None:
        code, _, err = self.run_cli(str(FIXTURES / "nope.json"))
        self.assertEqual(code, 2)
        self.assertIn("error", err)

    def test_invalid_json_returns_2(self) -> None:
        bad = Path(self.json_out).with_name("bad.json")
        bad.write_text("{not json", encoding="utf-8")
        code, _, _ = self.run_cli(str(bad))
        self.assertEqual(code, 2)


if __name__ == "__main__":
    unittest.main()
