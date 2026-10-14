"""Unit tests for audit_report.py. Run: python3 -m unittest discover -s tests -t ."""

from __future__ import annotations

import contextlib
import csv
import io
import json
import tempfile
import unittest
import urllib.error
from pathlib import Path
from unittest import mock

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
        self.assertFalse(self.by_package("delta")[0]["fix_available"])

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
        cases = [
            ("MEDIUM", "moderate"),
            ("High", "high"),
            (" low ", "low"),
            (None, ""),
            ("", ""),
            ("weird", ""),
        ]
        for raw, expected in cases:
            with self.subTest(raw=raw):
                self.assertEqual(ar.normalise_severity(raw), expected)

    def test_resolve_severity(self) -> None:
        cases = [
            (("high", "low"), "high"),
            (("weird", "high"), "high"),
            (("", "moderate"), "moderate"),
            ((None, None), "info"),
            (("weird", "also weird"), "critical"),
            (("weird",), "critical"),
        ]
        for candidates, expected in cases:
            with self.subTest(candidates=candidates):
                self.assertEqual(ar.resolve_severity(*candidates), expected)

    def test_unknown_severity_is_reported(self) -> None:
        warnings: list[str] = []
        ar.resolve_severity("weird", "high", warnings=warnings)
        self.assertEqual(warnings, ["unknown severity 'weird'"])

    def test_summary_counts_packages_once(self) -> None:
        rows = ar.build_rows(load("audit_v7.json"), {}, {})
        summary = ar.summarise(rows)
        self.assertEqual(summary["packages_total"], 4)
        self.assertEqual(summary["packages_by_severity"]["critical"], 1)
        self.assertEqual(summary["advisories_by_severity"]["critical"], 1)
        self.assertEqual(summary["advisories_by_severity"]["moderate"], 1)
        self.assertEqual(summary["packages_fixable_with_major_bump"], 2)
        self.assertEqual(summary["packages_fixable_without_major_bump"], 1)
        self.assertEqual(summary["packages_without_fix"], 1)


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


def one_advisory(source: int, severity: str = "high", **extra: object) -> dict:
    advisory = {"source": source, "title": f"t{source}", "severity": severity, "url": "u"}
    advisory.update(extra)
    return advisory


class RowDetailTests(unittest.TestCase):
    def test_direct_flag(self) -> None:
        rows = ar.build_rows(load("audit_v7.json"), {}, {})
        direct = {r["package"]: r["direct"] for r in rows}
        self.assertTrue(direct["alpha"])
        self.assertFalse(direct["beta"])

    def test_transitive_row_keeps_package_severity(self) -> None:
        rows = ar.build_rows(load("audit_v7.json"), {}, {})
        beta = [r for r in rows if r["package"] == "beta" and r["kind"] == "transitive"][0]
        self.assertEqual(beta["severity"], "high")

    def test_repeated_source_gives_one_row(self) -> None:
        report = {"vulnerabilities": {"a": {"via": [one_advisory(5), one_advisory(5)]}}}
        self.assertEqual(len(ar.build_rows(report, {}, {})), 1)

    def test_same_advisory_in_two_packages_is_counted_per_package(self) -> None:
        report = {
            "vulnerabilities": {
                "a": {"via": [one_advisory(5)]},
                "b": {"via": [one_advisory(5)]},
            }
        }
        summary = ar.summarise(ar.build_rows(report, {}, {}))
        self.assertEqual(summary["advisories_by_severity"]["high"], 2)
        self.assertEqual(summary["packages_total"], 2)

    def test_rows_are_sorted_by_package_whatever_the_input_order(self) -> None:
        report = {"vulnerabilities": {n: {"via": [one_advisory(i)]} for i, n in enumerate("cab")}}
        rows = ar.build_rows(report, {}, {})
        self.assertEqual([r["package"] for r in rows], ["a", "b", "c"])

    def test_installed_versions_are_unique(self) -> None:
        lock = {"packages": {"n/a": {"version": "1.0.0"}, "n/b/a": {"version": "1.0.0"}}}
        self.assertEqual(ar.installed_versions(["n/a", "n/b/a"], lock), ["1.0.0"])

    def test_unknown_advisory_severity_uses_package_severity(self) -> None:
        report = {"vulnerabilities": {"a": {"severity": "high", "via": [one_advisory(1, "weird")]}}}
        warnings: list[str] = []
        rows = ar.build_rows(report, {}, {}, warnings)
        self.assertEqual(rows[0]["severity"], "high")
        self.assertEqual(warnings, ["unknown severity 'weird'"])

    def test_v6_null_finding_does_not_crash(self) -> None:
        report = {"advisories": {"1": {"module_name": "x", "severity": "high", "findings": [None]}}}
        self.assertEqual(ar.build_rows(report, {}, {})[0]["package"], "x")


class EpssTests(unittest.TestCase):
    RESPONSE = {
        "data": [
            {"cve": "CVE-2099-0001", "epss": "0.5", "percentile": "0.9", "date": "2099-01-01"},
            {"cve": "cve-2099-0002", "epss": "0.0004", "percentile": "0.1", "date": "2099-01-01"},
            {"cve": "CVE-2099-0003", "epss": "bad", "percentile": "0.1"},
            {"epss": "0.1"},
            "junk",
        ]
    }

    def test_parse_skips_bad_entries_and_upper_cases_ids(self) -> None:
        mapping = ar.parse_epss(self.RESPONSE)
        self.assertEqual(sorted(mapping), ["CVE-2099-0001", "CVE-2099-0002"])
        self.assertEqual(mapping["CVE-2099-0001"]["epss"], 0.5)

    def test_parse_handles_non_objects(self) -> None:
        self.assertEqual(ar.parse_epss([]), {})
        self.assertEqual(ar.parse_epss({"data": None}), {})

    def test_apply_uses_the_highest_score_of_several_cves(self) -> None:
        rows = [{"cve": "CVE-2099-0002, CVE-2099-0001", "epss": "", "epss_percentile": ""}]
        self.assertEqual(ar.apply_epss(rows, ar.parse_epss(self.RESPONSE)), 1)
        self.assertEqual(rows[0]["epss"], 0.5)
        self.assertEqual(rows[0]["epss_percentile"], 0.9)

    def test_below_epss_keeps_unknown_scores(self) -> None:
        self.assertTrue(ar.below_epss({"epss": 0.0004}, 0.001))
        self.assertFalse(ar.below_epss({"epss": 0.001}, 0.001))
        self.assertFalse(ar.below_epss({"epss": ""}, 0.001))

    def test_fetch_batches_requests(self) -> None:
        calls = []

        def fake_urlopen(url: str, timeout: float) -> io.BytesIO:
            calls.append(url)
            return io.BytesIO(json.dumps(self.RESPONSE).encode())

        cves = [f"CVE-2099-{i:04d}" for i in range(ar.EPSS_BATCH + 1)]
        with mock.patch("urllib.request.urlopen", fake_urlopen):
            mapping = ar.fetch_epss(cves)
        self.assertEqual(len(calls), 2)
        self.assertEqual(calls[0].count("CVE-"), ar.EPSS_BATCH)
        self.assertEqual(calls[1].count("CVE-"), 1)
        self.assertTrue(calls[0].startswith(ar.EPSS_API + "?cve=CVE-2099-0000,CVE-2099-0001"))
        self.assertIn("CVE-2099-0001", mapping)

    def test_fetch_failure_raises_value_error(self) -> None:
        with mock.patch("urllib.request.urlopen", side_effect=urllib.error.URLError("down")):
            with self.assertRaises(ValueError):
                ar.fetch_epss(["CVE-2099-0001"])


class CsvTests(unittest.TestCase):
    def test_formula_cells_are_neutralised(self) -> None:
        for raw in ("=1+1", "+cmd", "-2", "@SUM(A1)", "\tx", "\rx"):
            with self.subTest(raw=raw):
                self.assertEqual(ar.neutralise_cell(raw), "'" + raw)

    def test_other_cells_are_untouched(self) -> None:
        for raw in ("<5.13.15", ">=4.17.11", "a-b", "", 9.8, True):
            with self.subTest(raw=raw):
                self.assertEqual(ar.neutralise_cell(raw), raw)


class CliExtraTests(unittest.TestCase):
    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.dir = Path(tmp.name)
        self.json_out = str(self.dir / "out.json")
        self.csv_out = str(self.dir / "out.csv")

    def run_cli(self, *args: str) -> tuple[int, str, str]:
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = ar.main([*args, "--json-out", self.json_out, "--csv-out", self.csv_out])
        return code, out.getvalue(), err.getvalue()

    def write(self, name: str, content: str | bytes) -> str:
        path = self.dir / name
        if isinstance(content, bytes):
            path.write_bytes(content)
        else:
            path.write_text(content, encoding="utf-8")
        return str(path)

    def test_unknown_severity_cannot_pass_the_gate(self) -> None:
        report = {"vulnerabilities": {"a": {"via": [one_advisory(1, "weird")]}}}
        path = self.write("unk.json", json.dumps(report))
        code, _, err = self.run_cli(path, "--fail-on", "high")
        self.assertEqual(code, 1)
        self.assertIn("unknown severity", err)

    def test_empty_file_returns_2(self) -> None:
        self.assertEqual(self.run_cli(self.write("e.json", ""))[0], 2)

    def test_non_utf8_returns_2(self) -> None:
        self.assertEqual(self.run_cli(self.write("n.json", b"\xff\xfe{}"))[0], 2)

    def test_malformed_entry_returns_2(self) -> None:
        path = self.write("m.json", '{"vulnerabilities": {"a": ["x"]}}')
        self.assertEqual(self.run_cli(path)[0], 2)

    def test_trivy_file_of_wrong_shape_returns_2(self) -> None:
        path = self.write("e.json", "{}")
        self.assertEqual(self.run_cli(path, "--trivy", self.write("t.json", "[1]"))[0], 2)

    def test_unwritable_output_returns_2(self) -> None:
        path = self.write("e.json", "{}")
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = ar.main([path, "--json-out", str(self.dir / "no" / "x.json")])
        self.assertEqual(code, 2)

    def test_stdin_input(self) -> None:
        with mock.patch("sys.stdin", io.StringIO('{"vulnerabilities": {}}')):
            code, out, _ = self.run_cli("-")
        self.assertEqual(code, 0)
        self.assertIn("Vulnerable packages: 0", out)
        data = json.loads(Path(self.json_out).read_text(encoding="utf-8"))
        self.assertEqual(data["meta"]["input"], "stdin")

    def test_json_has_meta_and_csv_uses_unix_newlines(self) -> None:
        self.run_cli(str(FIXTURES / "audit_v7.json"))
        data = json.loads(Path(self.json_out).read_text(encoding="utf-8"))
        self.assertEqual(data["meta"]["tool"], "audit_report.py")
        self.assertEqual(data["meta"]["input"], "audit_v7.json")
        self.assertEqual(data["meta"]["audit_report_version"], 2)
        self.assertRegex(data["meta"]["generated_at"], r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$")
        self.assertNotIn(b"\r", Path(self.csv_out).read_bytes())

    def test_csv_cells_are_neutralised_in_the_file(self) -> None:
        report = {"vulnerabilities": {"a": {"via": [one_advisory(1, title="=HYPERLINK()")]}}}
        self.run_cli(self.write("f.json", json.dumps(report)))
        with open(self.csv_out, encoding="utf-8", newline="") as handle:
            self.assertEqual(next(csv.DictReader(handle))["title"], "'=HYPERLINK()")

    def epss_inputs(self) -> list[str]:
        trivy = self.write("trivy.json", (FIXTURES / "trivy.json").read_text(encoding="utf-8"))
        epss = {
            "data": [
                {"cve": "CVE-2099-0001", "epss": "0.5", "percentile": "0.9", "date": "2099-01-01"},
                {
                    "cve": "CVE-2099-0002",
                    "epss": "0.0004",
                    "percentile": "0.1",
                    "date": "2099-01-01",
                },
            ]
        }
        return [
            str(FIXTURES / "audit_v7.json"),
            "--trivy",
            trivy,
            "--epss",
            self.write("epss.json", json.dumps(epss)),
        ]

    def test_epss_columns_are_filled(self) -> None:
        code, out, _ = self.run_cli(*self.epss_inputs())
        self.assertEqual(code, 0)
        self.assertIn("Advisories with an EPSS score: 2", out)
        data = json.loads(Path(self.json_out).read_text(encoding="utf-8"))
        scores = {r["advisory_id"]: r["epss"] for r in data["findings"] if r["advisory_id"]}
        self.assertEqual(scores["GHSA-aaaa-bbbb-cccc"], 0.5)
        self.assertEqual(scores["GHSA-gggg-hhhh-iiii"], 0.0004)
        self.assertEqual(scores["GHSA-dddd-eeee-ffff"], "")
        self.assertEqual(data["meta"]["epss_date"], "2099-01-01")

    def test_min_epss_drops_low_scores_and_keeps_unknown(self) -> None:
        self.run_cli(*self.epss_inputs(), "--min-epss", "0.001")
        data = json.loads(Path(self.json_out).read_text(encoding="utf-8"))
        ids = {r["advisory_id"] for r in data["findings"] if r["advisory_id"]}
        self.assertIn("GHSA-aaaa-bbbb-cccc", ids)
        self.assertIn("GHSA-dddd-eeee-ffff", ids)
        self.assertNotIn("GHSA-gggg-hhhh-iiii", ids)

    def test_min_epss_can_clear_the_gate(self) -> None:
        report = {
            "vulnerabilities": {
                "a": {"via": [one_advisory(1, "critical", url="x/GHSA-aaaa-bbbb-cccc")]}
            }
        }
        trivy = {
            "Results": [
                {
                    "Vulnerabilities": [
                        {"VulnerabilityID": "CVE-2099-0002", "VendorIDs": ["GHSA-aaaa-bbbb-cccc"]}
                    ]
                }
            ]
        }
        epss = {"data": [{"cve": "CVE-2099-0002", "epss": "0.0004", "percentile": "0.1"}]}
        args = [self.write("r.json", json.dumps(report)), "--fail-on", "critical"]
        args += ["--trivy", self.write("t.json", json.dumps(trivy))]
        args += ["--epss", self.write("e.json", json.dumps(epss))]
        self.assertEqual(self.run_cli(*args)[0], 1)
        self.assertEqual(self.run_cli(*args, "--min-epss", "0.001")[0], 0)

    def test_min_epss_needs_a_source(self) -> None:
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as ctx:
            ar.parse_args(["x.json", "--min-epss", "0.1"])
        self.assertEqual(ctx.exception.code, 2)

    def test_min_epss_range_is_checked(self) -> None:
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as ctx:
            ar.parse_args(["x.json", "--epss", "e.json", "--min-epss", "5"])
        self.assertEqual(ctx.exception.code, 2)

    def test_epss_without_cve_ids_warns_and_skips_the_lookup(self) -> None:
        with mock.patch("urllib.request.urlopen", side_effect=AssertionError("no call")):
            code, _, err = self.run_cli(str(FIXTURES / "audit_v7.json"), "--epss-fetch")
        self.assertEqual(code, 0)
        self.assertIn("pass --trivy", err)

    def test_epss_on_a_clean_report_does_not_warn(self) -> None:
        args = [
            self.write("e.json", '{"vulnerabilities": {}}'),
            "--epss",
            self.write("s.json", "{}"),
        ]
        code, _, err = self.run_cli(*args)
        self.assertEqual(code, 0)
        self.assertEqual(err, "")

    def test_epss_with_cve_ids_but_no_match_does_not_warn(self) -> None:
        trivy = self.write("trivy.json", (FIXTURES / "trivy.json").read_text(encoding="utf-8"))
        args = [
            str(FIXTURES / "audit_v7.json"),
            "--trivy",
            trivy,
            "--epss",
            self.write("s.json", "{}"),
        ]
        code, _, err = self.run_cli(*args)
        self.assertEqual(code, 0)
        self.assertEqual(err, "")

    def test_epss_fetch_failure_returns_2(self) -> None:
        trivy = self.write("trivy.json", (FIXTURES / "trivy.json").read_text(encoding="utf-8"))
        args = [str(FIXTURES / "audit_v7.json"), "--trivy", trivy, "--epss-fetch"]
        with mock.patch("urllib.request.urlopen", side_effect=urllib.error.URLError("down")):
            code, _, err = self.run_cli(*args)
        self.assertEqual(code, 2)
        self.assertIn("EPSS lookup failed", err)


if __name__ == "__main__":
    unittest.main()
