"""Unit tests for compare_scanners.py."""

from __future__ import annotations

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

import compare_scanners as cs

FIXTURES = Path(__file__).parent / "fixtures"


class CompareTests(unittest.TestCase):
    def run_main(self, *args: str) -> tuple[int, str, str]:
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = cs.main(["compare_scanners.py", *args])
        return code, out.getvalue(), err.getvalue()

    def test_npm_ids_lists_advisories(self) -> None:
        found = cs.npm_ids(str(FIXTURES / "audit_v7.json"))
        self.assertEqual(found["ghsa-aaaa-bbbb-cccc"], ("alpha", "critical"))
        self.assertEqual(len(found), 3)

    def test_trivy_ids_reads_vendor_ids_and_reference_links(self) -> None:
        found = cs.trivy_ids(str(FIXTURES / "trivy.json"))
        self.assertEqual(found["ghsa-aaaa-bbbb-cccc"][2], "CVE-2099-0001")
        self.assertEqual(found["ghsa-gggg-hhhh-iiii"][2], "CVE-2099-0002")

    def test_report_lists_each_side_only_advisories(self) -> None:
        code, out, _ = self.run_main(str(FIXTURES / "audit_v7.json"), str(FIXTURES / "trivy.json"))
        self.assertEqual(code, 0)
        self.assertIn("in both: 2", out)
        self.assertIn("ghsa-dddd-eeee-ffff alpha moderate", out.split("only in npm audit:")[1])

    def test_severity_difference_is_printed(self) -> None:
        trivy = {
            "Results": [
                {
                    "Vulnerabilities": [
                        {
                            "VulnerabilityID": "CVE-2099-0001",
                            "VendorIDs": ["GHSA-aaaa-bbbb-cccc"],
                            "Severity": "MEDIUM",
                        }
                    ]
                }
            ]
        }
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "t.json"
            path.write_text(json.dumps(trivy), encoding="utf-8")
            _, out, _ = self.run_main(str(FIXTURES / "audit_v7.json"), str(path))
        self.assertIn("npm=critical trivy=moderate", out)

    def test_usage_and_bad_input_return_2(self) -> None:
        self.assertEqual(self.run_main()[0], 2)
        self.assertEqual(self.run_main("nope.json", str(FIXTURES / "trivy.json"))[0], 2)
        with tempfile.TemporaryDirectory() as tmp:
            bad = Path(tmp) / "bad.json"
            bad.write_text("[1]", encoding="utf-8")
            code, _, err = self.run_main(str(bad), str(FIXTURES / "trivy.json"))
        self.assertEqual(code, 2)
        self.assertIn("error", err)


if __name__ == "__main__":
    unittest.main()
