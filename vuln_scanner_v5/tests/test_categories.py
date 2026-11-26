"""Python interpreter vs. Python libraries: categories, guard and scan filter."""
import datetime as dt
import json
import os
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from vulnscan.matcher import assess_nvd, text_scope  # noqa: E402
from vulnscan.models import Component, derive_category  # noqa: E402
from vulnscan.scanner import ScanOptions, Scanner  # noqa: E402

PY = Component(name="Python", version="3.8.10", vendor="Python Software Foundation", keywords=["CPython"],
               aliases=["python3"], cpe=["cpe:2.3:a:python:python:3.8.10:*:*:*:*:*:*:*"],
               projects=["HIL"], id="py")
FLASK = Component(name="Flask", version="2.0.1", type="library", purl="pkg:pypi/flask@2.0.1",
                  projects=["HIL"], id="flask")
BASH = Component(name="Bash", version="5.1", cpe=["cpe:2.3:a:gnu:bash:5.1:*:*:*:*:*:*:*"], id="bash")
GIT = Component(name="Git", version="2.39.2", vendor="Git project", keywords=["Git"],
                cpe=["cpe:2.3:a:git-scm:git:2.39.2:*:*:*:*:*:*:*"], id="git")


def nvd(cve_id, desc, configurations=None, status="Awaiting Analysis"):
    return {"id": cve_id, "description": desc, "published": "2025-03-01T10:00:00.000",
            "last_modified": "2025-03-05T10:00:00.000", "nvd_status": status, "cvss_score": 7.5,
            "cvss_vector": "", "cvss_version": "3.1", "severity_hint": "HIGH", "cwes": set(),
            "references": [], "configurations": configurations or [], "kev": False, "kev_date_added": ""}


class CategoryTests(unittest.TestCase):
    def test_derivation(self):
        self.assertEqual(derive_category(PY), "Core Component")
        self.assertEqual(derive_category(FLASK), "Package / Library")
        self.assertEqual(derive_category(Component(name="x", osv_ecosystem="PyPI", osv_package="x")),
                         "Package / Library")
        self.assertEqual(derive_category(BASH), "Software")
        self.assertEqual(derive_category(Component(name="MCU", type="hardware")), "Hardware")
        self.assertEqual(derive_category(Component(name="x", category="Safety lib", purl="pkg:pypi/x")),
                         "Safety lib")  # explicit wins

    def test_text_scope(self):
        sc = lambda d, c=PY: text_scope(d, c, [])[0]  # noqa: E731
        self.assertEqual(sc("Flask before 2.2.5 for Python allows cookie leakage"), "ecosystem")
        self.assertEqual(sc("A Python package on PyPI contains malicious code"), "ecosystem")
        self.assertEqual(sc("GitPython is a python library used to interact with Git repositories."), "ecosystem")
        self.assertEqual(sc("python-multipart is a streaming multipart parser for Python."), "ecosystem")
        self.assertEqual(sc("An issue in CPython: the tarfile module allows path traversal"), "core")
        self.assertEqual(sc("Python before 3.8.18 mishandles email address parsing"), "core")
        self.assertEqual(sc("The zipfile module in the Python standard library is slow"), "core")
        self.assertEqual(sc("Jenkins Git Plugin 5.2.1 and earlier allows XSS", GIT), "ecosystem")
        self.assertEqual(sc("GitPython is a python library used to interact with Git repositories.", GIT), "ecosystem")
        self.assertEqual(sc("Git is a revision control system. Prior to version 2.39.4 ...", GIT), "core")
        self.assertEqual(sc("Something unrelated"), "unknown")

    def test_interpreter_library_text_match_is_ecosystem(self):
        p = nvd("CVE-2025-1000", "The python3 bindings for the Flask framework for Python allow XSS.")
        a = assess_nvd(p, PY, "keyword", "python3", strict=False)
        self.assertEqual((a.applicability, a.scope), ("LOW", "ecosystem"))

    def test_interpreter_keeps_cpython_text_match(self):
        p = nvd("CVE-2025-1001", "CPython 3.8.10 (Python Software Foundation) has a flaw in the ssl module.")
        a = assess_nvd(p, PY, "keyword", "CPython", strict=True)
        self.assertEqual((a.applicability, a.scope), ("MEDIUM", "core"))

    def test_git_version_list(self):
        p = nvd("CVE-2025-1003", "Git is a revision control system. Prior to versions 2.43.1, 2.42.2, 2.41.1, "
                                 "2.40.2, and 2.39.4, a crafted repository can execute code during clone.")
        self.assertEqual(assess_nvd(p, GIT, "keyword", "Git").applicability, "MEDIUM")
        newer = Component(name="Git", version="2.43.1", vendor="Git project", keywords=["Git"],
                          cpe=["cpe:2.3:a:git-scm:git:2.43.1:*:*:*:*:*:*:*"])
        self.assertIsNone(assess_nvd(p, newer, "keyword", "Git").applicability)

    def test_cna_data(self):
        gitpython = [{"vendor": "gitpython-developers", "product": "GitPython",
                      "versions": [{"version": "< 3.1.41", "status": "affected"}]}]
        cpython = [{"vendor": "Python Software Foundation", "product": "CPython", "defaultStatus": "unaffected",
                    "versions": [{"version": "0", "lessThan": "3.9.21", "status": "affected"},
                                 {"version": "3.10.0", "lessThan": "3.10.16", "status": "affected"}]}]
        p = nvd("CVE-2024-22190", "GitPython ... runs git and bash.exe")
        a = assess_nvd(p, GIT, "keyword", "Git", cna=lambda i: gitpython)
        self.assertEqual((a.applicability, a.scope), ("LOW", "ecosystem"))
        a = assess_nvd(nvd("CVE-2024-9287", "venv in CPython"), PY, "keyword", "CPython", cna=lambda i: cpython)
        self.assertEqual((a.applicability, a.scope), ("HIGH", "core"))
        py313 = Component(name="Python", version="3.13.1", vendor="Python Software Foundation", keywords=["CPython"])
        a = assess_nvd(nvd("CVE-2024-9287", "venv in CPython"), py313, "keyword", "CPython", cna=lambda i: cpython)
        self.assertIsNone(a.applicability)

    def test_scope_option_in_scanner(self):
        def fake_search(self_, params, start, end, flags=(), date_field="published"):
            def raw(cid, desc):
                return {"id": cid, "published": "2025-03-01T00:00:00.000", "lastModified": "2025-03-02T00:00:00.000",
                        "vulnStatus": "Awaiting Analysis", "descriptions": [{"lang": "en", "value": desc}],
                        "metrics": {}, "configurations": [], "references": []}
            if params.get("keywordSearch") == "Git":
                return iter([raw("CVE-2025-4001", "Jenkins Git Plugin 5.2.1 and earlier allows XSS."),
                             raw("CVE-2025-4002", "In Git before 2.39.4 (Git project), clone can execute code.")])
            return iter([])
        with tempfile.TemporaryDirectory() as out:
            def run(scope, min_app="LOW"):
                opts = ScanOptions(start_date=dt.date(2025, 1, 1), end_date=dt.date(2025, 12, 31), output_dir=out,
                                   use_nvd_cpe=False, use_osv=False, use_kev=False, use_cve_org=False,
                                   scope=scope, min_applicability=min_app, formats=("json",))
                with mock.patch("vulnscan.sources.NVDClient.search_cves", fake_search):
                    return {v.id: v.applicability for v in Scanner([GIT], opts, log=lambda m: None).run().vulnerabilities}
            self.assertEqual(run("core"), {"CVE-2025-4002": "MEDIUM"})
            import time
            time.sleep(1.1)
            self.assertEqual(run("ecosystem"), {"CVE-2025-4002": "MEDIUM", "CVE-2025-4001": "LOW"})
            time.sleep(1.1)
            self.assertEqual(run("core", "ALL"), {"CVE-2025-4002": "MEDIUM", "CVE-2025-4001": "NOT APPLICABLE"})

    def test_nvd_confirmed_cpe_is_never_guarded(self):
        cfg = [{"nodes": [{"cpeMatch": [{"criteria": "cpe:2.3:a:python:python:*:*:*:*:*:*:*:*",
                                         "vulnerable": True, "versionEndExcluding": "3.8.18"}]}]}]
        p = nvd("CVE-2025-1002", "Issue for Python packages using the email module", cfg, "Analyzed")
        self.assertEqual(assess_nvd(p, PY, "cpe", "cpe:2.3:a:python:python", strict=True).applicability, "HIGH")

    def test_scan_category_filter(self):
        def fake_search(self_, params, start, end, flags=(), date_field="published"):
            if "python:python" in params.get("virtualMatchString", ""):
                cfg = [{"nodes": [{"cpeMatch": [{"criteria": "cpe:2.3:a:python:python:*:*:*:*:*:*:*:*",
                                                 "vulnerable": True, "versionEndExcluding": "3.8.18"}]}]}]
                return iter([{"id": "CVE-2025-2000", "sourceIdentifier": "x", "published": "2025-03-01T00:00:00.000",
                              "lastModified": "2025-03-02T00:00:00.000", "vulnStatus": "Analyzed",
                              "descriptions": [{"lang": "en", "value": "CPython tarfile flaw"}],
                              "metrics": {}, "weaknesses": [], "configurations": cfg, "references": []}])
            return iter([])

        def fake_osv(self_, purl="", ecosystem="", package="", version=""):
            return [{"id": "GHSA-flask-0001", "aliases": ["CVE-2025-3000"], "summary": "Flask cookie issue",
                     "details": "", "published": "2025-04-01T00:00:00Z", "modified": "2025-04-02T00:00:00Z",
                     "severity": [], "database_specific": {"severity": "HIGH"}, "references": []}]

        with tempfile.TemporaryDirectory() as out:
            def run(categories):
                opts = ScanOptions(start_date=dt.date(2025, 1, 1), end_date=dt.date(2025, 12, 31),
                                   output_dir=out, use_nvd_keywords=False, use_kev=False, use_cve_org=False,
                                   categories=categories, formats=("json",))
                with mock.patch("vulnscan.sources.NVDClient.search_cves", fake_search), \
                        mock.patch("vulnscan.sources.OSVClient.query", fake_osv):
                    return Scanner([PY, FLASK], opts, log=lambda m: None).run()

            both = run(())
            self.assertEqual({v.id for v in both.vulnerabilities}, {"CVE-2025-2000", "CVE-2025-3000"})
            with open(both.reports["json"], encoding="utf-8") as fh:
                data = json.load(fh)
            self.assertIn("_report_info", data[0])
            self.assertEqual(sorted(r["Type"] for r in data[1:]),
                             ["library / Package / Library", "software / Core Component"])

            import time
            time.sleep(1.1)
            interp = run(("Core Component",))
            self.assertEqual([v.id for v in interp.vulnerabilities], ["CVE-2025-2000"])
            self.assertEqual(interp.vulnerabilities[0].to_record()["categories"], ["Core Component"])

            time.sleep(1.1)
            libs = run(("package / library",))  # case-insensitive
            self.assertEqual([v.id for v in libs.vulnerabilities], ["CVE-2025-3000"])


class SourceErrorTests(unittest.TestCase):
    def test_nvd_failure_does_not_abort_scan(self):
        def boom(self_, params, start, end, flags=(), date_field="published"):
            raise RuntimeError("HTTP 522 for https://services.nvd.nist.gov/...: <html>")
        with tempfile.TemporaryDirectory() as out:
            opts = ScanOptions(start_date=dt.date(2025, 1, 1), end_date=dt.date(2025, 12, 31), output_dir=out,
                               use_osv=False, use_kev=False, use_cve_org=False, formats=("json",))
            with mock.patch("vulnscan.sources.NVDClient.search_cves", boom):
                r = Scanner([PY], opts, log=lambda m: None).run()
            self.assertEqual(r.vulnerabilities, [])
            self.assertGreaterEqual(r.stats["source_errors"], 1)
            self.assertTrue(os.path.exists(r.reports["json"]))


if __name__ == "__main__":
    unittest.main()
