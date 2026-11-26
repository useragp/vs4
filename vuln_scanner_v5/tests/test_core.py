import datetime as dt
import json
import os
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from vulnscan.cvss import cvss3_base_score, severity_from_score  # noqa: E402
from vulnscan.matcher import assess_nvd  # noqa: E402
from vulnscan.models import Component, load_components  # noqa: E402
from vulnscan.scanner import ScanOptions, Scanner, VulnerabilityStore  # noqa: E402
from vulnscan.versions import (compare_versions, parse_constraint, parse_cpe, validate_cpe,  # noqa: E402
                               version_in_range, with_cpe_update)


def A(p, comp, method, strict=True, term=""):
    return assess_nvd(p, comp, method, term, strict=strict).applicability


def cfg(criteria, vulnerable=True, **ranges):
    m = {"criteria": criteria, "vulnerable": vulnerable}
    m.update(ranges)
    return [{"nodes": [{"operator": "OR", "cpeMatch": [m]}]}]


def nvd(cve_id, desc, configurations=None, score=7.5, status="Analyzed"):
    return {"id": cve_id, "description": desc, "published": "2025-03-01T10:00:00.000",
            "last_modified": "2025-03-05T10:00:00.000", "nvd_status": status, "cvss_score": score,
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", "cvss_version": "3.1",
            "severity_hint": "HIGH", "cwes": {"CWE-787"}, "references": ["https://example.com/" + cve_id],
            "configurations": configurations or [], "kev": False, "kev_date_added": ""}


BASH = Component(name="Bash", version="5.1", vendor="GNU", keywords=["GNU Bash"],
                 cpe=["cpe:2.3:a:gnu:bash:5.1:*:*:*:*:*:*:*"], projects=["IVI"], id="bash")
OPENSSL = Component(name="OpenSSL", version="1.1.1w", vendor="OpenSSL", keywords=["OpenSSL"],
                    cpe=["cpe:2.3:a:openssl:openssl:1.1.1w:*:*:*:*:*:*:*"], projects=["GW"], id="ossl")
JLINK = Component(name="J-Link", version="7.88", vendor="SEGGER", keywords=["J-Link"], projects=["HIL"], id="jl")


class VersionTests(unittest.TestCase):
    def test_compare(self):
        self.assertEqual(compare_versions("1.10", "1.9"), 1)
        self.assertEqual(compare_versions("3.8.0rc1", "3.8.0"), -1)
        self.assertEqual(compare_versions("3.8.0a1", "3.8.0"), -1)
        self.assertEqual(compare_versions("1.1.1w", "1.1.1"), 1)
        self.assertEqual(compare_versions("1.1.1w", "1.1.1x"), -1)
        self.assertEqual(compare_versions("5.1", "5.1.0"), 0)
        self.assertEqual(compare_versions("v2.0", "2.0"), 0)
        self.assertEqual(compare_versions("3.8.10+dfsg", "3.8.10"), 0)     # build metadata
        self.assertEqual(compare_versions("1:2.39.2", "2.39.2"), 0)       # Debian epoch
        self.assertEqual(compare_versions("9.3p1", "9.3"), 1)             # OpenSSH patch level
        self.assertEqual(compare_versions("9.3p1", "9.3.1"), -1)
        self.assertEqual(compare_versions("2.0.0-final", "2.0"), 0)
        self.assertEqual(compare_versions("7.94e", "7.94"), 1)
        self.assertEqual(with_cpe_update("5.1", "patch8"), "5.1.8")

    def test_constraints(self):
        self.assertEqual(parse_constraint("< 3.1.41"), {"end_excl": "3.1.41"})
        self.assertEqual(parse_constraint(">= 1.0, < 2.0"), {"start_incl": "1.0", "end_excl": "2.0"})
        self.assertEqual(parse_constraint("3.8.*"), {"start_incl": "3.8", "end_excl": "3.9"})
        self.assertIsNone(parse_constraint("n/a"))

    def test_range(self):
        self.assertTrue(version_in_range("5.1", start_incl="5.0", end_excl="5.2"))
        self.assertFalse(version_in_range("5.2", start_incl="5.0", end_excl="5.2"))
        self.assertTrue(version_in_range("5.2", end_incl="5.2"))

    def test_cpe(self):
        p = parse_cpe(r"cpe:2.3:a:segger:j\-link:7.88:*:*:*:*:*:*:*")
        self.assertEqual(p["product"], "j-link")
        self.assertTrue(validate_cpe("cpe:2.3:a:gnu:bash:5.1:*:*:*:*:*:*:*")[0])
        self.assertFalse(validate_cpe("cpe:2.3:a:*:bash:5.1:*:*:*:*:*:*:*")[0])
        self.assertFalse(validate_cpe("bash 5.1")[0])


class CvssTests(unittest.TestCase):
    def test_scores(self):
        self.assertEqual(cvss3_base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"), 9.8)
        self.assertEqual(cvss3_base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"), 10.0)
        self.assertEqual(cvss3_base_score("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N"), 5.5)
        self.assertEqual(cvss3_base_score("CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N"), 4.2)
        self.assertEqual(severity_from_score(9.8), "CRITICAL")
        self.assertEqual(severity_from_score(None), "UNKNOWN")


class MatcherTests(unittest.TestCase):
    def test_cpe_version_in_range_is_high(self):
        c = cfg("cpe:2.3:a:gnu:bash:*:*:*:*:*:*:*:*", versionEndExcluding="5.2")
        self.assertEqual(A(nvd("CVE-1", "GNU Bash before 5.2 ...", c), BASH, "cpe"), "HIGH")

    def test_cpe_version_outside_range_dropped(self):
        c = cfg("cpe:2.3:a:gnu:bash:*:*:*:*:*:*:*:*", versionEndExcluding="4.4")
        a = assess_nvd(nvd("CVE-2", "GNU Bash before 4.4", c), BASH, "cpe", "", strict=True)
        self.assertIsNone(a.applicability)
        self.assertIn("outside", a.reason)

    def test_openssl_letter_versions(self):
        c = cfg("cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*",
                versionStartIncluding="1.1.1", versionEndExcluding="1.1.1x")
        self.assertEqual(A(nvd("CVE-3", "OpenSSL ...", c), OPENSSL, "cpe"), "HIGH")
        c2 = cfg("cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*",
                 versionStartIncluding="1.1.1", versionEndExcluding="1.1.1t")
        self.assertIsNone(A(nvd("CVE-4", "OpenSSL ...", c2), OPENSSL, "cpe"))

    def test_keyword_fuzzy_dropped(self):
        # NVD keyword search matched "Link" etc. but the phrase is not a whole word.
        self.assertIsNone(A(nvd("CVE-5", "A flaw in D-Link routers and J-Linker tool"), JLINK, "keyword"))

    def test_keyword_unanalysed_with_vendor_is_medium(self):
        a = assess_nvd(nvd("CVE-6", "SEGGER J-Link before 7.94 allows a buffer overflow", status="Awaiting Analysis"),
                       JLINK, "keyword", "J-Link")
        self.assertEqual(a.applicability, "MEDIUM")
        self.assertIn("'J-Link before 7.94'", a.reason)
        self.assertIn("NVD keyword search 'J-Link'", a.evidence)      # exact trigger is reported

    def test_text_version_outside_is_not_applicable(self):
        d = nvd("CVE-6b", "SEGGER J-Link before 7.50 allows a buffer overflow", status="Awaiting Analysis")
        self.assertIsNone(A(d, JLINK, "keyword"))

    def test_keyword_plugin_is_ecosystem(self):
        d = nvd("CVE-7", "The J-Link plugin for SomeCMS allows XSS", status="Awaiting Analysis")
        a = assess_nvd(d, JLINK, "keyword", "J-Link")
        self.assertEqual((a.applicability, a.scope), ("LOW", "ecosystem"))

    def test_keyword_only_strict(self):
        d = nvd("CVE-7b", "A crafted file can crash the J-Link viewer", status="Awaiting Analysis")
        self.assertIsNone(A(d, JLINK, "keyword", strict=True))
        self.assertEqual(A(d, JLINK, "keyword", strict=False), "LOW")

    def test_keyword_other_product_listed_is_ecosystem(self):
        d = nvd("CVE-8", "Plugin J-Link for WordPress", cfg("cpe:2.3:a:acme:wp_jlink_plugin:*:*:*:*:*:*:*:*",
                                                             versionEndExcluding="2.0"))
        a = assess_nvd(d, JLINK, "keyword", "J-Link")
        self.assertEqual(a.scope, "ecosystem")
        self.assertIn("acme:wp_jlink_plugin", a.reason)

    def test_vendor_product_naming_without_cpe(self):
        d = nvd("CVE-8b", "SEGGER J-Link ...", cfg("cpe:2.3:a:segger:j-link_software_and_documentation_pack:*:*:*:*:*:*:*:*",
                                                    versionEndExcluding="7.94e"))
        self.assertEqual(A(d, JLINK, "keyword"), "HIGH")

    def test_platform_only_is_ecosystem(self):
        linux = Component(name="Linux kernel", version="5.10.120", cpe=["cpe:2.3:o:linux:linux_kernel:5.10.120:*:*:*:*:*:*:*"])
        configs = [{"nodes": [{"cpeMatch": [
            {"criteria": "cpe:2.3:a:acme:app:*:*:*:*:*:*:*:*", "vulnerable": True},
            {"criteria": "cpe:2.3:o:linux:linux_kernel:-:*:*:*:*:*:*:*", "vulnerable": False}]}]}]
        a = assess_nvd(nvd("CVE-8c", "App on Linux", configs), linux, "cpe", "x")
        self.assertEqual(a.scope, "ecosystem")

    def test_bash_patch_level_update(self):
        bash518 = Component(name="Bash", version="5.1.8", vendor="GNU", cpe=["cpe:2.3:a:gnu:bash:5.1:*:*:*:*:*:*:*"])
        self.assertEqual(A(nvd("CVE-8d", "bash", cfg("cpe:2.3:a:gnu:bash:5.1:patch8:*:*:*:*:*:*")), bash518, "cpe"), "HIGH")
        self.assertIsNone(A(nvd("CVE-8e", "bash", cfg("cpe:2.3:a:gnu:bash:5.1:patch4:*:*:*:*:*:*")), bash518, "cpe"))

    def test_exclude_keyword(self):
        comp = Component(name="Bash", version="5.1", vendor="GNU", keywords=["Bash"], exclude_keywords=["Git Bash"])
        self.assertIsNone(A(nvd("CVE-9", "Git Bash for Windows allows ..."), comp, "keyword", strict=False))

    def test_hardware_platform_match(self):
        mcu = Component(name="STM32F407", type="hardware", vendor="STMicroelectronics",
                        cpe=["cpe:2.3:h:st:stm32f407:-:*:*:*:*:*:*:*"], id="stm")
        configs = [{"operator": "AND", "nodes": [
            {"operator": "OR", "cpeMatch": [{"criteria": "cpe:2.3:o:st:stm32f4_firmware:*:*:*:*:*:*:*:*", "vulnerable": True}]},
            {"operator": "OR", "cpeMatch": [{"criteria": "cpe:2.3:h:st:stm32f407:-:*:*:*:*:*:*:*", "vulnerable": False}]}]}]
        self.assertEqual(A(nvd("CVE-10", "STM32F4 RDP bypass", configs), mcu, "cpe"), "HIGH")


class StoreTests(unittest.TestCase):
    def test_alias_merge(self):
        store = VulnerabilityStore()
        a = store.get(["GHSA-xxxx-yyyy"])
        a.add_match(JLINK, "MEDIUM", "osv", "OSV", "OSV")
        b = store.get(["CVE-2025-1"])
        b.add_match(BASH, "HIGH", "cpe", "NVD-CPE", "NVD")
        merged = store.get(["GHSA-xxxx-yyyy", "CVE-2025-1"])
        self.assertEqual(len(store.values()), 1)
        self.assertEqual(merged.id, "CVE-2025-1")
        self.assertIn("GHSA-XXXX-YYYY", merged.aliases)
        self.assertEqual(set(merged.matches), {"jl", "bash"})
        self.assertEqual(merged.applicability, "HIGH")
        self.assertEqual(merged.projects, {"IVI", "HIL"})


class ScannerEndToEndTests(unittest.TestCase):
    """Runs the full pipeline with mocked HTTP sources and checks dedup, OLD flag and reports."""

    def _fake_search(self, params, start, end, flags=(), date_field="published"):
        bash_cfg = cfg("cpe:2.3:a:gnu:bash:*:*:*:*:*:*:*:*", versionEndExcluding="5.2")
        shared = [{"nodes": [{"operator": "OR", "cpeMatch": [
            {"criteria": "cpe:2.3:a:gnu:bash:*:*:*:*:*:*:*:*", "vulnerable": True, "versionEndExcluding": "5.2"},
            {"criteria": "cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*", "vulnerable": True,
             "versionStartIncluding": "1.1.1", "versionEndExcluding": "3.0.0"}]}]}]

        def raw(cid, desc, configs, status="Analyzed"):
            return {"id": cid, "published": "2025-03-01T00:00:00.000", "lastModified": "2025-03-02T00:00:00.000",
                    "vulnStatus": status, "descriptions": [{"lang": "en", "value": desc}],
                    "metrics": {"cvssMetricV31": [{"type": "Primary", "cvssData": {
                        "baseScore": 9.8, "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                        "baseSeverity": "CRITICAL"}}]},
                    "configurations": configs, "references": [{"url": "https://example.org/" + cid}]}
        vm = params.get("virtualMatchString", "")
        kw = params.get("keywordSearch", "")
        if "gnu:bash" in vm:
            return iter([raw("CVE-2025-0001", "GNU Bash and OpenSSL shared issue", shared),
                         raw("CVE-2025-0002", "GNU Bash old issue", cfg("cpe:2.3:a:gnu:bash:*:*:*:*:*:*:*:*",
                                                                     versionEndExcluding="4.0")),
                         raw("CVE-2025-0003", "GNU Bash 5.1 issue", bash_cfg)])
        if "openssl:openssl" in vm:
            return iter([raw("CVE-2025-0001", "GNU Bash and OpenSSL shared issue", shared)])
        if kw == "J-Link":
            return iter([raw("CVE-2025-0004", "SEGGER J-Link 7.88 allows code execution", [], "Awaiting Analysis"),
                         raw("CVE-2025-0005", "D-Link DIR-600 J-Linker issue", [], "Awaiting Analysis")])
        return iter([])

    def test_pipeline(self):
        comps = [BASH, OPENSSL, JLINK]
        with tempfile.TemporaryDirectory() as out:
            opts = ScanOptions(start_date=dt.date(2025, 1, 1), end_date=dt.date(2025, 12, 31), output_dir=out,
                               use_osv=False, use_kev=False, use_cve_org=False, strict=True)
            with mock.patch("vulnscan.sources.NVDClient.search_cves", side_effect=self._fake_search):
                r1 = Scanner(comps, opts, log=lambda m: None).run()
            ids = {v.id: v for v in r1.vulnerabilities}
            self.assertEqual(set(ids), {"CVE-2025-0001", "CVE-2025-0003", "CVE-2025-0004"})
            shared = ids["CVE-2025-0001"]
            self.assertEqual(len(shared.matches), 2)           # consolidated, not duplicated
            self.assertEqual(shared.projects, {"IVI", "GW"})
            self.assertTrue(all(v.status == "NEW" for v in r1.vulnerabilities))
            self.assertEqual(ids["CVE-2025-0004"].applicability, "MEDIUM")
            # reports land in <out>/vuln_report_<stamp>/vuln_report_<stamp>.<ext>
            folder = os.path.basename(r1.report_dir)
            self.assertTrue(folder.startswith("vuln_report_"))
            for fmt in ("csv", "xlsx", "html", "json"):
                self.assertTrue(os.path.getsize(r1.reports[fmt]) > 0)
                self.assertEqual(os.path.basename(r1.reports[fmt]), folder + "." + fmt)
                self.assertEqual(os.path.dirname(r1.reports[fmt]), r1.report_dir)
            with open(r1.reports["json"], encoding="utf-8") as fh:
                data = json.load(fh)
            from vulnscan.reports import EXPORT_LABELS
            self.assertEqual(len(data), 4)                                 # report metadata + one row per vulnerability
            self.assertIn("_report_info", data[0])
            self.assertEqual(list(data[1].keys()), EXPORT_LABELS)
            row = {r["Vulnerability ID"]: r for r in data[1:]}["CVE-2025-0001"]
            self.assertEqual(row["Component name"], "Bash\nOpenSSL")
            self.assertEqual(row["Version"], "Bash: 5.1\nOpenSSL: 1.1.1w")
            self.assertIn("NVD CPE search 'cpe:2.3:a:gnu:bash'", row["Match method"])
            import csv as _csv
            with open(r1.reports["csv"], encoding="utf-8-sig", newline="") as fh:
                lines = fh.read().splitlines()
            self.assertEqual(len(lines), 6)                                # 2 metadata rows + header + 3 findings
            parsed = list(_csv.reader(lines, delimiter=";"))
            self.assertEqual(parsed[2], EXPORT_LABELS)
            self.assertEqual(parsed[3][EXPORT_LABELS.index("CVSS score")], "9,8")
            from openpyxl import load_workbook
            wb = load_workbook(r1.reports["xlsx"])
            self.assertEqual(wb.sheetnames, ["Vulnerabilities"])
            self.assertEqual([c.value for c in wb.active[3]], EXPORT_LABELS)
            self.assertEqual(wb.active.max_row, 6)
            with open(r1.reports["html"], encoding="utf-8") as fh:
                html = fh.read()
            self.assertNotIn("__DATA__", html)

            import time
            time.sleep(1.1)  # new report timestamp
            with mock.patch("vulnscan.sources.NVDClient.search_cves", side_effect=self._fake_search):
                r2 = Scanner(comps, opts, log=lambda m: None).run()
            self.assertTrue(all(v.status == "OLD" for v in r2.vulnerabilities))

            # History file deleted -> OLD still detected from previous JSON reports
            os.remove(os.path.join(out, ".vuln_history.json"))
            time.sleep(1.1)
            with mock.patch("vulnscan.sources.NVDClient.search_cves", side_effect=self._fake_search):
                r3 = Scanner(comps, opts, log=lambda m: None).run()
            self.assertTrue(all(v.status == "OLD" for v in r3.vulnerabilities))

    def test_all_mode_lists_not_applicable(self):
        comps = [BASH, OPENSSL, JLINK]
        with tempfile.TemporaryDirectory() as out:
            opts = ScanOptions(start_date=dt.date(2025, 1, 1), end_date=dt.date(2025, 12, 31), output_dir=out,
                               use_osv=False, use_kev=False, use_cve_org=False, min_applicability="ALL",
                               formats=("json", "html"))
            with mock.patch("vulnscan.sources.NVDClient.search_cves", side_effect=self._fake_search):
                r = Scanner(comps, opts, log=lambda m: None).run()
            apps = {v.id: v.applicability for v in r.vulnerabilities}
            self.assertEqual(apps["CVE-2025-0002"], "NOT APPLICABLE")     # version outside range
            self.assertEqual(apps["CVE-2025-0005"], "NOT APPLICABLE")     # 'J-Link' only inside 'J-Linker'
            self.assertEqual(apps["CVE-2025-0003"], "HIGH")
            self.assertEqual(r.stats["not_applicable"], 2)
            details = {v.id: v.to_record()["applicability_details"][0] for v in r.vulnerabilities}
            self.assertIn("outside", details["CVE-2025-0002"])
            with open(os.path.join(out, ".vuln_history.json"), encoding="utf-8") as fh:
                hist = json.load(fh)["vulnerabilities"]
            self.assertNotIn("CVE-2025-0002", hist)                      # NA findings never become OLD
            self.assertIn("CVE-2025-0003", hist)


class SampleFileTests(unittest.TestCase):
    def test_sample_components_load(self):
        path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "components.json")
        comps = load_components(path)
        self.assertGreaterEqual(len(comps), 7)
        for c in comps:
            for cpe in c.cpe:
                self.assertTrue(validate_cpe(cpe)[0], cpe)

    def test_lookback_window(self):
        with tempfile.TemporaryDirectory() as out:
            seen = {}

            def fake(self_, params, start, end, flags=(), date_field="published"):
                seen["window"] = (start, end)
                return iter([])
            opts = ScanOptions(lookback_days=1, output_dir=out, use_osv=False, use_kev=False, formats=("json",))
            with mock.patch("vulnscan.sources.NVDClient.search_cves", fake):
                Scanner([BASH], opts, log=lambda m: None).run()
            start, end = seen["window"]
            self.assertAlmostEqual((end - start).total_seconds(), 86400, delta=1)
            with self.assertRaises(ValueError):
                Scanner([BASH], ScanOptions(lookback_days=5, output_dir=out), log=lambda m: None).run()

    def test_date_chunks(self):
        from vulnscan.sources import NVDClient
        chunks = list(NVDClient.date_chunks(dt.date(2024, 1, 1), dt.date(2024, 12, 31)))
        self.assertEqual(len(chunks), 4)
        for a, b in chunks:
            self.assertLessEqual((b - a).days, 119)
        self.assertEqual(chunks[0][0], dt.datetime(2024, 1, 1))
        self.assertEqual(chunks[-1][1].date(), dt.date(2024, 12, 31))


if __name__ == "__main__":
    unittest.main()
