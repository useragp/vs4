"""Scan period on published / last-modified dates, modified-only guard and NVD 'Deferred' status."""
import datetime as dt
import os
import sys
import tempfile
import time
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from vulnscan.models import REPORT_COLUMNS, Component  # noqa: E402
from vulnscan.scanner import ScanOptions, Scanner  # noqa: E402

BASH = Component(name="Bash", version="5.1", vendor="GNU", keywords=["Bash"],
                 cpe=["cpe:2.3:a:gnu:bash:5.1:*:*:*:*:*:*:*"], id="bash")

CPE_AFFECTED = [{"nodes": [{"operator": "OR", "cpeMatch": [{
    "vulnerable": True, "criteria": "cpe:2.3:a:gnu:bash:*:*:*:*:*:*:*:*",
    "versionStartIncluding": "5.0", "versionEndExcluding": "5.1.8"}]}]}]


def raw(cid, published, modified, desc, status="Analyzed", configurations=None):
    return {"id": cid, "published": published, "lastModified": modified, "vulnStatus": status,
            "descriptions": [{"lang": "en", "value": desc}], "metrics": {},
            "configurations": configurations or [], "references": []}


# Period used by the tests: 2025-03-01 .. 2025-03-31
RECORDS = [
    # published in the period, version-confirmed
    raw("CVE-2025-0001", "2025-03-10T00:00:00.000", "2025-03-12T00:00:00.000",
        "GNU Bash before 5.1.8 allows code execution.", configurations=CPE_AFFECTED),
    # published long before, modified in the period, version confirmed by CPE data -> kept (HIGH)
    raw("CVE-2019-0002", "2019-05-01T00:00:00.000", "2025-03-15T00:00:00.000",
        "GNU Bash before 5.1.8 has an integer overflow.", configurations=CPE_AFFECTED),
    # published long before, modified in the period, text-only evidence -> rejected in strict mode
    raw("CVE-2018-0003", "2018-01-01T00:00:00.000", "2025-03-20T00:00:00.000",
        "In GNU Bash before 5.2 (GNU), a crafted string causes a crash.", status="Awaiting Analysis"),
    # deferred record published in the period
    raw("CVE-2025-0004", "2025-03-05T00:00:00.000", "2025-03-06T00:00:00.000",
        "GNU Bash before 5.1.8 mishandles prompts.", status="Deferred", configurations=CPE_AFFECTED),
]


def read(path, enc="utf-8"):
    with open(path, encoding=enc) as fh:
        return fh.read()


def fake_search_factory(calls):
    def fake_search(self_, params, start, end, flags=(), date_field="published"):
        calls.append(date_field)
        key = "published" if date_field == "published" else "lastModified"
        def ts(v):
            return dt.datetime.strptime(v[:19], "%Y-%m-%dT%H:%M:%S")
        return iter([r for r in RECORDS if start <= ts(r[key]) <= end])
    return fake_search


class DateFieldTests(unittest.TestCase):
    def run_scan(self, calls, **kw):
        with tempfile.TemporaryDirectory() as out:
            opts = dict(start_date=dt.date(2025, 3, 1), end_date=dt.date(2025, 3, 31), output_dir=out,
                        use_nvd_keywords=False, use_osv=False, use_kev=False, use_cve_org=False,
                        formats=("json",))
            opts.update(kw)
            with mock.patch("vulnscan.sources.NVDClient.search_cves", fake_search_factory(calls)):
                r = Scanner([BASH], ScanOptions(**opts), log=lambda m: None).run()
            time.sleep(1.05)   # report folders are per-second
            return r

    def test_both_dates_default(self):
        calls = []
        r = self.run_scan(calls)
        ids = {v.id: v for v in r.vulnerabilities}
        self.assertEqual(sorted(ids), ["CVE-2019-0002", "CVE-2025-0001"])
        self.assertEqual(sorted(set(calls)), ["modified", "published"])   # past range -> both queries
        self.assertIn("last-modified date 2025-03-15", "; ".join(
            e for m in ids["CVE-2019-0002"].matches.values() for e in [m.describe()] + list(m.evidence or [])))
        self.assertEqual(r.stats["deferred_excluded"], 1)
        # CVE-2018-0003: old CVE, modified in the period, version not confirmed -> rejected (strict mode)
        self.assertEqual(r.stats["modified_only_rejected"], 1)

    def test_published_only(self):
        r = self.run_scan([], date_modified=False)
        self.assertEqual([v.id for v in r.vulnerabilities], ["CVE-2025-0001"])

    def test_modified_only(self):
        r = self.run_scan([], date_published=False)
        self.assertEqual(sorted(v.id for v in r.vulnerabilities), ["CVE-2019-0002", "CVE-2025-0001"])

    def test_include_deferred(self):
        r = self.run_scan([], include_deferred=True)
        self.assertIn("CVE-2025-0004", [v.id for v in r.vulnerabilities])

    def test_no_date_field_rejected(self):
        with self.assertRaises(ValueError):
            self.run_scan([], date_published=False, date_modified=False)

    def test_period_ending_now_needs_only_modified_query(self):
        calls = []
        self.run_scan(calls, start_date=None, end_date=None, lookback_days=7)
        self.assertEqual(set(calls), {"modified"})

    def test_modified_only_text_match_rejected_in_strict(self):
        calls = []
        r = self.run_scan(calls, use_nvd_cpe=False, use_nvd_keywords=True)
        ids = [v.id for v in r.vulnerabilities]
        self.assertNotIn("CVE-2018-0003", ids)
        self.assertGreaterEqual(r.stats["modified_only_rejected"], 1)
        lenient = self.run_scan([], use_nvd_cpe=False, use_nvd_keywords=True, strict=False)
        self.assertIn("CVE-2018-0003", [v.id for v in lenient.vulnerabilities])


class ReportColumnTests(unittest.TestCase):
    def test_removed_columns(self):
        labels = [c[1] for c in REPORT_COLUMNS]
        for gone in ("# Components", "Aliases", "Category", "First Seen"):
            self.assertNotIn(gone, labels)

    def test_writer_drops_deferred(self):
        from vulnscan.models import Vulnerability
        from vulnscan.reports import write_all
        v1 = Vulnerability(id="CVE-2099-1", description="ok")
        v1.add_match(BASH, "HIGH", "affected", "t", "NVD")
        v2 = Vulnerability(id="CVE-2099-2", description="deferred one")
        v2.nvd_status = "Deferred"
        v2.add_match(BASH, "HIGH", "affected", "t", "NVD")
        meta = {"generated": "2026-11-25T12:00:00", "date_range": {"start": "a", "end": "b"}, "stats": {}}
        with tempfile.TemporaryDirectory() as d:
            p = write_all(os.path.join(d, "r"), [v1, v2], [BASH], meta, ["csv", "html"])
            csv_text = read(p["csv"], "utf-8-sig")
            html = read(p["html"])
            self.assertIn("CVE-2099-1", csv_text)
            self.assertNotIn("CVE-2099-2", csv_text + html)
            meta["include_deferred"] = True
            p = write_all(os.path.join(d, "r2"), [v1, v2], [BASH], meta, ["csv"])
            self.assertIn("CVE-2099-2", read(p["csv"], "utf-8-sig"))


if __name__ == "__main__":
    unittest.main()
