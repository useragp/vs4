import csv

from vulnscan.models import Component, Vulnerability
from vulnscan.reports import write_all


def _meta(include_na):
    return {
        "generated": "2026-11-21T12:00:00",
        "date_range": {"start": "2026-11-20", "end": "2026-11-21"},
        "include_rejected_candidates": include_na,
    }


def _sample_vulns():
    applicable = Component(name="Applicable component", version="1.0", id="app")
    deferred = Component(name="Deferred component", version="2.0", id="na")
    vuln = Vulnerability(id="CVE-2099-0001", description="test vulnerability")
    vuln.add_match(applicable, "HIGH", "version affected", "test", "Test source")
    vuln.add_match(deferred, "NOT APPLICABLE", "not affected", "test", "Test source")
    return [vuln], [applicable, deferred], [("CVE-2099-0002", deferred.label, "candidate rejected")]



def test_report_omits_not_applicable_matches_when_toggle_off(tmp_path):
    vulns, components, dropped = _sample_vulns()
    paths = write_all(str(tmp_path / "report"), vulns, components, _meta(False), ["csv"], dropped)
    with open(paths["csv"], encoding="utf-8-sig", newline="") as fh:
        content = fh.read()
    assert "Applicable component" in content
    assert "Deferred component" not in content
    assert "candidate rejected" not in content


def test_report_includes_not_applicable_matches_when_toggle_on(tmp_path):
    vulns, components, dropped = _sample_vulns()
    paths = write_all(str(tmp_path / "report"), vulns, components, _meta(True), ["csv"], dropped)
    with open(paths["csv"], encoding="utf-8-sig", newline="") as fh:
        content = fh.read()
    assert "Applicable component" in content
    assert "Deferred component" in content
    assert "candidate rejected" in content
