"""Clients for vulnerability data sources: NVD CVE API 2.0, CVE.org (CNA records), OSV.dev, CISA KEV."""

import datetime as dt
import threading
import time
from typing import Any, Callable, Dict, Iterator, List, Optional, Tuple
from urllib.parse import urlencode

import requests

from .cvss import cvss3_base_score

LogFn = Callable[[str], None]
USER_AGENT = "automotive-vuln-scanner/2.0 (+python-requests)"


class ScanCancelled(Exception):
    pass


class _BaseClient:
    def __init__(self, log: LogFn, cancel_event: Optional[threading.Event] = None,
                 delay: float = 0.0, timeout: int = 60) -> None:
        self.log = log
        self.cancel_event = cancel_event or threading.Event()
        self.delay = delay
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers["User-Agent"] = USER_AGENT
        self._last_call = 0.0
        # Shared across worker threads: serialize admission to each provider's rate limit.
        self._throttle_lock = threading.Lock()

    def _sleep(self, seconds: float) -> None:
        end = time.time() + seconds
        while time.time() < end:
            if self.cancel_event.is_set():
                raise ScanCancelled()
            time.sleep(min(0.25, max(0.0, end - time.time())))

    def _throttle(self) -> None:
        # NVD's documented limits are 50 requests / 30 seconds with a key and
        # 5 / 30 seconds without one. A conservative fixed interval stays below
        # those ceilings and is safe when several component workers share a client.
        with self._throttle_lock:
            wait = self.delay - (time.monotonic() - self._last_call)
            if wait > 0:
                self._sleep(wait)
            self._last_call = time.monotonic()

    def _request(self, method: str, url: str, retries: int = 5, **kwargs: Any) -> Dict[str, Any]:
        backoff = 6.0
        for attempt in range(1, retries + 1):
            if self.cancel_event.is_set():
                raise ScanCancelled()
            self._throttle()
            try:
                resp = self.session.request(method, url, timeout=self.timeout, **kwargs)
            except requests.RequestException as exc:
                self.log("  network error ({}), retry {}/{}".format(exc.__class__.__name__, attempt, retries))
                self._sleep(backoff)
                backoff *= 2
                continue
            if resp.status_code == 200:
                return resp.json()
            if resp.status_code in (403, 429) or resp.status_code >= 500:  # incl. Cloudflare 52x
                retry_after = resp.headers.get("Retry-After", "")
                try:
                    wait_for = min(300.0, max(backoff, float(retry_after))) if retry_after else backoff
                except ValueError:
                    wait_for = backoff
                self.log("  HTTP {} from {}, retry {}/{} in {:.0f}s".format(
                    resp.status_code, url.split("?")[0], attempt, retries, wait_for))
                self._sleep(wait_for)
                backoff = min(backoff * 2, 120.0)
                continue
            if resp.status_code == 404:
                return {}
            raise RuntimeError("HTTP {} for {}: {}".format(resp.status_code, url, resp.text[:300]))
        raise RuntimeError("Giving up on {} after {} attempts".format(url, retries))


# ---------------------------------------------------------------------------
# NVD
# ---------------------------------------------------------------------------
class NVDClient(_BaseClient):
    CVE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    CPE_URL = "https://services.nvd.nist.gov/rest/json/cpes/2.0"
    MAX_RANGE_DAYS = 119      # NVD allows at most 120 days per request
    PAGE_SIZE = 2000

    def __init__(self, api_key: str = "", log: LogFn = print,
                 cancel_event: Optional[threading.Event] = None) -> None:
        # NVD public rate limits: 5 req / 30 s without key, 50 req / 30 s with key.
        # 0.62 s ~= 48.4 requests / 30 s; 6.1 s ~= 4.9 requests / 30 s.
        # This deliberately leaves headroom rather than operating at the hard limit.
        super().__init__(log, cancel_event, delay=0.60 if api_key else 6.0, timeout=30)
        if api_key:
            self.session.headers["apiKey"] = api_key

    @staticmethod
    def date_chunks(start: dt.date, end: dt.date, days: int = MAX_RANGE_DAYS
                    ) -> Iterator[Tuple[dt.datetime, dt.datetime]]:
        """Split [start, end] into NVD-sized windows. Datetimes are used as-is (look-back
        windows such as 'last 24 hours'); plain dates cover whole days."""
        cur = start if isinstance(start, dt.datetime) else dt.datetime.combine(start, dt.time.min)
        stop = end if isinstance(end, dt.datetime) else dt.datetime.combine(end, dt.time(23, 59, 59, 999000))
        while cur <= stop:
            chunk_end = min(cur + dt.timedelta(days=days) - dt.timedelta(milliseconds=1), stop)
            yield cur, chunk_end
            cur = chunk_end + dt.timedelta(milliseconds=1)

    @staticmethod
    def _fmt(ts: dt.datetime) -> str:
        # NVD interprets timestamps without an offset as UTC; the scanner passes UTC times.
        return ts.strftime("%Y-%m-%dT%H:%M:%S.") + "{:03d}".format(ts.microsecond // 1000)

    DATE_FIELDS = {"published": ("pubStartDate", "pubEndDate"),
                   "modified": ("lastModStartDate", "lastModEndDate")}

    def search_cves(self, params: Dict[str, str], start: dt.date, end: dt.date,
                    flags: Tuple[str, ...] = (), date_field: str = "published") -> Iterator[Dict[str, Any]]:
        """Yield raw NVD 'cve' objects whose published (date_field="published") or
        last-modified (date_field="modified") timestamp lies between start and end."""
        start_key, end_key = self.DATE_FIELDS[date_field]
        flags = tuple(flags) + ("noRejected",)
        for c_start, c_end in self.date_chunks(start, end):
            index = 0
            while True:
                query = dict(params)
                query.update({start_key: self._fmt(c_start), end_key: self._fmt(c_end),
                              "resultsPerPage": str(self.PAGE_SIZE), "startIndex": str(index)})
                # Flag parameters (e.g. keywordExactMatch) must be sent without a value.
                url = "{}?{}&{}".format(self.CVE_URL, urlencode(query), "&".join(flags))
                data = self._request("GET", url)
                items = data.get("vulnerabilities", [])
                for item in items:
                    if "cve" in item:
                        yield item["cve"]
                total = int(data.get("totalResults", 0))
                index += len(items)
                if not items or index >= total:
                    break

    def search_cpe_dictionary(self, keyword: str, limit: int = 100) -> List[Tuple[str, str]]:
        """Search the NVD CPE dictionary (helps users pick a correct CPE)."""
        url = "{}?{}".format(self.CPE_URL, urlencode({"keywordSearch": keyword,
                                                      "resultsPerPage": str(limit)}))
        data = self._request("GET", url, retries=3)
        out = []
        for prod in data.get("products", []):
            cpe = prod.get("cpe", {})
            if cpe.get("deprecated"):
                continue
            titles = cpe.get("titles", [])
            title = next((t["title"] for t in titles if t.get("lang") == "en"), "")
            out.append((cpe.get("cpeName", ""), title))
        return out


def _best_metric(metrics: Dict[str, Any]) -> Tuple[Optional[float], str, str, str]:
    for key, version in (("cvssMetricV31", "3.1"), ("cvssMetricV30", "3.0"),
                         ("cvssMetricV40", "4.0"), ("cvssMetricV2", "2.0")):
        entries = metrics.get(key) or []
        if not entries:
            continue
        entry = next((e for e in entries if e.get("type") == "Primary"), entries[0])
        data = entry.get("cvssData", {})
        severity = data.get("baseSeverity") or entry.get("baseSeverity") or ""
        score = data.get("baseScore")
        return (float(score) if score is not None else None,
                data.get("vectorString", ""), version, severity)
    return None, "", "", ""


def parse_nvd_cve(cve: Dict[str, Any]) -> Dict[str, Any]:
    desc = next((d["value"] for d in cve.get("descriptions", []) if d.get("lang") == "en"), "")
    score, vector, version, severity = _best_metric(cve.get("metrics", {}))
    cwes = set()
    for weakness in cve.get("weaknesses", []):
        for d in weakness.get("description", []):
            value = d.get("value", "")
            if value.startswith("CWE-"):
                cwes.add(value)
    return {
        "id": cve.get("id", ""),
        "description": desc,
        "published": cve.get("published", ""),
        "last_modified": cve.get("lastModified", ""),
        "nvd_status": cve.get("vulnStatus", ""),
        "cvss_score": score, "cvss_vector": vector, "cvss_version": version,
        "severity_hint": severity,
        "cwes": cwes,
        "references": [r.get("url", "") for r in cve.get("references", []) if r.get("url")],
        "configurations": cve.get("configurations", []),
        "kev": bool(cve.get("cisaExploitAdd")),
        "kev_date_added": cve.get("cisaExploitAdd", ""),
    }


# ---------------------------------------------------------------------------
# CVE.org - the official CVE record incl. the CNA's (vendor's) affected products
# ---------------------------------------------------------------------------
class CVEOrgClient(_BaseClient):
    URL = "https://cveawg.mitre.org/api/cve/{}"

    def __init__(self, log: LogFn = print, cancel_event: Optional[threading.Event] = None) -> None:
        super().__init__(log, cancel_event, delay=0.15, timeout=30)
        self.cache = {}  # type: Dict[str, Optional[List[Dict[str, Any]]]]

    def affected(self, cve_id: str) -> Optional[List[Dict[str, Any]]]:
        """'affected' entries of the CNA (and ADP) containers, or None if unavailable."""
        cve_id = (cve_id or "").upper()
        if not cve_id.startswith("CVE-"):
            return None
        if cve_id not in self.cache:
            data = self._request("GET", self.URL.format(cve_id), retries=3)
            self.cache[cve_id] = parse_cve_org_affected(data) if data else None
        return self.cache[cve_id]


def parse_cve_org_affected(record: Dict[str, Any]) -> List[Dict[str, Any]]:
    containers = record.get("containers", {}) or {}
    out = []  # type: List[Dict[str, Any]]
    blocks = [containers.get("cna", {}) or {}] + list(containers.get("adp", []) or [])
    for block in blocks:
        for a in block.get("affected", []) or []:
            out.append({
                "vendor": str(a.get("vendor", "") or ""),
                "product": str(a.get("product", "") or ""),
                "packageName": str(a.get("packageName", "") or ""),
                "cpes": list(a.get("cpes", []) or []),
                "defaultStatus": str(a.get("defaultStatus", "") or ""),
                "versions": list(a.get("versions", []) or []),
            })
    return out


# ---------------------------------------------------------------------------
# OSV.dev (open source packages: PyPI, npm, Debian, Alpine, crates.io, ...)
# ---------------------------------------------------------------------------
class OSVClient(_BaseClient):
    QUERY_URL = "https://api.osv.dev/v1/query"

    def __init__(self, log: LogFn = print, cancel_event: Optional[threading.Event] = None) -> None:
        super().__init__(log, cancel_event, delay=0.2)

    def query(self, purl: str = "", ecosystem: str = "", package: str = "",
              version: str = "") -> List[Dict[str, Any]]:
        body = {}  # type: Dict[str, Any]
        if purl:
            body["package"] = {"purl": purl}
            if version and "@" not in purl:
                body["version"] = version
        else:
            body["package"] = {"name": package, "ecosystem": ecosystem}
            if version:
                body["version"] = version
        vulns = []  # type: List[Dict[str, Any]]
        while True:
            data = self._request("POST", self.QUERY_URL, json=body)
            vulns.extend(data.get("vulns", []))
            token = data.get("next_page_token")
            if not token:
                return vulns
            body["page_token"] = token


def parse_osv(vuln: Dict[str, Any]) -> Dict[str, Any]:
    score, vector, version = None, "", ""
    for sev in vuln.get("severity", []):
        if sev.get("type") == "CVSS_V3":
            vector = sev.get("score", "")
            score = cvss3_base_score(vector)
            version = "3.1" if vector.startswith("CVSS:3.1") else "3.0"
            break
        if sev.get("type") == "CVSS_V4" and not vector:
            vector, version = sev.get("score", ""), "4.0"
    db = vuln.get("database_specific") or {}
    summary = vuln.get("summary", "")
    details = vuln.get("details", "")
    description = summary if not details else (summary + " - " + details if summary else details)
    return {
        "id": vuln.get("id", ""),
        "aliases": vuln.get("aliases", []) or [],
        "description": description.strip()[:4000],
        "published": vuln.get("published", ""),
        "last_modified": vuln.get("modified", ""),
        "withdrawn": bool(vuln.get("withdrawn")),
        "cvss_score": score, "cvss_vector": vector, "cvss_version": version,
        "severity_hint": str(db.get("severity", "") or ""),
        "cwes": set(db.get("cwe_ids", []) or []),
        "references": [r.get("url", "") for r in vuln.get("references", []) if r.get("url")],
    }


# ---------------------------------------------------------------------------
# CISA Known Exploited Vulnerabilities catalog
# ---------------------------------------------------------------------------
class KEVClient(_BaseClient):
    URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

    def __init__(self, log: LogFn = print, cancel_event: Optional[threading.Event] = None) -> None:
        super().__init__(log, cancel_event)

    def load(self) -> Dict[str, str]:
        data = self._request("GET", self.URL, retries=3)
        return {v["cveID"].upper(): v.get("dateAdded", "") for v in data.get("vulnerabilities", [])
                if v.get("cveID")}
