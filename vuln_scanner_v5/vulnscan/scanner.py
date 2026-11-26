"""Scan orchestration: query sources, assess, de-duplicate, flag OLD, write reports."""

import datetime as dt
import glob
import json
import os
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
import re
import threading
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

from . import reports
from .matcher import Assessment, assess_nvd, assess_osv, mentions
from .models import (APPLICABILITY_ORDER, NOT_APPLICABLE, SCOPE_CORE, SCOPE_RELATED, Component,
                     Vulnerability)
from .sources import (CVEOrgClient, KEVClient, NVDClient, OSVClient, ScanCancelled, parse_nvd_cve,
                      parse_osv)
from .versions import product_match_string, validate_cpe

HISTORY_FILE = ".vuln_history.json"
REPORT_PREFIX = "vuln_report_"
LOOKBACK_CHOICES = (1, 7, 14, 30)       # days
SCOPE_CHOICES = (SCOPE_CORE, SCOPE_RELATED)
APP_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_REPORTS_DIR = os.path.join(APP_DIR, "reports")


DATE_FORMAT = "%Y-%m-%d"


def parse_date_range(start: str, end: str = "") -> Tuple[dt.date, dt.date]:
    """Validate a user-entered date range (YYYY-MM-DD). Empty end = today.
    Raises ValueError with a readable message."""
    def _p(text: str, label: str) -> dt.date:
        try:
            return dt.datetime.strptime(text.strip(), DATE_FORMAT).date()
        except ValueError:
            raise ValueError("{} date '{}' is not valid - use YYYY-MM-DD, e.g. 2026-10-01".format(label, text.strip()))
    if not (start or "").strip():
        raise ValueError("Enter a start date (YYYY-MM-DD)")
    today = dt.datetime.now(dt.timezone.utc).date()
    s = _p(start, "Start")
    e = _p(end, "End") if (end or "").strip() else today
    if s > today:
        raise ValueError("Start date {} is in the future".format(s.isoformat()))
    if s > e:
        raise ValueError("Start date {} is after end date {}".format(s.isoformat(), e.isoformat()))
    return s, min(e, today)


@dataclass
class ScanOptions:
    lookback_days: int = 7
    output_dir: str = DEFAULT_REPORTS_DIR   # root folder; every scan gets its own sub-folder
    nvd_api_key: str = ""
    use_nvd_cpe: bool = True
    use_nvd_keywords: bool = True
    use_osv: bool = True
    use_kev: bool = True
    use_cve_org: bool = True                # CNA affected products/versions for unanalysed CVEs
    strict: bool = True
    min_applicability: str = "LOW"          # HIGH | MEDIUM | LOW | ALL (incl. not applicable)
    scope: str = SCOPE_CORE                 # core = product itself only; ecosystem = + libraries/plugins
    categories: Tuple[str, ...] = ()        # empty = all; e.g. ("Core Component",)
    formats: Tuple[str, ...] = ("csv", "xlsx", "html", "json")
    csv_delimiter: str = ";"
    include_rejected_candidates: bool = False
    # Which dates the scan period applies to. With both ticked a CVE is in scope when it was
    # published OR last modified inside the period (at least one must be True).
    date_published: bool = True
    date_modified: bool = True
    # NVD records with status "Deferred" (NVD will not analyse them) are left out unless True.
    include_deferred: bool = False
    # Custom date range (overrides lookback_days when start_date is set). Plain dates cover whole
    # days (00:00:00 .. 23:59:59 UTC); an end date of today or later is capped at "now".
    # end_date may be omitted -> up to now.
    start_date: Optional[dt.date] = None
    end_date: Optional[dt.date] = None


@dataclass
class ScanResult:
    vulnerabilities: List[Vulnerability]
    reports: Dict[str, str] = field(default_factory=dict)
    stats: Dict[str, Any] = field(default_factory=dict)
    dropped: List[Tuple[str, str, str]] = field(default_factory=list)  # (id, component, reason)
    report_dir: str = ""


def _canonical(ids: Set[str]) -> str:
    cves = sorted(i for i in ids if i.startswith("CVE-"))
    if cves:
        return cves[0]
    ghsa = sorted(i for i in ids if i.startswith("GHSA-"))
    return ghsa[0] if ghsa else sorted(ids)[0]


def is_deferred(nvd_status: str) -> bool:
    return (nvd_status or "").strip().lower() == "deferred"


def _utc(value: str) -> Optional[dt.datetime]:
    """ISO timestamp (any precision, 'Z' or +hh:mm offset) -> naive UTC datetime."""
    m = re.match(r"\s*(\d{4})-(\d{2})-(\d{2})(?:[T ](\d{2}):(\d{2})(?::(\d{2}))?(?:\.\d+)?)?\s*"
                 r"(Z|[+-]\d{2}:?\d{2})?", value or "")
    if not m:
        return None
    y, mo, d, hh, mi, ss, tz = m.groups()
    try:
        ts = dt.datetime(int(y), int(mo), int(d), int(hh or 0), int(mi or 0), int(ss or 0))
    except ValueError:
        return None
    if tz and tz != "Z":
        sign = 1 if tz[0] == "+" else -1
        digits = tz[1:].replace(":", "")
        ts -= sign * dt.timedelta(hours=int(digits[:2]), minutes=int(digits[2:4]))
    return ts


class VulnerabilityStore:
    """De-duplicates findings across components and sources using IDs + aliases."""

    def __init__(self) -> None:
        self.vulns = {}  # type: Dict[str, Vulnerability]
        self.index = {}  # type: Dict[str, str]  alias -> canonical id

    def get(self, ids: List[str]) -> Vulnerability:
        ids_set = {i.strip().upper() for i in ids if i and i.strip()}
        existing = []  # type: List[Vulnerability]
        for i in ids_set:
            key = self.index.get(i)
            if key and self.vulns[key] not in existing:
                existing.append(self.vulns[key])
        all_ids = set(ids_set)
        for v in existing:
            all_ids.add(v.id)
            all_ids.update(v.aliases)
        canonical = _canonical(all_ids)
        target = Vulnerability(id=canonical)
        for v in existing:
            del self.vulns[v.id]
            target.absorb(v)
        target.id = canonical
        target.aliases.update(all_ids)
        target.aliases.discard(canonical)
        self.vulns[canonical] = target
        for i in all_ids:
            self.index[i] = canonical
        return target

    def values(self) -> List[Vulnerability]:
        return list(self.vulns.values())


class History:
    """Remembers every applicable vulnerability that appeared in a generated report."""

    def __init__(self, output_dir: str) -> None:
        self.path = os.path.join(output_dir, HISTORY_FILE)
        self.output_dir = output_dir
        self.data = {}  # type: Dict[str, Dict[str, Any]]
        self._load()

    def _learn(self, ids: List[str], first_seen: str, generated: str) -> None:
        for vid in ids:
            vid = (vid or "").strip().upper()
            if vid and vid not in self.data:
                self.data[vid] = {"first_seen": first_seen or generated, "last_seen": generated}

    def _load(self) -> None:
        if os.path.exists(self.path):
            try:
                with open(self.path, encoding="utf-8") as fh:
                    self.data = json.load(fh).get("vulnerabilities", {})
            except (ValueError, OSError):
                self.data = {}
        # Also learn from earlier JSON reports (robust if the history file was deleted);
        # both the per-scan folder layout and older flat layouts are searched.
        pattern_new = os.path.join(self.output_dir, "**", REPORT_PREFIX + "*.json")
        for report in glob.glob(pattern_new, recursive=True):
            try:
                with open(report, encoding="utf-8") as fh:
                    content = json.load(fh)
            except (ValueError, OSError):
                continue
            if isinstance(content, list):          # metadata record followed by vulnerability rows
                info = content[0].get("_report_info", {}) if content and isinstance(content[0], dict) else {}
                generated = str(info.get("report_generated", ""))[:10]
                for row in content[1:] if info else content:
                    if not isinstance(row, dict):
                        continue
                    if row.get("Applicability") == NOT_APPLICABLE:
                        continue
                    row_generated = generated or str(row.get("Report generated", ""))[:10]
                    self._learn([str(row.get("Vulnerability ID", row.get("CVE", "")))], "", row_generated)
            elif isinstance(content, dict):        # format of version 1.x
                generated = str(content.get("metadata", {}).get("generated", ""))[:10]
                for v in content.get("vulnerabilities", []):
                    self._learn([v.get("id", "")] + list(v.get("aliases", [])), v.get("first_seen", ""), generated)

    def lookup(self, vuln: Vulnerability) -> Optional[Dict[str, Any]]:
        for vid in [vuln.id] + sorted(vuln.aliases):
            if vid in self.data:
                return self.data[vid]
        return None

    def record(self, vulns: List[Vulnerability], when: str) -> None:
        for v in vulns:
            for vid in [v.id] + list(v.aliases):
                entry = self.data.setdefault(vid, {"first_seen": v.first_seen or when})
                entry["last_seen"] = when
        tmp = self.path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump({"version": 2, "updated": when, "vulnerabilities": self.data}, fh, indent=1)
        os.replace(tmp, self.path)


class Scanner:
    def __init__(self, components: List[Component], options: ScanOptions,
                 log: Callable[[str], None] = print,
                 progress: Callable[[int, int, str], None] = lambda a, b, c: None,
                 cancel_event: Optional[threading.Event] = None) -> None:
        self.components = [c for c in components if c.enabled]
        self.opt = options
        self.log = log
        self.progress = progress
        self.cancel = cancel_event or threading.Event()
        self.store = VulnerabilityStore()
        self.dropped = []  # type: List[Tuple[str, str, str]]
        self._nvd_cache = {}  # type: Dict[str, List[Dict[str, Any]]]
        self._cache_lock = threading.Lock()
        self._store_lock = threading.RLock()
        self._state_lock = threading.Lock()
        self.source_errors = []  # type: List[str]
        self.nvd = NVDClient(options.nvd_api_key, self._log, self.cancel)
        self.osv = OSVClient(self._log, self.cancel)
        self.cveorg = CVEOrgClient(self._log, self.cancel)
        self._cna_failed = False
        self.include_all = options.min_applicability.upper() == "ALL"
        self.window_start = None  # type: Optional[dt.datetime]
        self.window_end = None  # type: Optional[dt.datetime]
        self.window_ends_now = False
        self.deferred_skipped = set()  # type: set
        self.modified_only_rejected = 0

    def _log(self, msg: str) -> None:
        self.log(msg)

    # ------------------------------------------------------------------
    def _window(self) -> Tuple[dt.datetime, dt.datetime]:
        opt = self.opt
        now = dt.datetime.now(dt.timezone.utc).replace(tzinfo=None, microsecond=0)
        if opt.start_date is not None:
            start, end = opt.start_date, opt.end_date
            if not isinstance(start, dt.datetime):
                start = dt.datetime.combine(start, dt.time.min)
            if end is None:
                end = now
            elif not isinstance(end, dt.datetime):
                end = dt.datetime.combine(end, dt.time(23, 59, 59))
            if end > now:
                end = now
        else:
            if opt.lookback_days not in LOOKBACK_CHOICES:
                raise ValueError("Look-back period must be one of {} days".format(
                    ", ".join(str(d) for d in LOOKBACK_CHOICES)))
            end = now
            start = end - dt.timedelta(days=opt.lookback_days)
        if not (opt.date_published or opt.date_modified):
            raise ValueError("Select at least one date field (published and/or last modified)")
        if start > end:
            raise ValueError("Start must not be after end")
        self.window_ends_now = (now - end) <= dt.timedelta(minutes=5)
        return start, end

    def date_basis(self, published: str, last_modified: str) -> Optional[str]:
        """'published' / 'modified' when the timestamps put the record inside the scan period
        for the selected date fields, else None. Published wins when both qualify."""
        opt = self.opt
        def inside(value: str) -> bool:
            ts = _utc(value)
            return ts is not None and self.window_start <= ts <= self.window_end
        if opt.date_published and inside(published):
            return "published"
        if opt.date_modified and inside(last_modified):
            return "modified"
        return None

    def date_fields_label(self) -> str:
        opt = self.opt
        return " + ".join(n for n, on in (("published", opt.date_published),
                                          ("last modified", opt.date_modified)) if on)

    def run(self) -> ScanResult:
        opt = self.opt
        if opt.scope not in SCOPE_CHOICES:
            raise ValueError("scope must be 'core' or 'ecosystem'")
        self.window_start, self.window_end = self._window()
        os.makedirs(opt.output_dir, exist_ok=True)
        if opt.categories:
            wanted = {c.strip().lower() for c in opt.categories if c.strip()}
            skipped = [c for c in self.components if c.effective_category.lower() not in wanted]
            self.components = [c for c in self.components if c.effective_category.lower() in wanted]
            self.log("Category filter {}: {} components in scope, {} skipped".format(
                ", ".join(opt.categories), len(self.components), len(skipped)))
            if not self.components:
                raise ValueError("No enabled component belongs to the selected categories")
        started = dt.datetime.now()
        self.log("Scan started: {} components, CVEs {} {} .. {} UTC ({}), scope: {}, minimum "
                 "applicability: {}, deferred: {}".format(
                     len(self.components), self.date_fields_label(), self.window_start.strftime("%Y-%m-%d %H:%M"),
                     self.window_end.strftime("%Y-%m-%d %H:%M"),
                     "last {} day{}".format(opt.lookback_days, "s" if opt.lookback_days != 1 else "")
                     if opt.start_date is None else "custom date range",
                     "core product only" if opt.scope == SCOPE_CORE else "product + ecosystem",
                     opt.min_applicability, "included" if opt.include_deferred else "excluded"))
        if not opt.nvd_api_key and (opt.use_nvd_cpe or opt.use_nvd_keywords):
            self.log("No NVD API key: requests are throttled to 5 per 30 s (scan will be slow).")

        total = max(1, len(self.components))
        completed = 0
        progress_lock = threading.Lock()

        def scan_one(item: Tuple[int, Component]) -> None:
            nonlocal completed
            idx, comp = item
            if self.cancel.is_set():
                raise ScanCancelled()
            self.log("[queued {}/{}] {}".format(idx + 1, total, comp.label))
            if opt.use_nvd_cpe:
                self._scan_nvd_cpe(comp)
            if opt.use_nvd_keywords:
                self._scan_nvd_keywords(comp)
            if opt.use_osv and (comp.purl or (comp.osv_ecosystem and comp.osv_package)):
                self._scan_osv(comp)
            with progress_lock:
                completed += 1
                self.progress(completed, total, "Scanned {} ({}/{})".format(comp.label, completed, total))

        try:
            # Network-bound component scans overlap across NVD, OSV and CVE.org.
            # NVD requests remain globally throttled by the shared NVDClient.
            workers = min(4, max(1, len(self.components)))
            with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="vulnscan") as pool:
                futures = [pool.submit(scan_one, pair) for pair in enumerate(self.components)]
                for future in as_completed(futures):
                    future.result()
            self.progress(total, total, "Enriching")
            if opt.use_kev:
                self._enrich_kev()
        except ScanCancelled:
            self.log("Scan cancelled by user - no reports written.")
            raise

        min_rank = 0 if self.include_all else APPLICABILITY_ORDER.get(opt.min_applicability.upper(), 1)
        all_vulns = self.store.values()
        if not opt.include_deferred:
            for v in all_vulns:
                if is_deferred(v.nvd_status):
                    self.deferred_skipped.add(v.id)
            all_vulns = [v for v in all_vulns if not is_deferred(v.nvd_status)]
        vulns = []
        for v in all_vulns:
            v.keep_matches(min_rank)
            if v.matches:
                vulns.append(v)
        below = len(all_vulns) - len(vulns)

        history = History(opt.output_dir)
        today = started.strftime("%Y-%m-%d")
        for v in vulns:
            prev = history.lookup(v)
            v.status = "OLD" if prev else "NEW"
            v.first_seen = (prev or {}).get("first_seen", today)
        vulns.sort(key=lambda v: (-v.risk_rank, v.id))
        applicable = [v for v in vulns if v.applicability != NOT_APPLICABLE]

        stats = {
            "components_scanned": len(self.components),
            "vulnerabilities": len(vulns),
            "applicable": len(applicable),
            "not_applicable": len(vulns) - len(applicable),
            "new": sum(1 for v in applicable if v.status == "NEW"),
            "old": sum(1 for v in applicable if v.status == "OLD"),
            "filtered_false_positives": len(self.dropped),
            "below_min_applicability": below,
            "deferred_excluded": 0 if opt.include_deferred else len(self.deferred_skipped),
            "modified_only_rejected": self.modified_only_rejected,
            "source_errors": len(self.source_errors),
            "duration_seconds": round((dt.datetime.now() - started).total_seconds(), 1),
        }
        stamp = started.strftime("%Y%m%d_%H%M%S")
        name = REPORT_PREFIX + stamp
        report_dir = os.path.join(opt.output_dir, name)
        os.makedirs(report_dir, exist_ok=True)
        result = ScanResult(vulns, stats=stats, dropped=self.dropped, report_dir=report_dir)
        sources = [s for s, on in (("NVD (CPE)", opt.use_nvd_cpe), ("NVD (keyword)", opt.use_nvd_keywords),
                                   ("CVE.org (CNA)", opt.use_cve_org), ("OSV.dev", opt.use_osv),
                                   ("CISA KEV", opt.use_kev)) if on]
        meta = {
            "generated": started.isoformat(timespec="seconds"),
            "lookback_days": opt.lookback_days if opt.start_date is None else None,
            "date_range": {"start": self.window_start.strftime("%Y-%m-%d %H:%M UTC"),
                           "end": self.window_end.strftime("%Y-%m-%d %H:%M UTC")},
            "sources": sources,
            "strict_mode": opt.strict,
            "min_applicability": opt.min_applicability.upper(),
            "include_rejected_candidates": opt.include_rejected_candidates,
            "include_deferred": opt.include_deferred,
            "date_fields": self.date_fields_label(),
            "scope": opt.scope,
            "categories": list(opt.categories) or ["(all)"],
            "source_errors": list(self.source_errors),
            "report_folder": report_dir,
            "stats": stats,
        }
        base = os.path.join(report_dir, name)
        result.reports = reports.write_all(base, vulns, self.components, meta, opt.formats, self.dropped,
                                           csv_delimiter=opt.csv_delimiter)
        history.record(applicable, today)
        self.log("Reports folder: {}".format(report_dir))
        for fmt, path in result.reports.items():
            self.log("Report ({}): {}".format(fmt.upper(), os.path.basename(path)))
        self.log("Done: {applicable} applicable vulnerabilities ({new} new, {old} old), {not_applicable} "
                 "not applicable listed, {filtered_false_positives} candidate matches rejected "
                 "({modified_only_rejected} modified-only without confirmed version), "
                 "{deferred_excluded} deferred CVEs excluded.".format(**stats))
        return result

    # ------------------------------------------------------------------
    def _finalize(self, a: Assessment) -> Tuple[str, str]:
        """Apply the scope option to an assessment -> (applicability label, reason)."""
        label, reason = a.label, a.reason
        if label != NOT_APPLICABLE and a.scope == SCOPE_RELATED:
            if self.opt.scope == SCOPE_CORE:
                return NOT_APPLICABLE, "out of scope - not the product itself: " + reason
            return "LOW", reason
        return label, reason

    def _record(self, ids: List[str], comp: Component, a: Assessment, method_tag: str, source: str
                ) -> Optional[Vulnerability]:
        label, reason = self._finalize(a)
        if label == NOT_APPLICABLE and not self.include_all:
            self.dropped.append((ids[0], comp.label, reason))
            return None
        with self._store_lock:
            v = self.store.get(ids)
            v.add_match(comp, label, reason, method_tag, source, a.scope, a.evidence)
            if "CVE.org" in a.reason:
                v.sources.add("CVE.org")
            return v if label != NOT_APPLICABLE else None

    def _cna_lookup(self, cve_id: str) -> Optional[List[Dict[str, Any]]]:
        if self._cna_failed:
            return None
        try:
            return self.cveorg.affected(cve_id)
        except RuntimeError as exc:
            self._cna_failed = True
            msg = "CVE.org lookup failed ({}) - continuing with NVD/text evidence".format(str(exc).split(":", 1)[0])
            self.log("  WARNING: " + msg)
            self.source_errors.append(msg)
            return None

    def _nvd_query(self, cache_key: str, params: Dict[str, str], flags: Tuple[str, ...] = ()
                   ) -> List[Dict[str, Any]]:
        with self._cache_lock:
            cached = self._nvd_cache.get(cache_key)
        if cached is not None:
            return cached
        try:
            fields = []
            if self.opt.date_modified:
                fields.append("modified")
            # A CVE published in the period was last modified at or after its publication, so
            # when the period ends "now" the last-modified query already returns every CVE
            # published in it - the extra published-date query would only repeat requests.
            if self.opt.date_published and not (self.opt.date_modified and self.window_ends_now):
                fields.append("published")
            merged = {}  # type: Dict[str, Dict[str, Any]]
            for field in fields:
                for c in self.nvd.search_cves(params, self.window_start, self.window_end, flags, field):
                    p = parse_nvd_cve(c)
                    merged.setdefault(p["id"], p)
            fetched = []
            for p in merged.values():
                basis = self.date_basis(p["published"], p["last_modified"])
                if basis is None:
                    continue
                p["date_basis"] = basis
                fetched.append(p)
            with self._cache_lock:
                self._nvd_cache[cache_key] = fetched
            return fetched
        except RuntimeError as exc:
                # One unreachable query must not abort the whole scan; it is reported instead.
                msg = "NVD query {} failed: {}".format(cache_key, str(exc).split(":", 1)[0])
                self.log("  WARNING: " + msg + " - results may be incomplete")
                with self._state_lock:
                    self.source_errors.append(msg)
                return []

    def _scan_nvd_cpe(self, comp: Component) -> None:
        for cpe in comp.cpe:
            ok, why = validate_cpe(cpe)
            if not ok:
                self.log("  skip invalid CPE '{}': {}".format(cpe, why))
                continue
            match_string = product_match_string(cpe) or cpe
            results = self._nvd_query("cpe|" + match_string.lower(), {"virtualMatchString": match_string})
            kept = self._apply_nvd(results, comp, "cpe", match_string)
            self.log("  NVD CPE {}: {} candidates, {} applicable".format(match_string, len(results), kept))

    def _scan_nvd_keywords(self, comp: Component) -> None:
        # Keywords + aliases are searched. The bare name is used only as a last resort,
        # i.e. when the component has no CPE and no package URL (precision first).
        base = comp.keywords + comp.aliases
        if not base and not comp.cpe and not comp.purl and not comp.osv_package:
            base = [comp.name]
        terms = []  # type: List[str]
        for t in base:
            if t.strip() and t.strip().lower() not in [x.lower() for x in terms]:
                terms.append(t.strip())
        for term in terms:
            if len(term) < 3:
                self.log("  skip keyword '{}' (too short, would cause false positives)".format(term))
                continue
            results = self._nvd_query("kw|" + term.lower(), {"keywordSearch": term}, ("keywordExactMatch",))
            kept = self._apply_nvd(results, comp, "keyword", term)
            self.log("  NVD keyword '{}': {} candidates, {} applicable".format(term, len(results), kept))

    def _apply_nvd(self, results: List[Dict[str, Any]], comp: Component, method: str, term: str) -> int:
        kept = 0
        cna = self._cna_lookup if self.opt.use_cve_org else None
        for p in results:
            if not self.opt.include_deferred and is_deferred(p.get("nvd_status", "")):
                with self._state_lock:
                    self.deferred_skipped.add(p["id"])
                continue
            # Assessment (including an occasional CVE.org fallback request) runs
            # outside the store lock so other workers can continue processing.
            a = assess_nvd(p, comp, method, term, self.opt.strict, cna)
            a = self._date_guard(a, p.get("date_basis", "published"), p["published"], p["last_modified"])
            label, _ = self._finalize(a)
            if label == NOT_APPLICABLE and not self.include_all:
                self._record([p["id"]], comp, a, "NVD-" + method.upper(), "NVD")
                continue
            with self._store_lock:
                v = self.store.get([p["id"]])
                v.update_text(p["description"], "NVD", p["published"], p["last_modified"])
                v.update_cvss(p["cvss_score"], p["cvss_vector"], p["cvss_version"])
                v.severity_hint = v.severity_hint or p["severity_hint"]
                v.nvd_status = p["nvd_status"] or v.nvd_status
                v.cwes.update(p["cwes"])
                for ref in p["references"]:
                    if ref not in v.references:
                        v.references.append(ref)
                if p["kev"]:
                    v.kev, v.kev_date_added = True, p["kev_date_added"]
                if self._record([p["id"]], comp, a, "NVD-" + method.upper(), "NVD") is not None:
                    kept += 1
        return kept

    def _date_guard(self, a: Assessment, basis: str, published: str, last_modified: str) -> Assessment:
        """A CVE that is in the period only because its record was modified (published earlier)
        is usually an old issue whose references or metadata changed. In strict mode it is
        reported only when the component's version is confirmed affected (HIGH)."""
        if basis != "modified" or a.applicability is None:
            return a
        note = "in scan period by last-modified date {} (published {})".format(
            (last_modified or "")[:10], (published or "")[:10] or "unknown")
        if self.opt.strict and a.applicability != "HIGH":
            with self._state_lock:
                self.modified_only_rejected += 1
            return Assessment(None, "published before the scan period and only modified in it; strict mode "
                                    "requires a confirmed affected version for such CVEs (was {}: {})".format(
                                        a.applicability, a.reason), a.scope, a.evidence)
        return a._replace(evidence=(a.evidence + "; " if a.evidence else "") + note)

    def _scan_osv(self, comp: Component) -> None:
        version = "" if "@" in comp.purl else comp.version
        query = comp.purl or "{}:{}".format(comp.osv_ecosystem, comp.osv_package or comp.name)
        try:
            raw = self.osv.query(comp.purl, comp.osv_ecosystem, comp.osv_package or comp.name, version)
        except RuntimeError as exc:
            msg = "OSV query for {} failed: {}".format(comp.label, str(exc).split(":", 1)[0])
            self.log("  WARNING: " + msg)
            self.source_errors.append(msg)
            return
        with self._store_lock:
            if "@" in comp.purl:
                version = comp.purl.rsplit("@", 1)[1]
            kept = 0
            for item in raw:
                p = parse_osv(item)
                if p["withdrawn"]:
                    continue
                basis = self.date_basis(p["published"], p["last_modified"])
                if basis is None:
                    continue
                excluded = mentions(p["description"], comp.exclude_keywords)
                if excluded:
                    a = Assessment(None, "exclude keyword '{}' found in description".format(excluded[0]),
                                   SCOPE_CORE, "OSV.dev package query '{}'".format(query))
                else:
                    a = assess_osv(comp, version, query)
                    a = self._date_guard(a, basis, p["published"], p["last_modified"])
                if a.applicability is None and not self.include_all:
                    self.dropped.append((p["id"], comp.label, a.reason))
                    continue
                v = self.store.get([p["id"]] + list(p["aliases"]))
                v.update_text(p["description"], "OSV", p["published"], p["last_modified"])
                v.update_cvss(p["cvss_score"], p["cvss_vector"], p["cvss_version"])
                v.severity_hint = v.severity_hint or p["severity_hint"]
                v.cwes.update(p["cwes"])
                for ref in p["references"]:
                    if ref not in v.references:
                        v.references.append(ref)
                v.add_match(comp, a.label, a.reason, "OSV", "OSV", a.scope, a.evidence)
                if a.applicability:
                    kept += 1
            self.log("  OSV.dev: {} advisories, {} applicable in the scan period".format(len(raw), kept))


    def _enrich_kev(self) -> None:
        try:
            kev = KEVClient(self._log, self.cancel).load()
        except RuntimeError as exc:
            self.log("CISA KEV unavailable: {}".format(exc))
            return
        hits = 0
        for v in self.store.values():
            for vid in [v.id] + list(v.aliases):
                if vid in kev:
                    if not v.kev:
                        hits += 1
                    v.kev, v.kev_date_added = True, v.kev_date_added or kev[vid]
                    v.sources.add("CISA KEV")
        self.log("CISA KEV: {} catalog entries loaded, {} additional exploited flags".format(len(kev), hits))
