"""Report writers.

CSV, XLSX and JSON share one flat structure: one row per vulnerability with the
columns in EXPORT_COLUMNS (vulnerability -> classification -> component -> provenance).
When a vulnerability affects several components, the component cells list one line per
component, prefixed with the component name, in the same order in every column.

The HTML report is interactive (filter, sort, hide/resize columns, hide/delete rows,
summary pie charts) and keeps its own, richer column set (REPORT_COLUMNS).
"""

import csv
import copy
import html
import json
import re
from collections import Counter
from typing import Any, Dict, Iterable, List, Sequence, Tuple

from .models import NOT_APPLICABLE, REPORT_COLUMNS, Component, Vulnerability, APPLICABILITY_ORDER

LIST_TYPES = ("list", "links")
SEVERITY_COLORS = {"CRITICAL": "7B1FA2", "HIGH": "D32F2F", "MEDIUM": "F57C00", "LOW": "FBC02D",
                   "NONE": "9E9E9E", "UNKNOWN": "BDBDBD"}
APPLICABILITY_COLORS = {"HIGH": "C62828", "MEDIUM": "EF6C00", "LOW": "558B2F", NOT_APPLICABLE: "9E9E9E"}
STATUS_COLORS = {"NEW": "1565C0", "OLD": "757575"}
XLSX_CELL_LIMIT = 32000

# (label, width in XLSX) - order is the logical reading order of a finding.
EXPORT_COLUMNS = [
    ("Component name", 24),
    ("Version", 13),
    ("Vulnerability ID", 22),
    ("Link", 48),
    ("Criticality", 12),
    ("CVSS score", 8),
    ("CVSS version", 8),
    ("Applicability", 14),
    ("Applicability details", 60),
    ("Match method", 50),
    ("Known exploited (CISA KEV)", 14),
    ("CWE", 14),
    ("Published", 11),
    ("NVD status", 14),
    ("CVE description", 80),
    ("Type", 20),
    ("Vendor", 18),
    ("Manufacturer", 20),
    ("Component description", 40),
    ("Keywords", 24),
    ("Aliases", 20),
    ("Excluded words", 18),
    ("CPE", 45),
    ("PURL", 28),
    ("Projects", 26),
    ("Sources", 16),
]
EXPORT_LABELS = [label for label, _ in EXPORT_COLUMNS]


def _range_text(meta: Dict[str, Any]) -> str:
    dr = meta.get("date_range", {}) or {}
    text = "{} .. {}".format(dr.get("start", ""), dr.get("end", ""))
    extras = []
    if meta.get("date_fields"):
        extras.append("dates: " + meta["date_fields"])
    if "include_deferred" in meta:
        extras.append("deferred CVEs " + ("included" if meta["include_deferred"] else "excluded"))
    return text + (" ({})".format("; ".join(extras)) if extras else "")


def build_summary(records: List[Dict[str, Any]]) -> Dict[str, Dict[str, int]]:
    def count(key: str) -> Dict[str, int]:
        c = Counter()  # type: Counter
        for r in records:
            val = r[key]
            for item in (val if isinstance(val, list) else [val]):
                c[str(item) if item not in ("", None) else "(none)"] += 1
        return dict(c.most_common())
    return {
        "by_component": count("components"),
        "by_category": count("categories"),
        "by_source": count("sources"),
        "by_project": count("projects"),
        "by_criticality": count("criticality"),
        "by_applicability": count("applicability"),
    }


def _flat(value: Any, sep: str = "; ") -> Any:
    if isinstance(value, list):
        return sep.join(str(v) for v in value)
    return "" if value is None else value


def _vuln_link(vid: str) -> str:
    if vid.startswith("CVE-"):
        return "https://nvd.nist.gov/vuln/detail/" + vid
    return "https://osv.dev/vulnerability/" + vid


def build_export_rows(vulns: List[Vulnerability], components: List[Component],
                      meta: Dict[str, Any]) -> List[Dict[str, Any]]:
    """One dict per vulnerability, keys = EXPORT_LABELS (shared by CSV, XLSX and JSON)."""
    by_id = {c.id: c for c in components}
    rows = []
    for v in vulns:
        matches = sorted(v.matches.values(),
                         key=lambda m: (-APPLICABILITY_ORDER.get(m.applicability, 0), m.component_label))
        comps = [(m, by_id.get(m.component_id)) for m in matches]
        multi = len(comps) > 1

        def per_comp(getter) -> str:
            lines = []
            for m, c in comps:
                value = getter(m, c) if c is not None else ""
                if multi:
                    name = c.name if c is not None else m.component_label
                    lines.append("{}: {}".format(name, value if value not in ("", None) else "-"))
                elif value not in ("", None):
                    lines.append(str(value))
            return "\n".join(lines)

        rows.append({
            "Component name": "\n".join((c.name if c else m.component_label) for m, c in comps),
            "Version": per_comp(lambda m, c: c.version),
            "Vulnerability ID": v.id,
            "Link": _vuln_link(v.id),
            "Criticality": v.criticality,
            "CVSS score": v.cvss_score if v.cvss_score is not None else "",
            "CVSS version": v.cvss_version,
            "Applicability": v.applicability,
            "Applicability details": "\n".join(m.describe() if multi else m.describe().split(": ", 1)[1]
                                               for m in matches),
            "Match method": per_comp(lambda m, c: "; ".join(m.evidence or sorted(m.methods))),
            "Known exploited (CISA KEV)": "YES (added {})".format(v.kev_date_added) if v.kev and v.kev_date_added
            else ("YES" if v.kev else "NO"),
            "CWE": ", ".join(sorted(v.cwes)),
            "Published": v.published[:10],
            "NVD status": v.nvd_status,
            "CVE description": v.description,
            "Type": per_comp(lambda m, c: "{} / {}".format(c.type or "software", c.effective_category)),
            "Vendor": per_comp(lambda m, c: c.vendor),
            "Manufacturer": per_comp(lambda m, c: c.manufacturer),
            "Component description": per_comp(lambda m, c: c.description),
            "Keywords": per_comp(lambda m, c: ", ".join(c.keywords)),
            "Aliases": per_comp(lambda m, c: ", ".join(c.aliases)),
            "Excluded words": per_comp(lambda m, c: ", ".join(c.exclude_keywords)),
            "CPE": per_comp(lambda m, c: ", ".join(c.cpe)),
            "PURL": per_comp(lambda m, c: c.purl),
            "Projects": per_comp(lambda m, c: ", ".join(c.projects)),
            "Sources": ", ".join(sorted(v.sources)),
        })
    if meta.get("include_rejected_candidates"):
        comp_by_label = {c.label: c for c in components}
        for vid, comp_label, reason in meta.get("rejected_candidates", []):
            comp = comp_by_label.get(comp_label)
            rows.append({
                "Component name": comp.name if comp else comp_label,
                "Version": comp.version if comp else "",
                "Vulnerability ID": vid,
                "Link": _vuln_link(vid),
                "Criticality": "UNKNOWN",
                "CVSS score": "",
                "CVSS version": "",
                "Applicability": NOT_APPLICABLE,
                "Applicability details": reason,
                "Match method": "Rejected candidate",
                "Known exploited (CISA KEV)": "NO",
                "CWE": "", "Published": "", "NVD status": "Rejected candidate",
                "CVE description": reason,
                "Type": "Rejected candidate",
                "Vendor": comp.vendor if comp else "",
                "Manufacturer": comp.manufacturer if comp else "",
                "Component description": comp.description if comp else "",
                "Keywords": ", ".join(comp.keywords) if comp else "",
                "Aliases": ", ".join(comp.aliases) if comp else "",
                "Excluded words": ", ".join(comp.exclude_keywords) if comp else "",
                "CPE": ", ".join(comp.cpe) if comp else "",
                "PURL": comp.purl if comp else "",
                "Projects": ", ".join(comp.projects) if comp else "",
                "Sources": "",
            })
    return rows


def write_csv(path: str, rows: List[Dict[str, Any]], delimiter: str = ";") -> None:
    """Strictly one line per vulnerability: line breaks inside cells become ' | '.

    ';' (default) is what Excel expects with Polish / most European regional settings;
    the CVSS score then uses a decimal comma so Excel does not turn 7.5 into a date.
    """
    decimal_comma = delimiter == ";"
    with open(path, "w", newline="", encoding="utf-8-sig") as fh:
        writer = csv.writer(fh, delimiter=delimiter, quoting=csv.QUOTE_MINIMAL)
        writer.writerow(["Report generated", str(getattr(write_csv, "_meta", {}).get("generated", ""))])
        writer.writerow(["Date range", _range_text(getattr(write_csv, "_meta", {}))])
        writer.writerow(EXPORT_LABELS)
        for r in rows:
            out = []
            for label in EXPORT_LABELS:
                value = r.get(label, "")
                if isinstance(value, float):
                    value = ("{:.1f}".format(value)).replace(".", ",") if decimal_comma else "{:.1f}".format(value)
                else:
                    value = str(value)
                    if label == "CVE description":
                        value = re.sub(r"\s+", " ", value).strip()
                    else:
                        value = re.sub(r"\s*\r?\n\s*", " | ", value).strip()
                out.append(value)
            writer.writerow(out)


def write_json(path: str, rows: List[Dict[str, Any]], meta: Dict[str, Any]) -> None:
    info = {"report_generated": meta.get("generated", ""), "date_range": meta.get("date_range", {}),
            "date_fields": meta.get("date_fields", "published"),
            "include_deferred": bool(meta.get("include_deferred", False))}
    with open(path, "w", encoding="utf-8") as fh:
        json.dump([{"_report_info": info}] + rows, fh, indent=2, ensure_ascii=False)


def write_xlsx(path: str, rows: List[Dict[str, Any]], meta: Dict[str, Any]) -> None:
    from openpyxl import Workbook
    from openpyxl.styles import Alignment, Font, PatternFill
    from openpyxl.utils import get_column_letter

    wb = Workbook()
    ws = wb.active
    ws.title = "Vulnerabilities"
    header_font = Font(bold=True, color="FFFFFF")
    header_fill = PatternFill("solid", fgColor="263238")
    ws.cell(row=1, column=1, value="Report generated")
    ws.cell(row=1, column=2, value=meta.get("generated", ""))
    ws.cell(row=2, column=1, value="Date range")
    ws.cell(row=2, column=2, value=_range_text(meta))
    for row in (1, 2):
        ws.cell(row=row, column=1).font = Font(bold=True, color="263238")
        ws.cell(row=row, column=1).alignment = Alignment(vertical="center")
        ws.row_dimensions[row].height = 21
    for col, (label, width) in enumerate(EXPORT_COLUMNS, start=1):
        cell = ws.cell(row=3, column=col, value=label)
        cell.font, cell.fill = header_font, header_fill
        cell.alignment = Alignment(wrap_text=True, vertical="center")
        ws.column_dimensions[get_column_letter(col)].width = width
    ws.row_dimensions[3].height = 32
    for r_idx, rec in enumerate(rows, start=4):
        for col, label in enumerate(EXPORT_LABELS, start=1):
            value = rec.get(label, "")
            if isinstance(value, str) and len(value) > XLSX_CELL_LIMIT:
                value = value[:XLSX_CELL_LIMIT] + " [...]"
            cell = ws.cell(row=r_idx, column=col, value=value)
            cell.alignment = Alignment(wrap_text=True, vertical="top")
            color = None
            if label == "Criticality":
                color = SEVERITY_COLORS.get(value)
            elif label == "Applicability":
                color = APPLICABILITY_COLORS.get(value)
            elif label.startswith("Known exploited") and str(value).startswith("YES"):
                color = "B71C1C"
            if color:
                cell.fill = PatternFill("solid", fgColor=color)
                cell.font = Font(bold=True, color="FFFFFF")
            if label == "CVSS score" and isinstance(value, float):
                cell.number_format = "0.0"
    ws.freeze_panes = "C4"
    ws.auto_filter.ref = "A3:{}{}".format(get_column_letter(len(EXPORT_COLUMNS)), max(3, len(rows)) + 3)
    wb.save(path)


def write_html(path: str, records: List[Dict[str, Any]], meta: Dict[str, Any],
               summary: Dict[str, Any]) -> None:
    payload = {
        "meta": meta,
        "summary": summary,
        "columns": [{"key": k, "label": l, "type": t} for k, l, t in REPORT_COLUMNS],
        "rows": records,
        "colors": {"severity": SEVERITY_COLORS, "applicability": APPLICABILITY_COLORS,
                   "status": STATUS_COLORS},
        "view": {},
    }
    data = json.dumps(payload, ensure_ascii=False).replace("</", "<\\/")
    title = "Vulnerability Report {}".format(html.escape(meta["generated"]))
    content = HTML_TEMPLATE.replace("__TITLE__", title).replace("__DATA__", data)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(content)


def write_all(base: str, vulns: List[Vulnerability], components: List[Component],
              meta: Dict[str, Any], formats: Iterable[str],
              dropped: Sequence[Tuple[str, str, str]] = (), csv_delimiter: str = ";") -> Dict[str, str]:
    formats = [f.lower() for f in formats]
    meta = dict(meta)
    # Defensive report-level filtering: never let N/A findings leak into exports
    # when the opt-in checkbox is off, even if upstream scan state contains them.
    include_na = bool(meta.get("include_rejected_candidates", False))
    if not meta.get("include_deferred", False):
        # NVD "Deferred" CVEs are never written unless explicitly requested.
        vulns = [v for v in vulns if (v.nvd_status or "").strip().lower() != "deferred"]
    if not include_na:
        safe_vulns = []
        for vuln in vulns:
            # Filter each component match too (not just whole-CVE applicability)
            # so a multi-component CVE cannot retain an N/A component entry.
            report_vuln = copy.copy(vuln)
            report_vuln.matches = dict(vuln.matches)
            report_vuln.keep_matches(1)  # LOW or higher; excludes NOT APPLICABLE
            if not report_vuln.matches:
                continue
            safe_vulns.append(report_vuln)
        vulns = safe_vulns
        dropped = ()
        meta["rejected_candidates"] = []
    else:
        meta["rejected_candidates"] = list(dropped)
    rows = build_export_rows(vulns, components, meta)
    out = {}
    if "json" in formats:
        out["json"] = base + ".json"
        write_json(out["json"], rows, meta)
    if "csv" in formats:
        out["csv"] = base + ".csv"
        write_csv._meta = meta
        write_csv(out["csv"], rows, csv_delimiter)
    if "xlsx" in formats:
        out["xlsx"] = base + ".xlsx"
        write_xlsx(out["xlsx"], rows, meta)
    if "html" in formats:
        by_component_id = {c.id: c for c in components}
        records = []
        for v in vulns:
            record = v.to_record()
            matched = sorted(v.matches.values(), key=lambda m: (-APPLICABILITY_ORDER.get(m.applicability, 0), m.component_label))
            record["component_name"] = [by_component_id[m.component_id].name if m.component_id in by_component_id else m.component_label for m in matched]
            record["version"] = [by_component_id[m.component_id].version if m.component_id in by_component_id else "" for m in matched]
            records.append(record)
        if meta.get("include_rejected_candidates"):
            comp_by_label = {c.label: c for c in components}
            for vid, comp_label, reason in dropped:
                comp = comp_by_label.get(comp_label)
                records.append({
                    "component_name": [comp.name if comp else comp_label],
                    "version": [comp.version if comp else ""],
                    "id": vid, "criticality": "UNKNOWN", "status": "REJECTED",
                    "aliases": [], "cvss_score": None, "cvss_version": "",
                    "applicability": NOT_APPLICABLE, "applicability_details": [reason],
                    "components": [comp_label], "component_count": 1,
                    "categories": ["Rejected candidate"], "projects": comp.projects if comp else [],
                    "sources": [], "match_methods": ["Rejected candidate"], "kev": "NO",
                    "cwes": [], "published": "", "last_modified": "",
                    "nvd_status": "Rejected candidate", "description": reason,
                    "first_seen": "",
                })
        out["html"] = base + ".html"
        write_html(out["html"], records, meta, build_summary(records))
    return out


HTML_TEMPLATE = r"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>__TITLE__</title>
<style>
body{font-family:"Segoe UI",Arial,sans-serif;margin:0 auto;padding:16px clamp(10px,1.5vw,24px);width:100%;max-width:none;box-sizing:border-box;color:#1f2937;background:#f3f6fa}
h1{margin:0 0 4px;font-size:22px} h2{font-size:17px;margin:18px 0 8px}
.meta{color:#555;font-size:13px}
.cards{display:grid;grid-template-columns:repeat(4,minmax(150px,1fr));gap:14px;margin:14px 0}
.card{background:#fff;border:1px solid #e3e8ef;border-radius:10px;padding:14px 18px;box-shadow:0 3px 12px rgba(25,40,60,.06);min-width:105px}
.card .n{font-size:24px;font-weight:600} .card .l{font-size:12px;color:#666}
.charts{display:grid;grid-template-columns:repeat(auto-fit,minmax(340px,1fr));gap:16px;align-items:stretch}
.chart{background:#fff;border:1px solid #e3e8ef;border-radius:10px;padding:16px;box-shadow:0 3px 12px rgba(25,40,60,.06);width:auto;min-width:0}
.chart h3{margin:0 0 6px;font-size:14px}
.chart .body{display:flex;gap:10px;align-items:flex-start}
.legend{font-size:11px;max-height:150px;overflow:auto;flex:1}
.legend div{display:flex;align-items:center;gap:5px;cursor:pointer;padding:1px 0}
.legend div:hover{text-decoration:underline}
.sw{width:11px;height:11px;border-radius:2px;flex:none}
.toolbar{margin:8px 0;display:flex;gap:10px;align-items:center;flex-wrap:wrap;font-size:13px}
.tablewrap{overflow-x:auto;overflow-y:hidden;height:auto;width:100%;scrollbar-width:none;background:#fff;border:1px solid #cbd5e1;border-radius:9px;box-shadow:0 2px 8px rgba(25,40,60,.05);overscroll-behavior:contain;scrollbar-gutter:stable}
table{border-collapse:separate;border-spacing:0;font-size:12px;min-width:100%;width:max-content;table-layout:auto;max-width:none}
th,td{border-bottom:1px solid #cbd5e1;border-right:1px solid #d3dce7;padding:7px 9px;vertical-align:top;text-align:left;line-height:1.35;white-space:normal;overflow-wrap:anywhere;word-break:normal}
thead tr.h th{background:#243447;color:#fff;position:relative;cursor:pointer;white-space:nowrap;z-index:2;user-select:none}
thead tr.f th{background:#eceff1;position:relative;z-index:2}
.tablewrap::-webkit-scrollbar{display:none}
.findings{position:relative}
.hscroll{position:sticky;bottom:0;overflow-x:auto;overflow-y:hidden;height:16px;z-index:5;background:#f3f6fa}
.hscroll div{height:1px}
thead input,thead select{width:100%;min-width:60px;box-sizing:border-box;font-size:11px}
.multi-filter{position:relative;text-align:left;font-size:11px}.multi-filter summary{cursor:pointer;background:#fff;padding:3px;border:1px solid #ccd4df;border-radius:4px;white-space:nowrap}.filter-options{display:none;position:absolute;top:20px;left:0;z-index:10;background:#fff;border:1px solid #cbd5e1;box-shadow:0 4px 12px #0002;padding:7px;min-width:160px;max-height:220px;overflow:auto}.multi-filter[open] .filter-options{display:grid;gap:4px}.filter-options label{display:flex;gap:5px;align-items:center;white-space:nowrap}.filter-options input{width:auto}
td.description{min-width:360px;max-width:720px} td.applicability_details{min-width:280px;max-width:560px}
td.cvss_vector{font-family:monospace;font-size:11px}
.pill{display:inline-block;padding:1px 7px;border-radius:9px;color:#fff;font-weight:600;font-size:11px}
tbody tr:hover{filter:brightness(.975)}
tbody tr[data-severity="CRITICAL"]{background:#f8e9ee} tbody tr[data-severity="HIGH"]{background:#fff0ed}
tbody tr[data-severity="MEDIUM"]{background:#fff6e8} tbody tr[data-severity="LOW"]{background:#fffbea}
tbody tr[data-severity="NONE"],tbody tr[data-severity="UNKNOWN"]{background:#f4f6f8}
ul.l{margin:0;padding-left:14px}
thead tr.h th .lbl{display:block;overflow:hidden;text-overflow:ellipsis}
.rz{position:absolute;top:0;right:-3px;width:7px;height:100%;cursor:col-resize;z-index:3}
.rz:hover,.rz.on{background:rgba(144,202,249,.7)}
tbody tr{cursor:default}
tbody tr.sel,tbody tr.sel:hover{background:#cfe3ff}
.ctx{position:fixed;z-index:100;background:#fff;border:1px solid #b0bec5;border-radius:4px;box-shadow:0 3px 10px rgba(0,0,0,.25);
  font-size:13px;min-width:230px;max-height:70vh;overflow:auto;padding:4px 0}
.ctx div{padding:5px 14px;cursor:pointer;white-space:nowrap}
.ctx div:hover{background:#e3f2fd}
.ctx div.sep{border-top:1px solid #e0e0e0;margin:4px 0;padding:0;cursor:default}
.ctx div.dis{color:#9e9e9e;cursor:default;background:none}
.ctx div.hd{color:#607d8b;font-size:11px;text-transform:uppercase;cursor:default;background:none}
#viewinfo a{color:#1565C0;cursor:pointer;text-decoration:underline}
</style></head>
<body>
<h1>Vulnerability Scan Report</h1>
<div class="meta" id="meta"></div>
<section id="summary">
  <h2>Summary</h2>
  <div class="cards" id="cards"></div>
  <div class="charts" id="charts"></div>
</section>
<h2>Findings</h2>
<div class="toolbar">
  <input id="global" placeholder="Search all columns..." size="36">
  <button id="reset">Reset filters &amp; sorting</button>
  <label><input type="checkbox" id="follow" checked> Summary follows filters</label>
  <button id="export">Export visible rows (CSV)</button>
  <button id="saveview" title="Download this report with deleted rows removed and the current column layout">Save edited report (HTML)</button>
  <span id="count"></span> <span id="viewinfo"></span>
  <span style="color:#777">Tip: click a header to sort (shift-click for multi-column); right-click a header to hide/show columns; drag a header edge to resize;
  click rows to select (Ctrl/Shift for several) and right-click to hide or delete them; numeric filters accept &gt;=7, &lt;5, 5-8; click legend entries to filter.</span>
</div>
<div class="findings">
<div class="tablewrap"><table id="tbl"><thead></thead><tbody></tbody></table></div>
<div class="hscroll" id="hscroll" title="Scroll the table left / right"><div></div></div>
</div>
<script id="report-data" type="application/json">__DATA__</script>
<script>
(function(){
"use strict";
var D = JSON.parse(document.getElementById("report-data").textContent);
var COLS = D.columns, ROWS = D.rows;
var ORDER = {severity:{CRITICAL:5,HIGH:4,MEDIUM:3,LOW:2,NONE:1,UNKNOWN:0}, applicability:{HIGH:3,MEDIUM:2,LOW:1,"NOT APPLICABLE":0}};
ROWS.forEach(function(r,i){ r.__i = i; });
var VIEW = D.view || {};
var hiddenCols = VIEW.hiddenCols || {}, widths = VIEW.widths || {}, hiddenRows = {}, deletedRows = {}, selected = {}, lastClicked = null, justResized = false;
var dynStyle = document.createElement("style"); document.head.appendChild(dynStyle);
var PALETTE = ["#1565C0","#C62828","#2E7D32","#EF6C00","#6A1B9A","#00838F","#AD1457","#9E9D24","#4E342E","#37474F","#5C6BC0","#26A69A","#FFA000","#8D6E63","#7CB342","#EC407A"];
var state = {sort:[{key:"applicability",dir:-1},{key:"criticality",dir:-1},{key:"cvss_score",dir:-1}], filters:{}, global:""};
var ENUM_TYPES = ["enum","severity","applicability"];
var SELECT_LIST_KEYS = ["sources","match_methods","projects","components","categories"];

function el(tag, attrs, text){ var e=document.createElement(tag); if(attrs){for(var k in attrs){ if(k==="style"){e.style.cssText=attrs[k];} else e.setAttribute(k,attrs[k]);}} if(text!==undefined&&text!==null) e.textContent=String(text); return e; }
function asText(v){ if(v===null||v===undefined) return ""; return Array.isArray(v)? v.join(", ") : String(v); }
function color(type,val){ var c=null; if(type==="severity") c=D.colors.severity[val]; else if(type==="applicability") c=D.colors.applicability[val]; return c?"#"+c:null; }

// ---- meta + cards ----
var m = D.meta;
document.getElementById("meta").textContent = "Generated: " + m.generated + " | Dates: " + (m.date_fields || "published") + (m.include_deferred ? " | Deferred CVEs included" : " | Deferred CVEs excluded") + " | Scan period: " + (m.lookback_days ? "last " + m.lookback_days + (m.lookback_days===1?" day":" days") + " (" : "") + m.date_range.start + " .. " + m.date_range.end + (m.lookback_days ? ")" : "");

// ---- table header ----
var thead = document.querySelector("#tbl thead"), tbody = document.querySelector("#tbl tbody");
var hr = el("tr",{"class":"h"}), fr = el("tr",{"class":"f"});
COLS.forEach(function(c){
  var th = el("th",{"data-key":c.key,"data-col":c.key,"title":"Sort by "+c.label+" (right-click for column options)"});
  th.appendChild(el("span",{"class":"lbl"}, c.label));
  var grip = el("div",{"class":"rz","title":"Drag to resize, double-click to reset"});
  th.appendChild(grip); attachResize(grip, th, c.key);
  th.addEventListener("click", function(ev){ if (justResized) { justResized=false; return; } toggleSort(c.key, ev.shiftKey); });
  th.addEventListener("contextmenu", function(ev){ ev.preventDefault(); columnMenu(ev, c); });
  hr.appendChild(th);
  var fth = el("th",{"data-col":c.key}), input;
  var distinct = distinctValues(c);
  if (ENUM_TYPES.indexOf(c.type)>=0 || (SELECT_LIST_KEYS.indexOf(c.key)>=0 && distinct.length<=60)) {
    input = el("details",{"class":"multi-filter"});
    input.appendChild(el("summary",null,"(all)"));
    var opts = el("div",{"class":"filter-options"});
    distinct.forEach(function(v){
      var lab=el("label"), cb=el("input",{type:"checkbox",value:v});
      cb.addEventListener("change",function(){
        var chosen=Array.prototype.slice.call(opts.querySelectorAll("input:checked")).map(function(x){return x.value;});
        setFilter(c.key,chosen,true);
        input.querySelector("summary").textContent=chosen.length?chosen.length+" selected":"(all)";
      });
      lab.appendChild(cb); lab.appendChild(document.createTextNode(v)); opts.appendChild(lab);
    });
    input.appendChild(opts);
  } else {
    input = el("input",{"data-key":c.key, placeholder: c.type==="number" ? ">=7" : "filter"});
    input.addEventListener("input", function(){ setFilter(c.key, input.value, false); });
  }
  fth.appendChild(input); fr.appendChild(fth);
  fth.addEventListener("contextmenu", function(ev){ if (ev.target===fth) { ev.preventDefault(); columnMenu(ev, c); } });
});
thead.appendChild(hr); thead.appendChild(fr);

function distinctValues(c){
  var s = {};
  ROWS.forEach(function(r){ var v=r[c.key]; (Array.isArray(v)?v:[v]).forEach(function(x){ if(x!==null&&x!==undefined&&x!=="") s[String(x)]=1; }); });
  var vals = Object.keys(s);
  var ord = ORDER[c.type];
  vals.sort(function(a,b){ return ord ? (ord[b]||0)-(ord[a]||0) : a.localeCompare(b); });
  return vals;
}
function setFilter(key, value, exact){ if(value===""){ delete state.filters[key]; } else state.filters[key]={value:value, exact:exact}; render(); }
function toggleSort(key, multi){
  var idx = -1; state.sort.forEach(function(s,i){ if(s.key===key) idx=i; });
  if (!multi) { var dir = (idx===0 && state.sort.length>=1) ? -state.sort[0].dir : -1; state.sort=[{key:key,dir:dir}]; }
  else if (idx>=0) state.sort[idx].dir = -state.sort[idx].dir; else state.sort.push({key:key,dir:-1});
  render();
}

function matchFilter(row, col, f){
  var v = row[col.key];
  if (f.exact) { var choices=Array.isArray(f.value)?f.value:[f.value]; return choices.length===0 || choices.some(function(x){return Array.isArray(v)?v.map(String).indexOf(x)>=0:String(v)===x;}); }
  var q = f.value.trim();
  if (col.type==="number") {
    var n = (v===null||v===undefined||v==="") ? null : Number(v), mm;
    if ((mm = q.match(/^(>=|<=|>|<|=)\s*(-?[\d.]+)$/))) {
      if (n===null) return false; var t=Number(mm[2]);
      return {">=":n>=t,"<=":n<=t,">":n>t,"<":n<t,"=":n===t}[mm[1]];
    }
    if ((mm = q.match(/^(-?[\d.]+)\s*-\s*(-?[\d.]+)$/))) { return n!==null && n>=Number(mm[1]) && n<=Number(mm[2]); }
  }
  var terms = q.toLowerCase().split(/\s+/).filter(Boolean), text = asText(v).toLowerCase();
  return terms.every(function(t){ return t.charAt(0)==="!" ? (t.length===1 || text.indexOf(t.slice(1))<0) : text.indexOf(t)>=0; });
}
function cmp(col, a, b){
  var x=a[col.key], y=b[col.key];
  if (ORDER[col.type]) { x=ORDER[col.type][x]||0; y=ORDER[col.type][y]||0; return x-y; }
  if (col.type==="number") { x=(x===null||x===undefined)?-1:Number(x); y=(y===null||y===undefined)?-1:Number(y); return x-y; }
  return asText(x).localeCompare(asText(y), undefined, {numeric:true, sensitivity:"base"});
}
function visibleRows(){
  var g = state.global.toLowerCase();
  var rows = ROWS.filter(function(r){
    if (deletedRows[r.__i] || hiddenRows[r.__i]) return false;
    for (var k in state.filters){ var col = COLS.filter(function(c){return c.key===k;})[0] || {key:k, type:"list"}; if(!matchFilter(r,col,state.filters[k])) return false; }
    if (g){ var all = COLS.map(function(c){return asText(r[c.key]);}).join(" ").toLowerCase(); if (all.indexOf(g)<0) return false; }
    return true;
  });
  var specs = state.sort.map(function(s){ return {col:COLS.filter(function(c){return c.key===s.key;})[0], dir:s.dir}; });
  rows.sort(function(a,b){ for(var i=0;i<specs.length;i++){ var r=cmp(specs[i].col,a,b); if(r!==0) return r*specs[i].dir; } return 0; });
  return rows;
}

function renderCell(td, col, v){
  if (col.type==="links") {
    (v||[]).forEach(function(u){ if(/^https?:\/\//i.test(u)){ var a=el("a",{href:u,target:"_blank",rel:"noopener noreferrer"},u); td.appendChild(a); td.appendChild(el("br")); } });
  } else if (col.type==="list" && (col.key==="applicability_details") && v && v.length) {
    var ul=el("ul",{"class":"l"}); v.forEach(function(x){ ul.appendChild(el("li",null,x)); }); td.appendChild(ul);
  } else if (col.key==="id" && /^CVE-/.test(v)) {
    td.appendChild(el("a",{href:"https://nvd.nist.gov/vuln/detail/"+encodeURIComponent(v),target:"_blank",rel:"noopener noreferrer",title:"https://nvd.nist.gov/vuln/detail/"+v},v));
  } else if (col.key==="id" && /^(GHSA|PYSEC|OSV|GO|RUSTSEC)-/.test(v)) {
    td.appendChild(el("a",{href:"https://osv.dev/vulnerability/"+encodeURIComponent(v),target:"_blank",rel:"noopener noreferrer",title:"https://osv.dev/vulnerability/"+v},v));
  } else if (col.key==="id") {
    td.appendChild(el("a",{href:"https://osv.dev/vulnerability/"+encodeURIComponent(v),target:"_blank",rel:"noopener noreferrer",title:"https://osv.dev/vulnerability/"+v},v));
  } else {
    var c = color(col.type, v);
    if (col.key==="status") c = v==="NEW" ? "#"+D.colors.status.NEW : "#"+D.colors.status.OLD;
    if (col.key==="kev" && v==="YES") c = "#B71C1C";
    if (c) td.appendChild(el("span",{"class":"pill",style:"background:"+c},v)); else td.textContent = asText(v);
  }
}

function render(){
  var rows = visibleRows();
  Array.prototype.forEach.call(hr.children, function(th){
    var k = th.getAttribute("data-key"), label = COLS.filter(function(c){return c.key===k;})[0].label, mark="";
    state.sort.forEach(function(s,i){ if(s.key===k) mark = (s.dir>0?" \u25B2":" \u25BC") + (state.sort.length>1?(i+1):""); });
    th.querySelector(".lbl").textContent = label + mark;
  });
  var frag = document.createDocumentFragment();
  rows.forEach(function(r){
    var tr = el("tr",{"data-i":r.__i,"data-severity":r.criticality||"UNKNOWN"});
    if (selected[r.__i]) tr.className = "sel";
    COLS.forEach(function(c){ var td=el("td",{"class":c.key,"data-col":c.key}); renderCell(td,c,r[c.key]); tr.appendChild(td); });
    frag.appendChild(tr);
  });
  tbody.innerHTML = ""; tbody.appendChild(frag);
  CURRENT = rows;
  var kept = ROWS.filter(function(r){ return !deletedRows[r.__i]; });
  document.getElementById("count").textContent = rows.length + " of " + kept.length + " vulnerabilities shown";
  renderViewInfo();
  renderSummary(document.getElementById("follow").checked ? rows : kept);
}

// ---- column hiding / resizing ----
var CURRENT = [];
function applyColumnStyles(){
  var css = [];
  Object.keys(hiddenCols).forEach(function(k){ if (hiddenCols[k]) css.push('#tbl [data-col="'+k+'"]{display:none}'); });
  Object.keys(widths).forEach(function(k){ var w = widths[k];
    css.push('#tbl th[data-col="'+k+'"],#tbl td[data-col="'+k+'"]{width:'+w+'px!important;min-width:'+w+'px!important;max-width:'+w+'px!important;overflow:hidden;overflow-wrap:anywhere}'); });
  dynStyle.textContent = css.join("\n");
}
function attachResize(grip, th, key){
  grip.addEventListener("click", function(ev){ ev.stopPropagation(); });
  grip.addEventListener("dblclick", function(ev){ ev.stopPropagation(); delete widths[key]; applyColumnStyles(); });
  grip.addEventListener("mousedown", function(ev){
    ev.preventDefault(); ev.stopPropagation();
    var startX = ev.clientX, startW = th.getBoundingClientRect().width; grip.classList.add("on");
    function move(e){ widths[key] = Math.max(40, Math.round(startW + e.clientX - startX)); applyColumnStyles(); }
    function up(){ document.removeEventListener("mousemove", move); document.removeEventListener("mouseup", up);
      grip.classList.remove("on"); justResized = true; setTimeout(function(){ justResized=false; }, 0); }
    document.addEventListener("mousemove", move); document.addEventListener("mouseup", up);
  });
}
function hiddenColList(){ return COLS.filter(function(c){ return hiddenCols[c.key]; }); }

// ---- context menu ----
var menuEl = null;
function closeMenu(){ if (menuEl) { menuEl.remove(); menuEl = null; } }
function openMenu(ev, items){
  closeMenu();
  menuEl = el("div",{"class":"ctx"});
  items.forEach(function(it){
    if (it === "-") { menuEl.appendChild(el("div",{"class":"sep"})); return; }
    var d = el("div",{"class": it.header ? "hd" : (it.disabled ? "dis" : "")}, it.label);
    if (!it.disabled && !it.header) d.addEventListener("click", function(e){ e.stopPropagation(); closeMenu(); it.action(); });
    menuEl.appendChild(d);
  });
  document.body.appendChild(menuEl);
  var x = ev.clientX, y = ev.clientY, r = menuEl.getBoundingClientRect();
  if (x + r.width > window.innerWidth) x = Math.max(0, window.innerWidth - r.width - 4);
  if (y + r.height > window.innerHeight) y = Math.max(0, window.innerHeight - r.height - 4);
  menuEl.style.left = x + "px"; menuEl.style.top = y + "px";
}
document.addEventListener("click", function(e){ if (menuEl && !menuEl.contains(e.target)) closeMenu(); });
window.addEventListener("blur", closeMenu);
document.querySelector(".tablewrap").addEventListener("scroll", closeMenu);
function columnMenu(ev, c){
  var items = [{label: "Hide column \u201c" + c.label + "\u201d", action: function(){ hiddenCols[c.key] = true; applyColumnStyles(); renderViewInfo(); },
                disabled: COLS.length - hiddenColList().length <= 1}];
  items.push({label: "Reset width of \u201c" + c.label + "\u201d", action: function(){ delete widths[c.key]; applyColumnStyles(); }, disabled: !widths[c.key]});
  items.push("-");
  var hidden = hiddenColList();
  items.push({label: "Hidden columns", header: true});
  if (!hidden.length) items.push({label: "(none)", disabled: true});
  hidden.forEach(function(h){ items.push({label: "Show \u201c" + h.label + "\u201d", action: function(){ delete hiddenCols[h.key]; applyColumnStyles(); renderViewInfo(); }}); });
  items.push("-");
  items.push({label: "Show all columns", action: function(){ hiddenCols = {}; applyColumnStyles(); renderViewInfo(); }, disabled: !hidden.length});
  items.push({label: "Reset all column widths", action: function(){ widths = {}; applyColumnStyles(); }, disabled: !Object.keys(widths).length});
  openMenu(ev, items);
}

// ---- row selection, hiding and deleting ----
function selCount(){ return Object.keys(selected).length; }
function setSelection(ids){ selected = {}; ids.forEach(function(i){ selected[i] = true; }); paintSelection(); }
function paintSelection(){ Array.prototype.forEach.call(tbody.children, function(tr){ tr.className = selected[tr.getAttribute("data-i")] ? "sel" : ""; }); }
tbody.addEventListener("click", function(ev){
  if (ev.target.closest("a")) return;
  var tr = ev.target.closest("tr"); if (!tr) return;
  var i = Number(tr.getAttribute("data-i"));
  if (ev.shiftKey && lastClicked !== null) {
    var ids = CURRENT.map(function(r){ return r.__i; }), a = ids.indexOf(lastClicked), b = ids.indexOf(i);
    if (a >= 0 && b >= 0) { if (!(ev.ctrlKey || ev.metaKey)) selected = {}; ids.slice(Math.min(a,b), Math.max(a,b)+1).forEach(function(x){ selected[x] = true; }); }
    if (window.getSelection) window.getSelection().removeAllRanges();
  } else if (ev.ctrlKey || ev.metaKey) {
    if (selected[i]) delete selected[i]; else selected[i] = true; lastClicked = i;
  } else {
    selected = {}; selected[i] = true; lastClicked = i;
  }
  paintSelection(); renderViewInfo();
});
tbody.addEventListener("contextmenu", function(ev){
  var tr = ev.target.closest("tr"); if (!tr) return;
  ev.preventDefault();
  var i = Number(tr.getAttribute("data-i"));
  if (!selected[i]) { setSelection([i]); lastClicked = i; }
  rowMenu(ev);
});
function rowMenu(ev){
  var n = selCount(), h = Object.keys(hiddenRows).length, d = Object.keys(deletedRows).length;
  openMenu(ev, [
    {label: "Hide selected row" + (n===1?"":"s") + " (" + n + ")", action: hideSelected, disabled: !n},
    {label: "Delete selected row" + (n===1?"":"s") + " (" + n + ")", action: deleteSelected, disabled: !n},
    "-",
    {label: "Select all visible rows (" + CURRENT.length + ")", action: function(){ setSelection(CURRENT.map(function(r){return r.__i;})); renderViewInfo(); }},
    {label: "Clear selection", action: function(){ setSelection([]); renderViewInfo(); }, disabled: !n},
    "-",
    {label: "Show hidden rows (" + h + ")", action: function(){ hiddenRows = {}; render(); }, disabled: !h},
    {label: "Undo all deletions (" + d + ")", action: function(){ deletedRows = {}; render(); }, disabled: !d}
  ]);
}
function hideSelected(){ Object.keys(selected).forEach(function(i){ hiddenRows[i] = true; }); selected = {}; render(); }
function deleteSelected(){
  var n = selCount(); if (!n) return;
  if (!window.confirm("Delete " + n + " row" + (n===1?"":"s") + " from this report?\nDeleted rows are removed from the summary, the CSV export and a saved edited report.")) return;
  Object.keys(selected).forEach(function(i){ deletedRows[i] = true; }); selected = {}; render();
}
document.addEventListener("keydown", function(ev){
  if (ev.key === "Escape") { closeMenu(); if (selCount()) { setSelection([]); renderViewInfo(); } }
  if (ev.key === "Delete" && selCount() && !/^(INPUT|SELECT|TEXTAREA)$/.test((ev.target.tagName||""))) { ev.preventDefault(); deleteSelected(); }
});
function renderViewInfo(){
  var box = document.getElementById("viewinfo"); box.innerHTML = "";
  var parts = [], n = selCount(), h = Object.keys(hiddenRows).length, d = Object.keys(deletedRows).length, hc = hiddenColList().length;
  function link(text, fn){ var a = el("a",null,text); a.addEventListener("click", fn); return a; }
  if (n) parts.push(document.createTextNode(n + " selected"));
  if (h) parts.push(link(h + " hidden row" + (h===1?"":"s") + " (show)", function(){ hiddenRows = {}; render(); }));
  if (d) parts.push(link(d + " deleted (undo)", function(){ deletedRows = {}; render(); }));
  if (hc) parts.push(link(hc + " hidden column" + (hc===1?"":"s") + " (show)", function(){ hiddenCols = {}; applyColumnStyles(); renderViewInfo(); }));
  parts.forEach(function(p, idx){ if (idx) box.appendChild(document.createTextNode(" \u00b7 ")); box.appendChild(p); });
}

// ---- summary ----
function counts(rows, key){
  var c = {};
  rows.forEach(function(r){ var v=r[key]; (Array.isArray(v)?(v.length?v:["(none)"]):[v===""||v===null?"(none)":v]).forEach(function(x){ c[x]=(c[x]||0)+1; }); });
  return Object.keys(c).map(function(k){return [k,c[k]];}).sort(function(a,b){return b[1]-a[1];});
}
function card(n,l){ var d=el("div",{"class":"card"}); d.appendChild(el("div",{"class":"n"},n)); d.appendChild(el("div",{"class":"l"},l)); return d; }
function pie(title, key, rows, colorType){
  var data = counts(rows, key), total = data.reduce(function(s,d){return s+d[1];},0);
  var box = el("div",{"class":"chart"}); box.appendChild(el("h3",null,title));
  var body = el("div",{"class":"body"}); box.appendChild(body);
  var canvas = el("canvas",{width:140,height:140}); body.appendChild(canvas);
  var legend = el("div",{"class":"legend"}); body.appendChild(legend);
  var ctx = canvas.getContext ? canvas.getContext("2d") : null, start=-Math.PI/2;
  if (!ctx) { ctx = {beginPath:function(){},moveTo:function(){},arc:function(){},closePath:function(){},fill:function(){},stroke:function(){},fillText:function(){}}; }
  if (!total){ ctx.fillStyle="#999"; ctx.font="12px sans-serif"; ctx.fillText("no data",45,72); }
  data.forEach(function(d,i){
    var col = (colorType && color(colorType,d[0])) || (key==="status" && D.colors.status[d[0]] ? "#"+D.colors.status[d[0]] : PALETTE[i%PALETTE.length]);
    var ang = d[1]/total*Math.PI*2;
    ctx.beginPath(); ctx.moveTo(70,70); ctx.arc(70,70,66,start,start+ang); ctx.closePath(); ctx.fillStyle=col; ctx.fill();
    ctx.strokeStyle="#fff"; ctx.lineWidth=1; ctx.stroke(); start+=ang;
    var item = el("div",{title:"Filter: "+d[0]}); item.appendChild(el("span",{"class":"sw",style:"background:"+col}));
    item.appendChild(el("span",null,d[0]+" \u2014 "+d[1]+" ("+Math.round(d[1]/total*100)+"%)"));
    item.addEventListener("click", function(){ applyLegendFilter(key, d[0]); });
    legend.appendChild(item);
  });
  return box;
}
function applyLegendFilter(key, value){
  if (value==="(none)") return;
  var sel = thead.querySelector('tr.f [data-key="'+key+'"]');
  if (sel && sel.tagName==="SELECT") { sel.value=value; setFilter(key,value,true); }
  else if (sel) { sel.value=value; setFilter(key,value,false); }
  else setFilter(key, [value], true);   // field without a table column (e.g. category): exact filter, cleared by Reset
}
function renderSummary(rows){
  var cards = document.getElementById("cards"); cards.innerHTML="";
  var by = function(k,v){ return rows.filter(function(r){return r[k]===v;}).length; };
  cards.appendChild(card(rows.length,"Vulnerabilities"));
  cards.appendChild(card(by("criticality","CRITICAL") + by("criticality","HIGH"),"Critical + High"));
  cards.appendChild(card(by("kev","YES"),"Known exploited"));
  cards.appendChild(card(m.stats.filtered_false_positives,"Rejected candidates"));
  var charts = document.getElementById("charts"); charts.innerHTML="";
  charts.appendChild(pie("By component","components",rows));
  charts.appendChild(pie("By category","categories",rows));
  charts.appendChild(pie("By source","sources",rows));
  charts.appendChild(pie("By project","projects",rows));
  charts.appendChild(pie("By criticality","criticality",rows,"severity"));
  charts.appendChild(pie("By applicability","applicability",rows,"applicability"));
}

// ---- full-height table: page scrolls vertically, table only horizontally ----
(function(){
  var wrap = document.querySelector(".tablewrap"), bar = document.getElementById("hscroll"), inner = bar.firstChild;
  var tbl = document.getElementById("tbl"), syncing = false;
  function sizeBar(){
    inner.style.width = tbl.scrollWidth + "px";
    bar.style.display = tbl.scrollWidth > wrap.clientWidth + 1 ? "block" : "none";
  }
  bar.addEventListener("scroll", function(){ if (syncing) { syncing=false; return; } syncing=true; wrap.scrollLeft = bar.scrollLeft; });
  wrap.addEventListener("scroll", function(){ if (syncing) { syncing=false; return; } syncing=true; bar.scrollLeft = wrap.scrollLeft; });
  // Keep both header rows visible while the page is scrolled through a long table.
  function pinHeader(){
    var head = tbl.tHead; if (!head) return;
    var r = tbl.getBoundingClientRect(), hh = head.getBoundingClientRect().height;
    var off = Math.max(0, Math.min(-r.top, r.height - hh - 30));
    var cells = head.querySelectorAll("th"), t = off ? "translateY(" + off + "px)" : "";
    for (var i = 0; i < cells.length; i++) cells[i].style.transform = t;
  }
  window.addEventListener("scroll", pinHeader, {passive:true});
  window.addEventListener("resize", function(){ sizeBar(); pinHeader(); });
  // Size changes (rows filtered, columns hidden or resized) re-measure the scroll bar.
  if (window.ResizeObserver) new ResizeObserver(function(){ sizeBar(); pinHeader(); }).observe(tbl);
  else if (window.MutationObserver) new MutationObserver(function(){ sizeBar(); pinHeader(); }).observe(tbl.tBodies[0] || tbl, {childList:true});
  setTimeout(sizeBar, 0);
  window.__sizeTableBar = sizeBar;
})();

// ---- toolbar ----
document.getElementById("global").addEventListener("input", function(e){ state.global=e.target.value; render(); });
document.getElementById("follow").addEventListener("change", render);
document.getElementById("reset").addEventListener("click", function(){
  state.filters={}; state.global=""; state.sort=[{key:"applicability",dir:-1},{key:"criticality",dir:-1},{key:"cvss_score",dir:-1}];
  document.getElementById("global").value="";
  Array.prototype.forEach.call(thead.querySelectorAll("input,select"), function(i){ if(i.type==="checkbox") i.checked=false; else i.value=""; });
  Array.prototype.forEach.call(thead.querySelectorAll(".multi-filter summary"), function(i){i.textContent="(all)";});
  render();
});
document.getElementById("export").addEventListener("click", function(){
  var esc = function(s){ s=asText(s).replace(/"/g,'""'); return /[",\n;]/.test(s) ? '"'+s+'"' : s; };
  var cols = COLS.filter(function(c){ return !hiddenCols[c.key]; });
  var lines = [cols.map(function(c){return esc(c.label);}).join(",")];
  visibleRows().forEach(function(r){ lines.push(cols.map(function(c){return esc(r[c.key]);}).join(",")); });
  var blob = new Blob(["\ufeff"+lines.join("\n")],{type:"text/csv;charset=utf-8"});
  var a = el("a",{href:URL.createObjectURL(blob),download:"filtered_vulnerabilities.csv"}); document.body.appendChild(a); a.click(); a.remove();
});
document.getElementById("saveview").addEventListener("click", function(){
  var data = JSON.parse(JSON.stringify(D));
  data.rows = ROWS.filter(function(r){ return !deletedRows[r.__i]; }).map(function(r){ var c = {}; for (var k in r) if (k !== "__i") c[k] = r[k]; return c; });
  data.view = {hiddenCols: hiddenCols, widths: widths};
  var doc = document.documentElement.cloneNode(true);
  ["#tbl thead", "#tbl tbody", "#cards", "#charts", "#meta", "#count", "#viewinfo"].forEach(function(sel){ var n = doc.querySelector(sel); if (n) n.innerHTML = ""; });
  Array.prototype.forEach.call(doc.querySelectorAll(".ctx"), function(n){ n.remove(); });
  Array.prototype.forEach.call(doc.querySelectorAll("head style"), function(n, idx){ if (idx > 0) n.remove(); });
  Array.prototype.forEach.call(doc.querySelectorAll("input"), function(n){ n.removeAttribute("value"); });
  doc.querySelector("#report-data").textContent = JSON.stringify(data).replace(/<\//g, "<\\/");
  var blob = new Blob(["<!DOCTYPE html>\n" + doc.outerHTML], {type: "text/html;charset=utf-8"});
  var name = (location.pathname.split("/").pop() || "report.html").replace(/\.html?$/i, "") + "_edited.html";
  var a = el("a",{href:URL.createObjectURL(blob),download:name}); document.body.appendChild(a); a.click(); a.remove();
});
applyColumnStyles();
render();
})();
</script>
</body></html>
"""
