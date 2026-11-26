# Automotive Component Vulnerability Scanner

Python 3.8+ desktop tool (tkinter) for monitoring vulnerabilities in the components your company
uses (MCUs, toolchains, debug probes, interpreters, OS/firmware, libraries). It reads a JSON
component list and writes CSV, XLSX, HTML and JSON reports.

## Install & run
```bash
python -m pip install -r requirements.txt            # requests, openpyxl
python main.py                                       # GUI, loads ./components.json
python main.py my_components.json                    # GUI with another list
python main.py --cli components.json --days 7        # headless (CI / scheduled task)
python main.py --cli components.json --start 2026-09-01 --end 2026-09-30   # custom date range
```
Optional: a free NVD API key (https://nvd.nist.gov/developers/request-an-api-key) makes scans
about 10x faster. Enter it in the GUI or set `NVD_API_KEY`.
CLI exit code 1 = NEW findings with HIGH applicability exist (useful as a CI gate).
Run the tests with `python -m unittest discover -s tests`.

### CLI options
| option | meaning |
|---|---|
| `--days {1,7,14,30}` | look-back period: the last N days (default 7) |
| `--start YYYY-MM-DD` / `--end YYYY-MM-DD` | custom date range instead of `--days` (inclusive, UTC days; `--end` defaults to today) |
| `--date-fields {both,published,modified}` | which dates the period applies to (default `both`: published **or** last modified inside the period) |
| `--include-deferred` | also report CVEs whose NVD status is "Deferred" (left out of every report by default) |
| `--min-applicability {HIGH,MEDIUM,LOW,ALL}` | `ALL` also lists every candidate judged NOT APPLICABLE, with the reason |
| `--scope {core,ecosystem}` | `core` (default): only the product itself (runtime, compiler, Git, Bash). `ecosystem`: also libraries, plugins, frameworks, APIs built on it |
| `--output DIR` | reports folder (default `reports` next to `main.py`, created automatically) |
| `--category NAME` | report only components of this category (repeatable); `--list-categories` shows them |
| `--project NAME` | only components used in this project |
| `--lenient` | keep weak keyword-only evidence as LOW (strict mode is the default) |
| `--no-cpe --no-keywords --no-cve-org --no-osv --no-kev` | switch individual sources off |
| `--formats csv,xlsx,html,json`, `--csv-delimiter {;,,}` | output formats; `;` (default) suits Excel with Polish/European settings |

## Where reports go
Every scan creates its own folder, named with the existing naming convention:
```
reports/
  .vuln_history.json                         remembers applicable findings -> NEW / OLD
  vuln_report_20261114_183000/
    vuln_report_20261114_183000.csv
    vuln_report_20261114_183000.xlsx
    vuln_report_20261114_183000.html
    vuln_report_20261114_183000.json
```

## Project layout
```
main.py                 entry point (GUI / --cli)
components.json         sample component list
vulnscan/models.py      Component + Vulnerability model, merge logic, HTML report columns
vulnscan/versions.py    version comparison (rc/alpha, OpenSSL letters, p1 patch levels, epochs,
                        build metadata), CNA constraint parsing ('< 3.1.41', '3.8.*'), CPE 2.3
vulnscan/cvss.py        CVSS v3.x base score calculator, severity mapping
vulnscan/sources.py     NVD CVE API 2.0, NVD CPE dictionary, CVE.org records, OSV.dev, CISA KEV
vulnscan/matcher.py     applicability + scope assessment = false-positive filter
vulnscan/scanner.py     orchestration, look-back window, de-duplication, history, report folder
vulnscan/reports.py     CSV / XLSX / JSON (shared columns) and the interactive HTML report
vulnscan/gui.py         tkinter GUI
tests/                  unit + end-to-end tests (mocked HTTP)
```

## Component JSON
| field | meaning |
|---|---|
| name, version, type | type: software, hardware, firmware, tool, library, os. **The version field is used for all version checks** (the CPE version is only a fallback) |
| description, vendor, manufacturer | free text. vendor/manufacturer are also used as evidence |
| keywords, aliases | exact phrases searched in NVD descriptions (whole-word verified) |
| cpe | list of CPE 2.3 names. **The most precise way to match.** Use "Look up in NVD..." in the edit dialog |
| projects | projects where the component is used |
| exclude_keywords | CVEs whose description contains one of these are not applicable (e.g. "Git Bash") |
| purl / osv_ecosystem + osv_package | open-source packages checked on OSV.dev (e.g. `pkg:pypi/requests@2.25.1`) |
| category | optional, derived automatically when empty (see below) |
| enabled | include in scans |

## How a candidate is judged
Each CVE found by CPE or keyword search is checked against the component with the strongest
evidence available:

1. **NVD CPE configuration** (CVE analysed by NVD): vendor:product and version ranges
   (start/end including/excluding, exact versions, CPE update fields such as bash `5.1:patch8`).
   If the product is listed only as the platform an application runs on, or only other products are
   listed, the CVE is not about your component.
2. **CVE.org record** (most new CVEs are not analysed by NVD for weeks): the vendor/CNA's own
   "affected" data - product name, version ranges (`lessThan`, `< 3.1.41`, `3.8.*`), unaffected
   versions and default status. If the CNA only lists individual tested versions and leaves the
   rest "unknown", your version is reported as MEDIUM (not verifiable) instead of being dropped.
3. **Description text**: product/vendor mentions, version ranges next to the product
   ("Bash before 5.1.8", "Prior to versions 2.43.1, ..., and 2.39.4", "7.88 and earlier"; branch aware:
   3.10.4 is compared with the 3.10.x bound), and wording that reveals a library or plugin.

### Applicability
- **HIGH**: product and version inside an affected range confirmed by NVD, CVE.org (CNA) or OSV.dev.
- **MEDIUM**: product confirmed but the version cannot be verified, or the CVE is not analysed yet and
  the description names the product together with its vendor or an affected range containing your version.
- **LOW**: weak evidence (keyword only, kept only with `--lenient`), or an ecosystem item when the
  scope "Product + ecosystem" is selected.
- **NOT APPLICABLE**: version outside the affected range, a different product, the keyword occurs only
  inside another word (J-Link / J-Linker), exclude keyword, rejected CVE. Listed only with minimum
  applicability **ALL** - useful to see *everything* associated with a component (e.g. every J-Link CVE).

The *Applicability details* column states the reason for every component; the *Match method* column
shows how it was found, including the exact search term and the words that matched
(e.g. `NVD keyword search 'Python'; description contains 'Python'; confirmed by CVE.org CNA data`).

### Published vs. last-modified date
The scan period can apply to the CVE's **published** date, its **last modified** date, or both
(GUI: "Apply period to", both ticked by default; CLI: `--date-fields`). With both, a CVE is in scope when
either date falls inside the period, so CVEs that NVD re-analysed recently (new CPE data, a corrected
version range) are picked up too.

False-positive protection for modified-only CVEs: a CVE published *before* the period whose record was
merely updated in it (new reference, reformatted text) is usually an old, known issue. In strict mode such a
CVE is reported only when the component's version is **confirmed** affected (HIGH: NVD CPE range, CVE.org
CNA data or OSV.dev package version). Its Match method then says
`in scan period by last-modified date YYYY-MM-DD (published YYYY-MM-DD)`. The log counts the rejected ones.

When the period ends "now" (look-back mode), one last-modified query already covers every CVE published in
the period, so no extra NVD requests are made; a past date range runs both queries.

### Deferred CVEs
NVD marks CVEs it will not analyse as **Deferred**. They are excluded from the scan and from every report
(CSV, XLSX, JSON, HTML) unless "Include deferred" is ticked (CLI: `--include-deferred`). The log shows how
many were excluded; report headers state whether they were included.

### Core product vs. ecosystem (Python, Git, Bash, ...)
Many CVEs mention "Python", "Git" or "Bash" without being vulnerabilities *of* them:
GitPython, `python-multipart`, Flask, the Jenkins Git plugin, apps that "run on Linux"...
Every match therefore gets a scope:

| scope | evidence |
|---|---|
| core component | NVD/CNA lists the component itself; or the text names it with a version range, its vendor or a known product marker |
| ecosystem | NVD/CNA lists another product whose name is built from yours (msgpack-python, GitPython, a Jenkins `git` plugin), a package registry (PyPI, npm...), a "library/plugin/package for X" phrase, or your product is only the platform |
| (not applicable) | another product that merely mentions yours |

Choose in the GUI ("Product scope") or with `--scope`:
- **Core component only** (default): only vulnerabilities of the selected component itself (runtime, compiler, tool, firmware, etc.).
- **Component + ecosystem**: also libraries, plugins, frameworks and APIs built on or for the component (reported as LOW, scope "ecosystem").

To monitor a specific library, add it as its own component with a purl (`pkg:pypi/flask@2.0.1`);
OSV.dev then reports exactly that package and version.

### Categories
Set `"category"` or let it be derived: purl / OSV ecosystem (PyPI, npm, Maven, Cargo, Go, NuGet, RubyGems, Debian, RPM, etc.) ->
Package / Library; known runtime CPEs -> Core Component; otherwise the category is derived from component type. GUI: "Report only categories"; CLI: `--category`.

**Criticality**: from the CVSS base score (v3.1 > v3.0 > v4.0 > v2 preference): CRITICAL >= 9.0, HIGH >= 7.0,
MEDIUM >= 4.0, LOW > 0, otherwise UNKNOWN. CISA KEV membership is shown separately.

## Report columns (CSV, XLSX and JSON share one structure)
One vulnerability per row. Component name, version, vulnerability ID, link and criticality are the first fields.
CSV and XLSX start with report-generation time and the searched date range; JSON starts with a `_report_info`
record, followed by vulnerability records. Generation metadata is not repeated in each finding. The Link field
contains the direct vulnerability record URL; external reference lists are not included.

When one vulnerability affects several components, component names and versions are listed in matching order.
In CSV, embedded line breaks are replaced by ` | ` so every finding occupies exactly one row.

## De-duplication and NEW/OLD
Findings are keyed by ID **and aliases** (a GHSA advisory that maps to a CVE becomes one row).
`reports/.vuln_history.json` stores every *applicable* ID ever reported (NOT APPLICABLE entries listed
with ALL are not recorded); earlier JSON reports are read too. Findings seen before are marked **OLD**
(HTML report).

## HTML report
Self-contained (no internet/CDN). Summary with cards and pie charts by component, category, source,
project, criticality and applicability at the top; filters on every column; multi-column sort.
The findings table uses the full page height: scroll the page to see every row. Wide tables scroll
left/right with the bar pinned to the bottom of the window; the header row stays visible while scrolling.
- **Right-click a column header**: hide the column, show hidden columns, reset widths.
- **Drag the right edge of a header** to change the column width (double-click the edge to reset).
- **Click rows to select** (Ctrl/Cmd-click: add, Shift-click: range). **Right-click** the selection to
  hide or delete rows; Delete key deletes, Escape clears the selection. Hidden rows come back with
  "show"; deleted rows are removed from the summary and exports ("undo" until the page is reloaded).
- "Save edited report (HTML)" downloads the report without deleted rows and with your column layout.
- "Export visible rows (CSV)" exports what you see (visible columns, filtered/non-hidden rows).

## Limitations
- Hardware/MCU vulnerabilities are often published only in vendor PSIRT advisories (NXP, Infineon, ST,
  Renesas...). Those are found by keyword only. Add a hardware CPE when NVD has one.
- Text analysis is a heuristic; it is used only when neither NVD nor the CNA provides structured data.
  Use minimum applicability **ALL** to review what was judged not applicable and why.
- CVE.org data is fetched per candidate CVE (cached per scan); without network access to
  cveawg.mitre.org the scanner falls back to NVD/text evidence and reports a source error.
- Without an API key, NVD allows 5 requests per 30 s.

## Performance and NVD API key

- Component scans run concurrently (up to 4 workers). NVD requests share one
  process-wide throttle; the configured spacing is deliberately conservative
  (0.62 s with a key and 6.1 s without one) to remain below NVD's published
  50 requests / 30 seconds and 5 requests / 30 seconds limits.
- HTTP timeouts, network errors, HTTP 429/403 and server errors are retried with
  exponential backoff. `Retry-After` is honored when supplied.
- CVE.org is used as a fallback during NVD assessment when NVD configuration
  data does not provide a sufficient conclusion; it is not queried for every
  returned CVE.
- In the GUI, enter the NVD key and choose **Save securely**. The application
  stores it through Python `keyring` in the operating-system credential vault.
  The key is not written into project source files. For headless use, set the
  `NVD_API_KEY` environment variable or pass `--api-key`.
- Install dependencies with `pip install -r requirements.txt`. If the OS has no
  usable credential vault, the GUI can still use a key for the current session,
  but cannot persist it securely until a keyring backend is configured.

Never commit API keys to source control or share them with other users. If a key
has been exposed, revoke it and request a replacement through NVD.
