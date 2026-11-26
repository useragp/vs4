#!/usr/bin/env python3
"""Automotive component vulnerability scanner - entry point.

GUI:  python main.py [components.json]
CLI:  python main.py --cli components.json --days 7

Reports are written to <reports folder>/vuln_report_YYYYMMDD_HHMMSS/vuln_report_YYYYMMDD_HHMMSS.*
(the reports folder is created automatically; default: 'reports' next to this file).
"""

import argparse
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)


def main() -> int:
    if sys.version_info < (3, 8):
        print("Python 3.8 or newer is required.")
        return 2
    from vulnscan.scanner import DEFAULT_REPORTS_DIR, LOOKBACK_CHOICES

    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("components", nargs="?", default=os.path.join(HERE, "components.json"))
    parser.add_argument("--cli", action="store_true", help="run headless (CI / scheduled jobs)")
    period = parser.add_mutually_exclusive_group()
    period.add_argument("--days", type=int, choices=LOOKBACK_CHOICES, default=None,
                        help="look-back period: the last N days (default 7)")
    period.add_argument("--start", metavar="YYYY-MM-DD",
                        help="custom date range: from this date (instead of --days)")
    parser.add_argument("--end", metavar="YYYY-MM-DD", default="",
                        help="end of the custom date range, inclusive (default: today; needs --start)")
    parser.add_argument("--date-fields", choices=["both", "published", "modified"], default="both",
                        help="which dates the period applies to: published, last modified, or both "
                             "(default both = published OR last modified inside the period)")
    parser.add_argument("--include-deferred", action="store_true",
                        help="also report CVEs whose NVD status is 'Deferred' (left out by default)")
    parser.add_argument("--output", default=DEFAULT_REPORTS_DIR,
                        help="reports folder (created if missing; one sub-folder per scan)")
    parser.add_argument("--api-key", default=os.environ.get("NVD_API_KEY", ""))
    parser.add_argument("--no-cpe", action="store_true")
    parser.add_argument("--no-keywords", action="store_true")
    parser.add_argument("--no-cve-org", action="store_true",
                        help="do not use CVE.org CNA data to verify CVEs not yet analysed by NVD")
    parser.add_argument("--no-osv", action="store_true")
    parser.add_argument("--no-kev", action="store_true")
    parser.add_argument("--lenient", action="store_true", help="disable strict false-positive filtering")
    parser.add_argument("--min-applicability", type=str.upper, choices=["HIGH", "MEDIUM", "LOW", "ALL"], default="LOW",
                        help="ALL also lists every candidate judged NOT APPLICABLE, with the reason")
    parser.add_argument("--scope", choices=["core", "ecosystem"], default="core",
                        help="core = only the product itself (e.g. the runtime, compiler, Git, Bash); "
                             "ecosystem = also libraries, plugins, frameworks and APIs built on it")
    parser.add_argument("--project", help="scan only components used in this project")
    parser.add_argument("--category", action="append", default=[],
                        help="report only components of this category (repeatable), e.g. "
                             "--category \"Core Component\" or --category \"Package / Library\"")
    parser.add_argument("--list-categories", action="store_true",
                        help="print the category of every component and exit")
    parser.add_argument("--formats", default="csv,xlsx,html,json")
    parser.add_argument("--csv-delimiter", choices=[";", ","], default=";",
                        help="';' (default) suits Excel with Polish/European regional settings")
    args = parser.parse_args()

    if not args.cli and not args.list_categories:
        from vulnscan.gui import run_gui
        run_gui(args.components)
        return 0

    from vulnscan.models import load_components
    from vulnscan.scanner import ScanOptions, Scanner

    comps = load_components(args.components)
    if args.list_categories:
        for c in sorted(comps, key=lambda c: (c.effective_category, c.name)):
            print("{:<22} {}".format(c.effective_category, c.label))
        return 0
    if args.project:
        comps = [c for c in comps if args.project in c.projects]
    from vulnscan.scanner import parse_date_range
    start_date = end_date = None
    if args.end and not args.start:
        parser.error("--end needs --start")
    if args.start:
        try:
            start_date, end_date = parse_date_range(args.start, args.end)
        except ValueError as exc:
            parser.error(str(exc))
    opts = ScanOptions(lookback_days=args.days or 7, start_date=start_date, end_date=end_date,
                       output_dir=args.output, nvd_api_key=args.api_key,
                       use_nvd_cpe=not args.no_cpe, use_nvd_keywords=not args.no_keywords,
                       use_cve_org=not args.no_cve_org,
                       use_osv=not args.no_osv, use_kev=not args.no_kev, strict=not args.lenient,
                       min_applicability=args.min_applicability, scope=args.scope,
                       categories=tuple(args.category),
                       formats=tuple(f.strip() for f in args.formats.split(",") if f.strip()),
                       csv_delimiter=args.csv_delimiter,
                       include_rejected_candidates=args.min_applicability == "ALL",
                       date_published=args.date_fields in ("both", "published"),
                       date_modified=args.date_fields in ("both", "modified"),
                       include_deferred=args.include_deferred)
    result = Scanner(comps, opts, log=print).run()
    # Exit code 1 when NEW high-applicability findings exist (useful for CI gates).
    return 1 if any(v.status == "NEW" and v.applicability == "HIGH" for v in result.vulnerabilities) else 0


if __name__ == "__main__":
    sys.exit(main())
