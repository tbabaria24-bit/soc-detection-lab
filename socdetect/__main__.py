"""Command-line interface.

    python -m socdetect analyze sample_logs/
    python -m socdetect analyze /path/to/auth.log --year 2026 --out reports/
    python -m socdetect rules
    python -m socdetect validate
"""

from __future__ import annotations

import argparse
import sys
from datetime import datetime
from pathlib import Path

from . import __version__
from .engine import SEVERITY_ORDER, RuleError, load_rules, run_rules
from .parsers import load_logs
from .report import console_summary, write_reports

DEFAULT_RULES = Path(__file__).resolve().parent.parent / "rules"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="socdetect", description="Detect attacks in security logs.")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument("--rules", type=Path, default=DEFAULT_RULES, help="folder of YAML rules")
    sub = parser.add_subparsers(dest="command", required=True)

    a = sub.add_parser("analyze", help="analyze log files or folders and write reports")
    a.add_argument("logs", nargs="+", type=Path, help="log files or folders")
    a.add_argument("--out", type=Path, default=Path("reports"), help="output folder (default: reports)")
    a.add_argument("--year", type=int, default=datetime.now().year,
                   help="year for Linux syslog lines, which carry no year (default: this year)")
    a.add_argument("--min-severity", choices=list(SEVERITY_ORDER), default="informational",
                   help="only report alerts at or above this severity")
    a.add_argument("--fail-on", choices=list(SEVERITY_ORDER),
                   help="exit with code 1 if any alert is at or above this severity (for pipelines)")

    sub.add_parser("rules", help="list the loaded detection rules")
    sub.add_parser("validate", help="check every rule file and exit")

    args = parser.parse_args(argv)
    try:
        rules = load_rules(args.rules)
    except RuleError as exc:
        print(f"Rule error: {exc}", file=sys.stderr)
        return 2

    if args.command == "validate":
        print(f"OK: {len(rules)} rules are valid.")
        return 0

    if args.command == "rules":
        for r in sorted(rules, key=lambda r: (r.logsource, r.id)):
            print(f"{r.id:34} {r.severity:8} {r.technique_id:10} {r.logsource:8} {r.title}")
        return 0

    missing = [p for p in args.logs if not p.exists()]
    if missing:
        print(f"Not found: {', '.join(map(str, missing))}", file=sys.stderr)
        return 2
    try:
        events, stats = load_logs(args.logs, args.year)
    except ValueError as exc:
        print(f"Log error: {exc}", file=sys.stderr)
        return 2

    limit = SEVERITY_ORDER[args.min_severity]
    alerts = [al for al in run_rules(rules, events) if SEVERITY_ORDER[al.rule.severity] <= limit]
    paths = write_reports(alerts, rules, stats, args.out)

    print(f"Analyzed {stats['events']} events from {stats['files']} files "
          f"({stats['skipped_lines']} unparsed lines) with {len(rules)} rules.\n")
    print(console_summary(alerts))
    print(f"\n{len(alerts)} alerts. Reports written to:")
    for p in paths.values():
        print(f"  {p}")

    if args.fail_on and any(SEVERITY_ORDER[al.rule.severity] <= SEVERITY_ORDER[args.fail_on] for al in alerts):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
