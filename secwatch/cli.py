"""Command-line interface for SecWatch."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from secwatch import __version__
from secwatch.detections import DetectionEngine, load_rules
from secwatch.hardening import run_hardening_checks
from secwatch.iac import scan_terraform_plan
from secwatch.models import SEVERITY_ORDER, Finding
from secwatch.parsers import parse_auth_log, parse_cloudtrail, parse_web_log
from secwatch.reporting import write_reports

DEFAULT_RULES = Path(__file__).parent / "rules"


def _detect(args: argparse.Namespace) -> list[Finding]:
    events = []
    if args.auth:
        events += parse_auth_log(args.auth, year=args.year)
    if args.web:
        events += parse_web_log(args.web)
    if args.cloudtrail:
        events += parse_cloudtrail(args.cloudtrail)
    rules = load_rules(args.rules)
    print(f"[*] Loaded {len(rules)} rules and {len(events)} events", file=sys.stderr)
    return DetectionEngine(rules).run(events)


def _print_table(findings: list[Finding]) -> None:
    if not findings:
        print("No findings.")
        return
    for f in sorted(findings, key=lambda x: -x.severity_rank):
        print(f"{f.severity.upper():<9} {f.rule_id:<13} {f.title[:55]:<55} {f.entity[:45]}")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="secwatch", description="Security detection, hardening, and IaC auditing toolkit.")
    p.add_argument("--version", action="version", version=f"secwatch {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    def common(sp: argparse.ArgumentParser) -> None:
        sp.add_argument("-o", "--out", default="reports", help="Output directory (default: reports)")
        sp.add_argument("-f", "--format", default="json,md,html", help="Comma-separated: json,md,html,sarif")
        sp.add_argument("--fail-on", choices=list(SEVERITY_ORDER), help="Exit 1 if a finding is at or above this severity")

    d = sub.add_parser("detect", help="Run detection rules against logs")
    d.add_argument("--auth", help="Linux auth.log path")
    d.add_argument("--web", help="Web access log path (combined format)")
    d.add_argument("--cloudtrail", help="AWS CloudTrail JSON path")
    d.add_argument("--rules", default=str(DEFAULT_RULES), help="Directory of YAML rules")
    d.add_argument("--year", type=int, help="Year for syslog timestamps (default: current year)")
    common(d)

    h = sub.add_parser("harden", help="Audit Linux hardening (read-only)")
    h.add_argument("--root", default="/", help="Filesystem root to audit (default: /)")
    common(h)

    i = sub.add_parser("iac", help="Scan a Terraform plan JSON for misconfigurations")
    i.add_argument("--plan", required=True, help="Output of 'terraform show -json plan.out'")
    common(i)

    r = sub.add_parser("rules", help="List loaded detection rules")
    r.add_argument("--rules", default=str(DEFAULT_RULES))
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    if args.command == "rules":
        for rule in load_rules(args.rules):
            print(f"{rule.id:<10} {rule.severity:<9} {rule.type:<10} {rule.mitre_technique:<45} {rule.title}")
        return 0

    if args.command == "detect":
        if not (args.auth or args.web or args.cloudtrail):
            print("error: provide at least one of --auth, --web, --cloudtrail", file=sys.stderr)
            return 2
        findings = _detect(args)
    elif args.command == "harden":
        findings = run_hardening_checks(args.root)
    else:
        findings = scan_terraform_plan(args.plan)

    _print_table(findings)
    formats = [x.strip() for x in args.format.split(",") if x.strip()]
    for path in write_reports(findings, args.out, formats, name=args.command):
        print(f"[+] Wrote {path}", file=sys.stderr)

    if args.fail_on:
        threshold = SEVERITY_ORDER[args.fail_on]
        if any(f.severity_rank >= threshold for f in findings):
            print(f"[!] Findings at or above '{args.fail_on}' severity", file=sys.stderr)
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
