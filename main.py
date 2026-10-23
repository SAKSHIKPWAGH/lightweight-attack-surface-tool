"""Lightweight Attack Surface Analysis Tool v2 - command line interface.

Examples:
    python main.py localhost --authorized --ports 8000
    python main.py scanme.nmap.org --authorized --profile quick
    python main.py yourdomain.com --authorized --profile extended --no-passive

Only assess systems you own or have explicit written permission to test.
"""
import argparse
import os
import sys

from core.safety import audit, is_protected
from core.scanner import run_scan
from modules.port_scan import PROFILES
from modules.validator import is_valid_target, normalize_target, parse_ports
from reports import history
from reports.report import print_summary, save_csv, save_html, save_json, save_md
from reports.risk import analyze, score


def build_parser():
    ap = argparse.ArgumentParser(description="Lightweight Attack Surface Analysis Tool v2")
    ap.add_argument("target", help="domain, IP or localhost")
    ap.add_argument("--authorized", action="store_true", help="confirm you have permission to assess the target")
    ap.add_argument("--profile", choices=PROFILES, default="common", help="port profile (default: common)")
    ap.add_argument("--ports", type=parse_ports, help="explicit comma-separated ports (overrides profile)")
    ap.add_argument("--no-subdomains", action="store_true", help="skip subdomain discovery")
    ap.add_argument("--no-passive", action="store_true", help="skip passive discovery via crt.sh")
    ap.add_argument("--no-paths", action="store_true", help="skip sensitive-file checks (.git, .env ...)")
    ap.add_argument("--no-tls-probe", action="store_true", help="skip TLS protocol-version probing")
    ap.add_argument("--dns-server", default="8.8.8.8", help="resolver for DNS/email checks (default 8.8.8.8)")
    ap.add_argument("--timeout", type=float, default=1.0, help="port connect timeout (s)")
    ap.add_argument("--http-timeout", type=float, default=6.0, help="HTTP/TLS timeout (s)")
    ap.add_argument("--threads", type=int, default=50)
    ap.add_argument("--delay", type=float, default=0.0, help="pause between hosts (s) to stay polite")
    ap.add_argument("--max-hosts", type=int, default=25, help="cap on hosts scanned")
    ap.add_argument("--formats", default="html,json,csv,md", help="comma list: html,json,csv,md")
    ap.add_argument("--output", default="output", help="output directory")
    ap.add_argument("--no-history", action="store_true", help="do not store/compare scan history")
    return ap


def main(argv=None):
    a = build_parser().parse_args(argv)
    a.target = normalize_target(a.target)
    if not is_valid_target(a.target):
        sys.exit("Invalid target: %s" % a.target)
    if is_protected(a.target):
        sys.exit("Refused: %s belongs to a protected third-party/government zone. Assess only systems "
                 "you own or are explicitly authorised to test (see core/safety.py)." % a.target)
    if not a.authorized:
        if input("Do you own or have written permission to assess %s? (yes/no): " % a.target).strip().lower() != "yes":
            sys.exit("Aborted: authorization is required.")
    audit(a.output, a.target, sys.argv[1:] if argv is None else argv)

    results = run_scan(a)
    findings = analyze(results)
    summary = score(findings, results)

    diff = None
    if not a.no_history:
        diff = history.diff(history.load_previous(a.output, a.target), results, findings, summary)
        history.save(a.output, results, findings, summary)

    os.makedirs(a.output, exist_ok=True)
    print_summary(results, findings, summary, diff)
    fmts = {f.strip() for f in a.formats.split(",")}
    out = []
    if "json" in fmts:
        out.append(save_json(results, findings, summary, diff, a.output))
    if "csv" in fmts:
        out.append(save_csv(findings, a.output))
    if "md" in fmts:
        out.append(save_md(results, findings, summary, a.output))
    if "html" in fmts:
        out.append(save_html(results, findings, summary, diff, a.output))
    print("\n Reports written:")
    for p in out:
        print("   " + p)
    return results, findings, summary


if __name__ == "__main__":
    main()
