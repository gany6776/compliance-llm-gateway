"""
Command Line Interface for compliance-llm-gateway.

Entry point: compliance-gateway (or python -m compliance_gateway.cli)

Subcommands:
  sanitize --mode strict         Reads stdin, outputs sanitized text, prints redaction summary to stderr
  audit verify --audit-path ...  Verify chain integrity
  audit stats  --audit-path ...  Show statistics
  audit query  --tier N --model M --start YYYY-MM-DD  Query records
"""

import argparse
import json
import sys

from .sanitizer import Sanitizer
from .audit import AuditLogger


def cmd_sanitize(args):
    sanitizer = Sanitizer(mode=args.mode)
    text = sys.stdin.read()
    result = sanitizer.sanitize(text)
    sys.stdout.write(result.clean_text)
    print(
        f"\n[Redaction Summary] {len(result.redactions)} redaction(s) applied.",
        file=sys.stderr,
    )
    for r in result.redactions:
        print(f"  - Stage {r['stage']}: [{r['type']}] at position {r['position']}", file=sys.stderr)


def cmd_audit_verify(args):
    logger = AuditLogger(audit_path=args.audit_path)
    result = logger.verify_chain(audit_path=args.audit_path)
    print(json.dumps(result, indent=2))
    if result.get("status") != "valid":
        sys.exit(1)


def cmd_audit_stats(args):
    logger = AuditLogger(audit_path=args.audit_path)
    stats = logger.get_stats(audit_path=args.audit_path)
    print(json.dumps(stats, indent=2))


def cmd_audit_query(args):
    logger = AuditLogger(audit_path=args.audit_path)
    records = logger.query(
        tier=args.tier,
        model=args.model,
        start_date=args.start,
        end_date=args.end,
        audit_path=args.audit_path,
    )
    print(json.dumps(records, indent=2))


def main():
    parser = argparse.ArgumentParser(
        prog="compliance-gateway",
        description="Regulatory data compliance proxy for LLM APIs",
    )
    subparsers = parser.add_subparsers(dest="command")

    # sanitize subcommand
    sanitize_parser = subparsers.add_parser("sanitize", help="Sanitize text from stdin")
    sanitize_parser.add_argument(
        "--mode",
        choices=["strict", "pci_dss", "hipaa", "moderate"],
        default="strict",
        help="Sanitization mode (default: strict)",
    )

    # audit subcommand
    audit_parser = subparsers.add_parser("audit", help="Audit trail operations")
    audit_sub = audit_parser.add_subparsers(dest="audit_command")

    # audit verify
    verify_parser = audit_sub.add_parser("verify", help="Verify audit chain integrity")
    verify_parser.add_argument("--audit-path", default="./audit", help="Path to audit directory")

    # audit stats
    stats_parser = audit_sub.add_parser("stats", help="Show audit statistics")
    stats_parser.add_argument("--audit-path", default="./audit", help="Path to audit directory")

    # audit query
    query_parser = audit_sub.add_parser("query", help="Query audit records")
    query_parser.add_argument("--audit-path", default="./audit", help="Path to audit directory")
    query_parser.add_argument("--tier", type=int, default=None, help="Filter by tier")
    query_parser.add_argument("--model", type=str, default=None, help="Filter by model name")
    query_parser.add_argument("--start", type=str, default=None, help="Start date YYYY-MM-DD")
    query_parser.add_argument("--end", type=str, default=None, help="End date YYYY-MM-DD")

    args = parser.parse_args()

    if args.command == "sanitize":
        cmd_sanitize(args)
    elif args.command == "audit":
        if args.audit_command == "verify":
            cmd_audit_verify(args)
        elif args.audit_command == "stats":
            cmd_audit_stats(args)
        elif args.audit_command == "query":
            cmd_audit_query(args)
        else:
            audit_parser.print_help()
            sys.exit(1)
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
