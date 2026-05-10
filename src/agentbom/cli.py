"""Command line interface for AgentBOM."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .report import write_reports
from .sarif import write_sarif_report
from .scanner import scan_path


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="agentbom")
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan_parser = subparsers.add_parser("scan", help="scan a repository")
    scan_parser.add_argument("path", help="path to scan")
    scan_parser.add_argument("--output-dir", default=".", help="directory for agentbom.json and agentbom.md")
    scan_parser.add_argument("--pretty", action="store_true", help="pretty-print JSON output")
    scan_parser.add_argument("--sarif", action="store_true", help="write agentbom.sarif")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "scan":
        try:
            bom = scan_path(args.path)
            json_path, md_path = write_reports(bom, Path(args.output_dir), pretty=args.pretty)
            sarif_path = None
            if args.sarif:
                sarif_path = write_sarif_report(bom, Path(args.output_dir), pretty=args.pretty)
        except (FileNotFoundError, NotADirectoryError, PermissionError) as exc:
            print(f"agentbom: {exc}", file=sys.stderr)
            return 1
        print(f"Wrote {json_path}")
        print(f"Wrote {md_path}")
        if sarif_path is not None:
            print(f"Wrote {sarif_path}")
        return 0

    parser.error("unknown command")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
