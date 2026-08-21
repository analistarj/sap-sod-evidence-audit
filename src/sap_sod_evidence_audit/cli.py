"""Command line interface for the offline MVP."""

from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import date
from pathlib import Path

from sap_sod_evidence_audit import __version__
from sap_sod_evidence_audit.analyzer import analyze
from sap_sod_evidence_audit.loader import BundleValidationError, load_bundle, parse_date
from sap_sod_evidence_audit.reporting import build_report, write_json_report


def parser() -> argparse.ArgumentParser:
    command = argparse.ArgumentParser(
        prog="sap-sod-evidence-audit",
        description="Analyze offline SAP SoD evidence with explainable risk and confidence scores.",
    )
    command.add_argument("bundle", type=Path, help="Directory containing normalized CSV exports")
    command.add_argument("--rules", required=True, type=Path, help="Versioned JSON SoD ruleset")
    command.add_argument("--output", required=True, type=Path, help="Pseudonymized JSON report")
    command.add_argument(
        "--analysis-date", help="ISO date used for assignments and mitigations, default: today"
    )
    command.add_argument("--version", action="version", version=__version__)
    return command


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        analysis_date = parse_date(args.analysis_date) if args.analysis_date else date.today()
        if analysis_date is None:
            raise BundleValidationError("analysis date is required")
        bundle = load_bundle(args.bundle, args.rules)
        findings = analyze(bundle, analysis_date)
        report = build_report(
            findings, bundle, analysis_date, os.getenv("SAP_SOD_HMAC_SECRET")
        )
        write_json_report(args.output, report)
        summary = {
            key: report[key]
            for key in (
                "environment_score",
                "environment_level",
                "finding_count",
                "observed_conflict_count",
                "valid_mitigation_count",
                "counts_by_level",
            )
        }
        print(json.dumps(summary, ensure_ascii=False))
        return 0
    except (OSError, ValueError, json.JSONDecodeError, BundleValidationError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
