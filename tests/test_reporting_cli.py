import json
import os
import stat
from datetime import date
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import TestCase, mock

from sap_sod_evidence_audit.analyzer import analyze
from sap_sod_evidence_audit.cli import main
from sap_sod_evidence_audit.reporting import build_report, write_json_report
from sap_sod_evidence_audit.scoring import environment_score, risk_level
from tests.helpers import EXAMPLE, RULES, example_bundle

ANALYSIS_DATE = date(2026, 8, 21)


class ReportingTests(TestCase):
    def setUp(self):
        self.bundle = example_bundle()
        self.findings = analyze(self.bundle, ANALYSIS_DATE)

    def test_report_omits_raw_identifiers(self):
        rendered = json.dumps(build_report(self.findings, self.bundle, ANALYSIS_DATE))
        for raw_value in (
            "U_ALFA",
            "R_VENDOR_MAINT",
            "BR01",
            "DOC-P2P-001",
            "CTRL-INDEPENDENT-GL-REVIEW",
        ):
            self.assertNotIn(raw_value, rendered)
        self.assertIn("user_ref", rendered)

    def test_hmac_secret_changes_references(self):
        first = build_report(self.findings, self.bundle, ANALYSIS_DATE, "secret-one")
        second = build_report(self.findings, self.bundle, ANALYSIS_DATE, "secret-two")
        self.assertNotEqual(first["findings"][0]["user_ref"], second["findings"][0]["user_ref"])

    def test_hmac_secret_makes_references_stable(self):
        first = build_report(self.findings, self.bundle, ANALYSIS_DATE, "stable-secret")
        second = build_report(self.findings, self.bundle, ANALYSIS_DATE, "stable-secret")
        self.assertEqual(first["findings"][0]["user_ref"], second["findings"][0]["user_ref"])

    def test_ephemeral_secret_prevents_cross_report_correlation(self):
        first = build_report(self.findings, self.bundle, ANALYSIS_DATE)
        second = build_report(self.findings, self.bundle, ANALYSIS_DATE)
        self.assertNotEqual(first["findings"][0]["user_ref"], second["findings"][0]["user_ref"])

    def test_report_summary_matches_findings(self):
        report = build_report(self.findings, self.bundle, ANALYSIS_DATE)
        self.assertEqual(report["finding_count"], 5)
        self.assertEqual(report["observed_conflict_count"], 3)
        self.assertEqual(report["valid_mitigation_count"], 1)
        self.assertEqual(report["environment_score"], 86)
        self.assertEqual(report["ruleset_version"], "sap-sod-core-1.0.0")

    def test_atomic_report_is_private_on_posix(self):
        with TemporaryDirectory() as directory:
            path = Path(directory) / "report.json"
            write_json_report(path, {"ok": True})
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)

    def test_symbolic_link_destination_is_rejected(self):
        if not hasattr(os, "symlink"):
            self.skipTest("symbolic links unavailable")
        with TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "target.json"
            target.write_text("{}")
            link = root / "report.json"
            try:
                os.symlink(target, link)
            except OSError as error:
                self.skipTest(f"symbolic links unavailable: {error}")
            with self.assertRaisesRegex(ValueError, "symbolic-link report"):
                write_json_report(link, {"ok": True})

    def test_cli_processes_example(self):
        with TemporaryDirectory() as directory:
            output_path = Path(directory) / "report.json"
            args = [
                str(EXAMPLE),
                "--rules",
                str(RULES),
                "--analysis-date",
                "2026-08-21",
                "--output",
                str(output_path),
            ]
            with mock.patch("builtins.print") as printed:
                self.assertEqual(main(args), 0)
            summary = json.loads(printed.call_args.args[0])
            self.assertEqual(summary["finding_count"], 5)
            self.assertTrue(output_path.exists())

    def test_cli_rejects_invalid_bundle(self):
        with TemporaryDirectory() as directory, mock.patch("sys.stderr"):
            args = [
                directory,
                "--rules",
                str(RULES),
                "--output",
                str(Path(directory) / "report.json"),
            ]
            self.assertEqual(main(args), 2)


class ScoringTests(TestCase):
    def test_risk_level_boundaries(self):
        self.assertEqual(risk_level(0), "informational")
        self.assertEqual(risk_level(1), "low")
        self.assertEqual(risk_level(30), "medium")
        self.assertEqual(risk_level(50), "high")
        self.assertEqual(risk_level(70), "critical")

    def test_empty_environment_is_informational(self):
        self.assertEqual(environment_score([]), (0, "informational"))

    def test_environment_score_emphasizes_highest_residual_risk(self):
        self.assertEqual(environment_score([100, 20]), (78, "critical"))
