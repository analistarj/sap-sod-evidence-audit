from datetime import date
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import TestCase

from sap_sod_evidence_audit.analyzer import analyze
from sap_sod_evidence_audit.loader import load_bundle
from tests.helpers import RULES, copy_example, example_bundle, replace

ANALYSIS_DATE = date(2026, 8, 21)


class AnalyzerTests(TestCase):
    def test_example_finds_five_conflicts(self):
        findings = analyze(example_bundle(), ANALYSIS_DATE)
        self.assertEqual(len(findings), 5)
        self.assertEqual(sum(item.observed_conflict for item in findings), 3)

    def test_observed_same_document_conflict_is_critical(self):
        finding = next(
            item
            for item in analyze(example_bundle(), ANALYSIS_DATE)
            if item.risk_id == "SOD-P2P-001"
        )
        self.assertTrue(finding.observed_conflict)
        self.assertTrue(finding.same_document_flow)
        self.assertEqual(finding.risk_score, 95)
        self.assertEqual(finding.confidence_score, 98)

    def test_valid_mitigation_reduces_only_residual_risk(self):
        finding = next(
            item
            for item in analyze(example_bundle(), ANALYSIS_DATE)
            if item.risk_id == "SOD-R2R-001"
        )
        self.assertEqual(finding.risk_score, 80)
        self.assertEqual(finding.residual_risk_score, 60)
        self.assertEqual(finding.mitigation_status, "valid")

    def test_expired_mitigation_does_not_reduce_risk(self):
        finding = next(
            item
            for item in analyze(example_bundle(), ANALYSIS_DATE)
            if item.risk_id == "SOD-P2P-002"
        )
        self.assertEqual(finding.risk_score, 75)
        self.assertEqual(finding.residual_risk_score, 75)
        self.assertIn("expired_mitigation=+5", finding.factors)

    def test_shared_user_increases_risk_and_reduces_confidence(self):
        finding = next(
            item
            for item in analyze(example_bundle(), ANALYSIS_DATE)
            if item.risk_id == "SOD-O2C-001"
        )
        self.assertEqual(finding.risk_score, 100)
        self.assertEqual(finding.confidence_score, 78)

    def test_disjoint_organizational_scopes_are_not_a_conflict(self):
        user_ids = {item.user_id for item in analyze(example_bundle(), ANALYSIS_DATE)}
        self.assertNotIn("U_CHARLIE", user_ids)

    def test_display_only_permission_is_not_a_conflict(self):
        user_ids = {item.user_id for item in analyze(example_bundle(), ANALYSIS_DATE)}
        self.assertNotIn("U_FOXTROT", user_ids)

    def test_locked_user_is_not_included(self):
        user_ids = {item.user_id for item in analyze(example_bundle(), ANALYSIS_DATE)}
        self.assertNotIn("U_LOCKED", user_ids)

    def test_wildcard_scope_creates_overlap(self):
        with TemporaryDirectory() as directory:
            bundle_path = copy_example(Path(directory))
            replace(
                bundle_path / "permissions.csv",
                "R_PAY_BR02,PAYMENT_EXECUTE,execute,BR02,true",
                "R_PAY_BR02,PAYMENT_EXECUTE,execute,*,true",
            )
            findings = analyze(load_bundle(bundle_path, RULES), ANALYSIS_DATE)
            self.assertIn("U_CHARLIE", {item.user_id for item in findings})

    def test_events_after_analysis_date_are_ignored(self):
        with TemporaryDirectory() as directory:
            bundle_path = copy_example(Path(directory))
            replace(bundle_path / "events.csv", "2026-08-10", "2026-09-10")
            replace(bundle_path / "events.csv", "2026-08-11", "2026-09-11")
            finding = next(
                item
                for item in analyze(load_bundle(bundle_path, RULES), ANALYSIS_DATE)
                if item.risk_id == "SOD-P2P-001"
            )
            self.assertFalse(finding.observed_conflict)
            self.assertEqual(finding.risk_score, 70)

    def test_different_documents_are_observed_without_same_flow(self):
        with TemporaryDirectory() as directory:
            bundle_path = copy_example(Path(directory))
            content = (bundle_path / "events.csv").read_text()
            first = content.find("DOC-P2P-001")
            second = content.find("DOC-P2P-001", first + 1)
            modified = content[:second] + "DOC-P2P-002" + content[second + len("DOC-P2P-001") :]
            (bundle_path / "events.csv").write_text(modified)
            finding = next(
                item
                for item in analyze(load_bundle(bundle_path, RULES), ANALYSIS_DATE)
                if item.risk_id == "SOD-P2P-001"
            )
            self.assertTrue(finding.observed_conflict)
            self.assertFalse(finding.same_document_flow)
            self.assertEqual(finding.risk_score, 85)

    def test_expired_assignment_removes_conflict(self):
        with TemporaryDirectory() as directory:
            bundle_path = copy_example(Path(directory))
            replace(
                bundle_path / "assignments.csv",
                "U_BRAVO,R_PO_RELEASE,2026-01-01,2026-12-31",
                "U_BRAVO,R_PO_RELEASE,2026-01-01,2026-06-30",
            )
            findings = analyze(load_bundle(bundle_path, RULES), ANALYSIS_DATE)
            keys = {(item.user_id, item.risk_id) for item in findings}
            self.assertNotIn(("U_BRAVO", "SOD-P2P-003"), keys)

    def test_missing_log_coverage_changes_confidence_not_risk(self):
        complete = next(
            item
            for item in analyze(example_bundle(), ANALYSIS_DATE)
            if item.risk_id == "SOD-P2P-001"
        )
        with TemporaryDirectory() as directory:
            bundle_path = copy_example(Path(directory))
            (bundle_path / "coverage.json").unlink()
            without = next(
                item
                for item in analyze(load_bundle(bundle_path, RULES), ANALYSIS_DATE)
                if item.risk_id == "SOD-P2P-001"
            )
            self.assertEqual(without.risk_score, complete.risk_score)
            self.assertLess(without.confidence_score, complete.confidence_score)

    def test_coverage_outside_analysis_date_does_not_increase_confidence(self):
        with TemporaryDirectory() as directory:
            bundle_path = copy_example(Path(directory))
            replace(bundle_path / "coverage.json", "2026-08-21", "2026-07-31")
            finding = next(
                item
                for item in analyze(load_bundle(bundle_path, RULES), ANALYSIS_DATE)
                if item.risk_id == "SOD-P2P-001"
            )
            self.assertEqual(finding.confidence_score, 80)

    def test_technical_user_adds_five_points(self):
        with TemporaryDirectory() as directory:
            bundle_path = copy_example(Path(directory))
            replace(
                bundle_path / "users.csv",
                "U_BRAVO,active,dialog,2026-08-18",
                "U_BRAVO,active,service,2026-08-18",
            )
            finding = next(
                item
                for item in analyze(load_bundle(bundle_path, RULES), ANALYSIS_DATE)
                if item.risk_id == "SOD-P2P-003"
            )
            self.assertEqual(finding.risk_score, 60)
            self.assertIn("technical_user=+5", finding.factors)

    def test_evidence_is_sorted_and_deduplicated(self):
        finding = analyze(example_bundle(), ANALYSIS_DATE)[0]
        evidence = [(item["source"], item["row"]) for item in finding.evidence]
        self.assertEqual(evidence, sorted(set(evidence)))
