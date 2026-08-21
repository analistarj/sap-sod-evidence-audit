import json
import os
from datetime import timezone
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import TestCase, mock

from sap_sod_evidence_audit.loader import (
    MAX_FILE_BYTES,
    BundleValidationError,
    load_bundle,
    parse_bool,
    parse_date,
    parse_datetime,
)
from tests.helpers import RULES, copy_example, example_bundle, replace


class LoaderTests(TestCase):
    def test_loads_complete_example(self):
        bundle = example_bundle()
        self.assertEqual(len(bundle.users), 8)
        self.assertEqual(len(bundle.ruleset.risks), 5)
        self.assertEqual(bundle.ruleset.version, "sap-sod-core-1.0.0")
        self.assertEqual(bundle.coverage.completeness, 0.9)

    def test_optional_evidence_can_be_absent(self):
        with TemporaryDirectory() as directory:
            bundle_path = copy_example(Path(directory))
            for name in ("events.csv", "mitigations.csv", "coverage.json"):
                (bundle_path / name).unlink()
            bundle = load_bundle(bundle_path, RULES)
            self.assertEqual(bundle.events, ())
            self.assertEqual(bundle.mitigations, ())
            self.assertIsNone(bundle.coverage)
            self.assertFalse(bundle.mitigations_supplied)

    def test_missing_required_file_is_rejected(self):
        with TemporaryDirectory() as directory:
            with self.assertRaisesRegex(BundleValidationError, "users.csv"):
                load_bundle(Path(directory), RULES)

    def test_missing_csv_column_is_rejected(self):
        with TemporaryDirectory() as directory:
            bundle_path = copy_example(Path(directory))
            (bundle_path / "users.csv").write_text("user_id,status\nU1,active\n")
            with self.assertRaisesRegex(BundleValidationError, "missing columns"):
                load_bundle(bundle_path, RULES)

    def test_invalid_boolean_is_rejected(self):
        with TemporaryDirectory() as directory:
            bundle_path = copy_example(Path(directory))
            replace(bundle_path / "permissions.csv", ",true\n", ",maybe\n")
            with self.assertRaisesRegex(BundleValidationError, "invalid boolean"):
                load_bundle(bundle_path, RULES)

    def test_invalid_date_is_rejected(self):
        with self.assertRaisesRegex(BundleValidationError, "invalid ISO date"):
            parse_date("21/08/2026")

    def test_timestamp_is_normalized_to_utc(self):
        parsed = parse_datetime("2026-08-21T10:30:00-03:00")
        self.assertEqual(parsed.tzinfo, timezone.utc)
        self.assertEqual(parsed.hour, 13)

    def test_naive_timestamp_is_rejected(self):
        with self.assertRaisesRegex(BundleValidationError, "timezone offset"):
            parse_datetime("2026-08-21T10:30:00")

    def test_boolean_parser_accepts_normalized_values(self):
        self.assertTrue(parse_bool(True))
        self.assertTrue(parse_bool("approved"))
        self.assertFalse(parse_bool("disabled"))

    def test_invalid_coverage_is_rejected(self):
        with TemporaryDirectory() as directory:
            bundle_path = copy_example(Path(directory))
            (bundle_path / "coverage.json").write_text(
                json.dumps(
                    {
                        "source": "synthetic",
                        "period_start": "2026-08-21",
                        "period_end": "2026-08-01",
                        "completeness": 2,
                    }
                )
            )
            with self.assertRaises(BundleValidationError):
                load_bundle(bundle_path, RULES)

    def test_invalid_ruleset_is_rejected(self):
        with TemporaryDirectory() as directory:
            bundle_path = copy_example(Path(directory))
            rules = Path(directory) / "rules.json"
            rules.write_text(
                json.dumps(
                    {
                        "version": "bad",
                        "risks": [
                            {
                                "risk_id": "R1",
                                "process": "P2P",
                                "severity": "extreme",
                                "actions": [],
                            }
                        ],
                    }
                )
            )
            with self.assertRaisesRegex(BundleValidationError, "unsupported severity"):
                load_bundle(bundle_path, rules)

    def test_duplicate_users_are_rejected(self):
        with TemporaryDirectory() as directory:
            bundle_path = copy_example(Path(directory))
            with (bundle_path / "users.csv").open("a", encoding="utf-8") as handle:
                handle.write("U_ALFA,active,dialog,2026-08-20\n")
            with self.assertRaisesRegex(BundleValidationError, "duplicated"):
                load_bundle(bundle_path, RULES)

    def test_unknown_referenced_user_is_rejected(self):
        with TemporaryDirectory() as directory:
            bundle_path = copy_example(Path(directory))
            with (bundle_path / "assignments.csv").open("a", encoding="utf-8") as handle:
                handle.write("U_UNKNOWN,R_VENDOR_MAINT,2026-01-01,2026-12-31\n")
            with self.assertRaisesRegex(BundleValidationError, "absent from users.csv"):
                load_bundle(bundle_path, RULES)

    def test_inverted_assignment_period_is_rejected(self):
        with TemporaryDirectory() as directory:
            bundle_path = copy_example(Path(directory))
            replace(
                bundle_path / "assignments.csv",
                "U_ALFA,R_VENDOR_MAINT,2026-01-01,2026-12-31",
                "U_ALFA,R_VENDOR_MAINT,2026-12-31,2026-01-01",
            )
            with self.assertRaisesRegex(BundleValidationError, "period is inverted"):
                load_bundle(bundle_path, RULES)

    def test_file_size_limit_is_enforced(self):
        with TemporaryDirectory() as directory:
            bundle_path = copy_example(Path(directory))
            with (bundle_path / "users.csv").open("wb") as handle:
                handle.truncate(MAX_FILE_BYTES + 1)
            with self.assertRaisesRegex(BundleValidationError, "20 MiB"):
                load_bundle(bundle_path, RULES)

    def test_row_limit_is_enforced(self):
        with TemporaryDirectory() as directory:
            bundle_path = copy_example(Path(directory))
            with mock.patch("sap_sod_evidence_audit.loader.MAX_ROWS", 1):
                with self.assertRaisesRegex(BundleValidationError, "exceeds 1 rows"):
                    load_bundle(bundle_path, RULES)

class SymlinkLoaderTests(TestCase):
    def test_symlink_evidence_is_rejected(self):
        if not hasattr(os, "symlink"):
            self.skipTest("symbolic links unavailable")
        with TemporaryDirectory() as directory:
            root = Path(directory)
            bundle_path = copy_example(root)
            original = bundle_path / "events.csv"
            target = root / "outside-events.csv"
            original.replace(target)
            try:
                os.symlink(target, original)
            except OSError as error:
                self.skipTest(f"symbolic links unavailable: {error}")
            with self.assertRaisesRegex(BundleValidationError, "symbolic-link evidence"):
                load_bundle(bundle_path, RULES)
