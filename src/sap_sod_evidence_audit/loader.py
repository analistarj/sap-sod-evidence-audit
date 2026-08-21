"""Load a bounded bundle of normalized, offline SAP audit exports."""

from __future__ import annotations

import csv
import json
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any

from sap_sod_evidence_audit.models import (
    ActionRequirement,
    Assignment,
    AuditBundle,
    Coverage,
    Event,
    Mitigation,
    Permission,
    RiskRule,
    Ruleset,
    UserRecord,
)

MAX_FILE_BYTES = 20 * 1024 * 1024
MAX_ROWS = 200_000
VALID_SEVERITIES = {"low", "medium", "high", "critical"}


class BundleValidationError(ValueError):
    """Raised when evidence cannot be parsed without unsafe assumptions."""


def parse_date(value: str | None) -> date | None:
    cleaned = (value or "").strip()
    if not cleaned:
        return None
    try:
        return date.fromisoformat(cleaned)
    except ValueError as error:
        raise BundleValidationError(f"invalid ISO date: {cleaned}") from error


def parse_datetime(value: str | None) -> datetime:
    cleaned = (value or "").strip()
    if not cleaned:
        raise BundleValidationError("event timestamp is required")
    try:
        parsed = datetime.fromisoformat(cleaned.replace("Z", "+00:00"))
    except ValueError as error:
        raise BundleValidationError(f"invalid ISO timestamp: {cleaned}") from error
    if parsed.tzinfo is None:
        raise BundleValidationError("event timestamp requires a timezone offset")
    return parsed.astimezone(timezone.utc)


def parse_bool(value: str | bool | None) -> bool:
    if isinstance(value, bool):
        return value
    cleaned = (value or "").strip().lower()
    if cleaned in {"1", "true", "yes", "enabled", "active", "approved"}:
        return True
    if cleaned in {"0", "false", "no", "disabled", "inactive", "rejected"}:
        return False
    raise BundleValidationError(f"invalid boolean: {value}")


def _safe_file(root: Path, name: str, required: bool = True) -> Path | None:
    candidate = root / name
    if not candidate.exists():
        if required:
            raise BundleValidationError(f"required file is missing: {name}")
        return None
    if candidate.is_symlink():
        raise BundleValidationError(f"symbolic-link evidence is not accepted: {name}")
    resolved = candidate.resolve(strict=True)
    if resolved.parent != root:
        raise BundleValidationError(f"evidence escaped the authorized bundle: {name}")
    if not resolved.is_file():
        raise BundleValidationError(f"evidence must be a regular file: {name}")
    if resolved.stat().st_size > MAX_FILE_BYTES:
        raise BundleValidationError(f"evidence exceeds 20 MiB: {name}")
    return resolved


def _read_csv(
    root: Path, name: str, required_columns: set[str], required: bool = True
) -> tuple[list[dict[str, str]], bool]:
    path = _safe_file(root, name, required)
    if path is None:
        return [], False
    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)
        columns = set(reader.fieldnames or [])
        missing = required_columns - columns
        if missing:
            joined = ", ".join(sorted(missing))
            raise BundleValidationError(f"{name} is missing columns: {joined}")
        rows = []
        for row_number, row in enumerate(reader, start=2):
            if len(rows) >= MAX_ROWS:
                raise BundleValidationError(f"{name} exceeds {MAX_ROWS} rows")
            normalized = {key: (value or "").strip() for key, value in row.items() if key}
            normalized["_row"] = str(row_number)
            rows.append(normalized)
    return rows, True


def _load_rules(path: Path) -> Ruleset:
    if path.is_symlink():
        raise BundleValidationError("symbolic-link rulesets are not accepted")
    resolved = path.expanduser().resolve(strict=True)
    if not resolved.is_file() or resolved.stat().st_size > MAX_FILE_BYTES:
        raise BundleValidationError("ruleset must be a regular JSON file under 20 MiB")
    with resolved.open("r", encoding="utf-8") as handle:
        payload: Any = json.load(handle)
    if not isinstance(payload, dict) or not isinstance(payload.get("risks"), list):
        raise BundleValidationError("ruleset must contain a risks array")
    version = str(payload.get("version", "")).strip()
    if not version:
        raise BundleValidationError("ruleset version is required")
    risks = []
    identifiers = set()
    for item in payload["risks"]:
        if not isinstance(item, dict):
            raise BundleValidationError("each risk rule must be an object")
        risk_id = str(item.get("risk_id", "")).strip()
        if not risk_id or risk_id in identifiers:
            raise BundleValidationError(f"risk_id is empty or duplicated: {risk_id}")
        identifiers.add(risk_id)
        severity = str(item.get("severity", "")).lower()
        if severity not in VALID_SEVERITIES:
            raise BundleValidationError(f"unsupported severity for {risk_id}: {severity}")
        actions = item.get("actions")
        if not isinstance(actions, list) or len(actions) != 2:
            raise BundleValidationError(f"{risk_id} must define exactly two actions")
        requirements = []
        for action in actions:
            if not isinstance(action, dict) or not action.get("action"):
                raise BundleValidationError(f"invalid action in {risk_id}")
            activities = action.get("activities")
            if not isinstance(activities, list) or not activities:
                raise BundleValidationError(f"activities are required in {risk_id}")
            requirements.append(
                ActionRequirement(
                    action=str(action["action"]).strip().upper(),
                    activities=tuple(str(value).strip().lower() for value in activities),
                )
            )
        risks.append(
            RiskRule(
                risk_id=risk_id,
                process=str(item.get("process", "unknown")).strip().upper(),
                title=str(item.get("title", risk_id)).strip(),
                severity=severity,
                action_a=requirements[0],
                action_b=requirements[1],
            )
        )
    return Ruleset(version=version, risks=tuple(risks))


def load_bundle(bundle_path: Path, rules_path: Path) -> AuditBundle:
    if bundle_path.is_symlink():
        raise BundleValidationError("symbolic-link bundles are not accepted")
    root = bundle_path.expanduser().resolve(strict=True)
    if not root.is_dir():
        raise BundleValidationError("bundle must be a directory")

    user_rows, _ = _read_csv(
        root, "users.csv", {"user_id", "status", "user_type", "last_logon"}
    )
    assignment_rows, _ = _read_csv(
        root, "assignments.csv", {"user_id", "role", "valid_from", "valid_to"}
    )
    permission_rows, _ = _read_csv(
        root, "permissions.csv", {"role", "action", "activity", "org_unit", "active"}
    )
    event_rows, _ = _read_csv(
        root,
        "events.csv",
        {"user_id", "action", "activity", "timestamp", "org_unit", "document_ref", "event_source"},
        required=False,
    )
    mitigation_rows, mitigations_supplied = _read_csv(
        root,
        "mitigations.csv",
        {"user_id", "risk_id", "control_id", "valid_from", "valid_to", "approved"},
        required=False,
    )

    coverage_path = _safe_file(root, "coverage.json", required=False)
    coverage = None
    if coverage_path:
        with coverage_path.open("r", encoding="utf-8") as handle:
            payload = json.load(handle)
        try:
            completeness = float(payload["completeness"])
            period_start = parse_date(payload["period_start"])
            period_end = parse_date(payload["period_end"])
            source = str(payload["source"]).strip()
        except (KeyError, TypeError, ValueError) as error:
            raise BundleValidationError("invalid coverage.json") from error
        if period_start is None or period_end is None or period_start > period_end:
            raise BundleValidationError("invalid coverage period")
        if not 0 <= completeness <= 1:
            raise BundleValidationError("coverage completeness must be between 0 and 1")
        if not source:
            raise BundleValidationError("coverage source cannot be empty")
        coverage = Coverage(source, period_start, period_end, completeness)

    users = tuple(
        UserRecord(
            user_id=row["user_id"],
            status=row["status"].lower(),
            user_type=row["user_type"].lower(),
            last_logon=parse_date(row["last_logon"]),
            row=int(row["_row"]),
        )
        for row in user_rows
    )
    assignments = tuple(
        Assignment(
            user_id=row["user_id"],
            role=row["role"],
            valid_from=parse_date(row["valid_from"]),
            valid_to=parse_date(row["valid_to"]),
            row=int(row["_row"]),
        )
        for row in assignment_rows
    )
    permissions = tuple(
        Permission(
            role=row["role"],
            action=row["action"].upper(),
            activity=row["activity"].lower(),
            org_unit=row["org_unit"] or "*",
            active=parse_bool(row["active"]),
            row=int(row["_row"]),
        )
        for row in permission_rows
    )
    events = tuple(
        Event(
            user_id=row["user_id"],
            action=row["action"].upper(),
            activity=row["activity"].lower(),
            timestamp=parse_datetime(row["timestamp"]),
            org_unit=row["org_unit"] or "*",
            document_ref=row["document_ref"],
            event_source=row["event_source"] or "unknown",
            row=int(row["_row"]),
        )
        for row in event_rows
    )
    mitigations = tuple(
        Mitigation(
            user_id=row["user_id"],
            risk_id=row["risk_id"],
            control_id=row["control_id"],
            valid_from=parse_date(row["valid_from"]),
            valid_to=parse_date(row["valid_to"]),
            approved=parse_bool(row["approved"]),
            row=int(row["_row"]),
        )
        for row in mitigation_rows
    )
    if any(not user.user_id for user in users):
        raise BundleValidationError("user_id cannot be empty")
    if len({user.user_id for user in users}) != len(users):
        raise BundleValidationError("users.csv contains duplicated user_id values")
    if any(not item.user_id or not item.role for item in assignments):
        raise BundleValidationError("assignments require user_id and role")
    if any(
        item.valid_from and item.valid_to and item.valid_from > item.valid_to
        for item in assignments
    ):
        raise BundleValidationError("assignment validity period is inverted")
    if any(not item.role or not item.action or not item.activity for item in permissions):
        raise BundleValidationError("permissions require role, action, and activity")
    if any(not item.user_id or not item.action or not item.activity for item in events):
        raise BundleValidationError("events require user_id, action, and activity")
    if any(
        not item.user_id or not item.risk_id or not item.control_id for item in mitigations
    ):
        raise BundleValidationError("mitigations require user_id, risk_id, and control_id")
    if any(
        item.valid_from and item.valid_to and item.valid_from > item.valid_to
        for item in mitigations
    ):
        raise BundleValidationError("mitigation validity period is inverted")
    known_users = {user.user_id for user in users}
    referenced_users = {
        *(item.user_id for item in assignments),
        *(item.user_id for item in events),
        *(item.user_id for item in mitigations),
    }
    unknown_users = referenced_users - known_users
    if unknown_users:
        raise BundleValidationError(
            "bundle references users absent from users.csv: " + ", ".join(sorted(unknown_users))
        )
    return AuditBundle(
        users=users,
        assignments=assignments,
        permissions=permissions,
        events=events,
        mitigations=mitigations,
        coverage=coverage,
        ruleset=_load_rules(rules_path),
        mitigations_supplied=mitigations_supplied,
    )
