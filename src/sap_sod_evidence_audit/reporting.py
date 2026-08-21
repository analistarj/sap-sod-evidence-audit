"""Build pseudonymized reports and publish them atomically."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
from datetime import date, datetime, timezone
from pathlib import Path
from tempfile import NamedTemporaryFile

from sap_sod_evidence_audit.models import AuditBundle, Finding
from sap_sod_evidence_audit.scoring import SCORING_VERSION, environment_score


def _reference(value: str, secret: str | None) -> str:
    encoded = value.encode("utf-8")
    digest = hmac.new((secret or "").encode("utf-8"), encoded, hashlib.sha256).hexdigest()
    return digest[:16]


def build_report(
    findings: list[Finding], bundle: AuditBundle, on_date: date, secret: str | None = None
) -> dict:
    reference_secret = secret or secrets.token_hex(32)
    score, level = environment_score(
        [finding.residual_risk_score for finding in findings]
    )
    counts = {name: 0 for name in ("informational", "low", "medium", "high", "critical")}
    rows = []
    for finding in findings:
        counts[finding.risk_level] += 1
        rows.append(
            {
                "user_ref": _reference(finding.user_id, reference_secret),
                "user_type": finding.user_type,
                "risk_id": finding.risk_id,
                "process": finding.process,
                "title": finding.title,
                "severity": finding.severity,
                "role_refs": [_reference(role, reference_secret) for role in finding.roles],
                "org_scope_refs": [
                    _reference(scope, reference_secret) for scope in finding.org_units
                ],
                "potential_conflict": finding.potential_conflict,
                "observed_conflict": finding.observed_conflict,
                "same_document_flow": finding.same_document_flow,
                "mitigation_status": finding.mitigation_status,
                "control_ref": _reference(finding.control_id, reference_secret)
                if finding.control_id
                else None,
                "risk_score": finding.risk_score,
                "residual_risk_score": finding.residual_risk_score,
                "risk_level": finding.risk_level,
                "confidence_score": finding.confidence_score,
                "factors": list(finding.factors),
                "evidence": list(finding.evidence),
            }
        )
    return {
        "schema_version": "sap-sod-report-1.0",
        "ruleset_version": bundle.ruleset.version,
        "scoring_version": SCORING_VERSION,
        "analysis_date": on_date.isoformat(),
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "environment_score": score,
        "environment_level": level,
        "finding_count": len(findings),
        "observed_conflict_count": sum(finding.observed_conflict for finding in findings),
        "valid_mitigation_count": sum(
            finding.mitigation_status == "valid" for finding in findings
        ),
        "counts_by_level": counts,
        "log_coverage": {
            "source_ref": _reference(bundle.coverage.source, reference_secret),
            "period_start": bundle.coverage.period_start.isoformat(),
            "period_end": bundle.coverage.period_end.isoformat(),
            "completeness": bundle.coverage.completeness,
        }
        if bundle.coverage
        else None,
        "privacy_notice": (
            "user, role, organization, and control identifiers are pseudonymized; "
            "document references and original event text are omitted"
        ),
        "decision_notice": (
            "scores prioritize audit review and do not prove fraud, control failure, or compliance"
        ),
        "findings": rows,
    }


def write_json_report(path: Path, report: dict) -> None:
    if path.exists() and path.is_symlink():
        raise ValueError("symbolic-link report destinations are not accepted")
    destination = path.expanduser().resolve()
    destination.parent.mkdir(parents=True, exist_ok=True)
    with NamedTemporaryFile(
        "w", encoding="utf-8", dir=destination.parent, delete=False, prefix=".sap-sod-"
    ) as temporary:
        json.dump(report, temporary, ensure_ascii=False, indent=2)
        temporary.write("\n")
        temporary_path = Path(temporary.name)
    try:
        os.chmod(temporary_path, 0o600)
        temporary_path.replace(destination)
    except Exception:
        temporary_path.unlink(missing_ok=True)
        raise
