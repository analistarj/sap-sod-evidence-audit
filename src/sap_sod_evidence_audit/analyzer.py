"""Correlate effective access, observed events, scopes, and mitigations."""

from __future__ import annotations

from collections import defaultdict
from datetime import date

from sap_sod_evidence_audit.models import AuditBundle, Event, Finding, Grant, Mitigation, RiskRule
from sap_sod_evidence_audit.scoring import SEVERITY_POINTS, risk_level

ACTIVE_USER_STATES = {"active", "enabled"}
SHARED_USER_TYPES = {"shared", "generic"}
TECHNICAL_USER_TYPES = {"service", "system", "communication"}


def _date_active(valid_from: date | None, valid_to: date | None, on_date: date) -> bool:
    return (valid_from is None or valid_from <= on_date) and (
        valid_to is None or valid_to >= on_date
    )


def _scope_overlap(left: str, right: str) -> bool:
    return left == "*" or right == "*" or left == right


def _effective_grants(bundle: AuditBundle, on_date: date) -> dict[str, list[Grant]]:
    permission_map = defaultdict(list)
    for permission in bundle.permissions:
        if permission.active:
            permission_map[permission.role].append(permission)
    grants = defaultdict(list)
    for assignment in bundle.assignments:
        if not _date_active(assignment.valid_from, assignment.valid_to, on_date):
            continue
        for permission in permission_map[assignment.role]:
            grants[assignment.user_id].append(
                Grant(
                    action=permission.action,
                    activity=permission.activity,
                    org_unit=permission.org_unit,
                    role=assignment.role,
                    assignment_row=assignment.row,
                    permission_row=permission.row,
                )
            )
    return grants


def _matching(grants: list[Grant], action: str, activities: tuple[str, ...]) -> list[Grant]:
    return [grant for grant in grants if grant.action == action and grant.activity in activities]


def _observed(
    events: list[Event], rule: RiskRule, scopes: set[str], on_date: date
) -> tuple[bool, bool, list[Event]]:
    relevant = [
        event
        for event in events
        if event.timestamp.date() <= on_date
        and any(_scope_overlap(event.org_unit, scope) for scope in scopes)
    ]
    first = [
        event
        for event in relevant
        if event.action == rule.action_a.action and event.activity in rule.action_a.activities
    ]
    second = [
        event
        for event in relevant
        if event.action == rule.action_b.action and event.activity in rule.action_b.activities
    ]
    if not first or not second:
        return False, False, first + second
    same_document = any(
        left.document_ref
        and left.document_ref == right.document_ref
        and _scope_overlap(left.org_unit, right.org_unit)
        for left in first
        for right in second
    )
    return True, same_document, first + second


def _mitigation_status(
    mitigations: list[Mitigation], on_date: date
) -> tuple[str, Mitigation | None]:
    approved = [mitigation for mitigation in mitigations if mitigation.approved]
    valid = [
        mitigation
        for mitigation in approved
        if _date_active(mitigation.valid_from, mitigation.valid_to, on_date)
    ]
    if valid:
        return "valid", valid[0]
    if approved:
        return "expired_or_outside_period", approved[0]
    if mitigations:
        return "not_approved", mitigations[0]
    return "none", None


def _confidence(
    bundle: AuditBundle,
    user_type: str,
    scopes: set[str],
    on_date: date,
) -> int:
    score = 15  # versioned rule
    score += 15  # user record
    score += 15  # assignment evidence
    score += 20  # permission evidence
    score += 10 if any(scope != "*" for scope in scopes) else 0
    if bundle.coverage and bundle.coverage.period_start <= on_date <= bundle.coverage.period_end:
        score += round(bundle.coverage.completeness * 20)
    score += 5 if bundle.mitigations_supplied else 0
    if user_type in SHARED_USER_TYPES:
        score -= 20
    return max(0, min(score, 100))


def analyze(bundle: AuditBundle, on_date: date) -> list[Finding]:
    grants_by_user = _effective_grants(bundle, on_date)
    events_by_user = defaultdict(list)
    for event in bundle.events:
        events_by_user[event.user_id].append(event)
    mitigations_by_key = defaultdict(list)
    for mitigation in bundle.mitigations:
        mitigations_by_key[(mitigation.user_id, mitigation.risk_id)].append(mitigation)

    findings = []
    for user in bundle.users:
        if user.status not in ACTIVE_USER_STATES:
            continue
        user_grants = grants_by_user[user.user_id]
        for rule in bundle.ruleset.risks:
            first = _matching(user_grants, rule.action_a.action, rule.action_a.activities)
            second = _matching(user_grants, rule.action_b.action, rule.action_b.activities)
            overlapping_pairs = [
                (left, right)
                for left in first
                for right in second
                if _scope_overlap(left.org_unit, right.org_unit)
            ]
            if not overlapping_pairs:
                continue
            roles = {grant.role for pair in overlapping_pairs for grant in pair}
            scopes = {
                scope
                for pair in overlapping_pairs
                for scope in (pair[0].org_unit, pair[1].org_unit)
            }
            observed, same_document, used_events = _observed(
                events_by_user[user.user_id], rule, scopes, on_date
            )
            mitigation_status, mitigation = _mitigation_status(
                mitigations_by_key[(user.user_id, rule.risk_id)], on_date
            )
            points = SEVERITY_POINTS[rule.severity]
            factors = [f"severity:{rule.severity}={points}", "effective_conflict=confirmed"]
            points += 5
            factors.append("overlapping_org_scope=+5")
            if observed:
                points += 15
                factors.append("observed_both_actions=+15")
            if same_document:
                points += 10
                factors.append("same_document_flow=+10")
            if user.user_type in SHARED_USER_TYPES:
                points += 10
                factors.append("shared_or_generic_user=+10")
            elif user.user_type in TECHNICAL_USER_TYPES:
                points += 5
                factors.append("technical_user=+5")
            if mitigation_status == "expired_or_outside_period":
                points += 5
                factors.append("expired_mitigation=+5")
            points = min(points, 100)
            residual = points
            if mitigation_status == "valid":
                residual = max(0, points - 20)
                factors.append("valid_mitigation=-20_residual")

            evidence = [
                {"source": "users.csv", "row": user.row},
                *(
                    {
                        "source": "assignments.csv",
                        "row": grant.assignment_row,
                    }
                    for pair in overlapping_pairs
                    for grant in pair
                ),
                *(
                    {"source": "permissions.csv", "row": grant.permission_row}
                    for pair in overlapping_pairs
                    for grant in pair
                ),
                *({"source": "events.csv", "row": event.row} for event in used_events),
            ]
            if mitigation:
                evidence.append({"source": "mitigations.csv", "row": mitigation.row})
            unique_evidence_keys = sorted(
                {tuple(sorted(item.items())) for item in evidence},
                key=lambda item: (str(dict(item)["source"]), int(dict(item)["row"])),
            )
            unique_evidence = tuple(dict(item) for item in unique_evidence_keys)
            findings.append(
                Finding(
                    user_id=user.user_id,
                    user_type=user.user_type,
                    risk_id=rule.risk_id,
                    process=rule.process,
                    title=rule.title,
                    severity=rule.severity,
                    roles=tuple(sorted(roles)),
                    org_units=tuple(sorted(scopes)),
                    potential_conflict=True,
                    observed_conflict=observed,
                    same_document_flow=same_document,
                    mitigation_status=mitigation_status,
                    control_id=mitigation.control_id if mitigation else None,
                    risk_score=points,
                    residual_risk_score=residual,
                    risk_level=risk_level(residual),
                    confidence_score=_confidence(bundle, user.user_type, scopes, on_date),
                    factors=tuple(factors),
                    evidence=unique_evidence,
                )
            )
    return sorted(
        findings,
        key=lambda finding: (-finding.residual_risk_score, finding.risk_id, finding.user_id),
    )
