"""Typed records used by the offline analyzer."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date, datetime


@dataclass(frozen=True)
class UserRecord:
    user_id: str
    status: str
    user_type: str
    last_logon: date | None
    row: int


@dataclass(frozen=True)
class Assignment:
    user_id: str
    role: str
    valid_from: date | None
    valid_to: date | None
    row: int


@dataclass(frozen=True)
class Permission:
    role: str
    action: str
    activity: str
    org_unit: str
    active: bool
    row: int


@dataclass(frozen=True)
class Event:
    user_id: str
    action: str
    activity: str
    timestamp: datetime
    org_unit: str
    document_ref: str
    event_source: str
    row: int


@dataclass(frozen=True)
class Mitigation:
    user_id: str
    risk_id: str
    control_id: str
    valid_from: date | None
    valid_to: date | None
    approved: bool
    row: int


@dataclass(frozen=True)
class Coverage:
    source: str
    period_start: date
    period_end: date
    completeness: float


@dataclass(frozen=True)
class ActionRequirement:
    action: str
    activities: tuple[str, ...]


@dataclass(frozen=True)
class RiskRule:
    risk_id: str
    process: str
    title: str
    severity: str
    action_a: ActionRequirement
    action_b: ActionRequirement


@dataclass(frozen=True)
class Ruleset:
    version: str
    risks: tuple[RiskRule, ...]


@dataclass(frozen=True)
class AuditBundle:
    users: tuple[UserRecord, ...]
    assignments: tuple[Assignment, ...]
    permissions: tuple[Permission, ...]
    events: tuple[Event, ...]
    mitigations: tuple[Mitigation, ...]
    coverage: Coverage | None
    ruleset: Ruleset
    mitigations_supplied: bool


@dataclass(frozen=True)
class Grant:
    action: str
    activity: str
    org_unit: str
    role: str
    assignment_row: int
    permission_row: int


@dataclass(frozen=True)
class Finding:
    user_id: str
    user_type: str
    risk_id: str
    process: str
    title: str
    severity: str
    roles: tuple[str, ...]
    org_units: tuple[str, ...]
    potential_conflict: bool
    observed_conflict: bool
    same_document_flow: bool
    mitigation_status: str
    control_id: str | None
    risk_score: int
    residual_risk_score: int
    risk_level: str
    confidence_score: int
    factors: tuple[str, ...]
    evidence: tuple[dict[str, object], ...]
