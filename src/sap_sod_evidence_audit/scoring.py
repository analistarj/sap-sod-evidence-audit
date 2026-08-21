"""Versioned scoring for potential and observed SAP SoD conflicts."""

from __future__ import annotations

from statistics import mean

SCORING_VERSION = "sap-sod-risk-1.0.0"
SEVERITY_POINTS = {"low": 20, "medium": 35, "high": 50, "critical": 65}


def risk_level(score: int) -> str:
    if score == 0:
        return "informational"
    if score < 30:
        return "low"
    if score < 50:
        return "medium"
    if score < 70:
        return "high"
    return "critical"


def environment_score(scores: list[int]) -> tuple[int, str]:
    active = sorted((score for score in scores if score > 0), reverse=True)
    if not active:
        return 0, "informational"
    top = active[:10]
    critical_ratio = sum(score >= 70 for score in active) / len(active) * 100
    score = round(0.50 * active[0] + 0.35 * mean(top) + 0.15 * critical_ratio)
    score = min(score, 100)
    return score, risk_level(score)
