"""Offline and explainable SAP segregation-of-duties evidence analysis."""

from sap_sod_evidence_audit.analyzer import analyze
from sap_sod_evidence_audit.scoring import SCORING_VERSION

__all__ = ["SCORING_VERSION", "analyze"]
__version__ = "0.1.0"
