"""Severity and Confidence Scorer for SecurePy.

Calculates aggregate project risk scores and provides separate severity vs.
confidence classifications.
"""

from __future__ import annotations

from typing import Any

from backend.engine.models.finding import Confidence, Finding, Severity

SEVERITY_WEIGHTS: dict[Severity, float] = {
    Severity.CRITICAL: 25.0,
    Severity.HIGH: 15.0,
    Severity.MEDIUM: 8.0,
    Severity.LOW: 3.0,
    Severity.INFO: 0.0,
}

CONFIDENCE_MULTIPLIERS: dict[Confidence, float] = {
    Confidence.HIGH: 1.0,
    Confidence.MEDIUM: 0.75,
    Confidence.LOW: 0.5,
}


class Scorer:
    """Computes project risk metrics while maintaining decoupled severity & confidence."""

    @staticmethod
    def calculate_risk_score(findings: list[Finding]) -> int:
        """Calculate aggregate risk score from 0 (clean) to 100 (high risk)."""
        if not findings:
            return 0

        raw_score = 0.0
        for f in findings:
            weight = SEVERITY_WEIGHTS.get(f.severity, 0.0)
            multiplier = CONFIDENCE_MULTIPLIERS.get(f.confidence, 1.0)
            raw_score += weight * multiplier

        # Normalize score between 0 and 100
        return min(100, int(round(raw_score)))

    @staticmethod
    def get_summary(findings: list[Finding]) -> dict[str, Any]:
        """Generate statistical breakdown of findings by severity, confidence, and status."""
        severity_counts: dict[str, int] = {s.value: 0 for s in Severity}
        confidence_counts: dict[str, int] = {c.value: 0 for c in Confidence}
        category_counts: dict[str, int] = {}

        for f in findings:
            severity_counts[f.severity.value] += 1
            confidence_counts[f.confidence.value] += 1
            cat = f.category
            category_counts[cat] = category_counts.get(cat, 0) + 1

        return {
            "total_findings": len(findings),
            "risk_score": Scorer.calculate_risk_score(findings),
            "severity_breakdown": severity_counts,
            "confidence_breakdown": confidence_counts,
            "category_breakdown": category_counts,
        }
