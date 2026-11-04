"""Finding Aggregator and Deduplication for SecurePy.

Consolidates, normalizes, and enriches findings from both rule-based and
taint-based analysis engines.
"""

from __future__ import annotations

from typing import Optional

from backend.engine.models.finding import Confidence, Finding, Severity
from backend.engine.remediation.explanations import (
    generate_beginner_explanation,
    generate_developer_explanation,
)
from backend.engine.remediation.suggestions import generate_mitigation_code

SEVERITY_ORDER: dict[Severity, int] = {
    Severity.CRITICAL: 4,
    Severity.HIGH: 3,
    Severity.MEDIUM: 2,
    Severity.LOW: 1,
    Severity.INFO: 0,
}


class FindingAggregator:
    """Merges rule and taint findings, prioritizing proven data-flow evidence."""

    def aggregate(
        self,
        rule_findings: list[Finding],
        taint_findings: list[Finding],
    ) -> list[Finding]:
        """Combine and deduplicate rule and taint findings.

        Args:
            rule_findings: Heuristic and pattern findings from RuleEngine.
            taint_findings: Proven source-to-sink findings from TaintAnalyzer.

        Returns:
            Consolidated, enriched list of unique findings.
        """
        # Index taint findings by (file_path, line_number, cwe_id)
        taint_map: dict[tuple[Optional[str], int, str], Finding] = {}
        for tf in taint_findings:
            key = (tf.file_path, tf.line_number, tf.cwe_id)
            taint_map[key] = tf

        final_findings: list[Finding] = []
        covered_taint_keys: set[tuple[Optional[str], int, str]] = set()

        # Process rule findings against taint findings
        for rf in rule_findings:
            key = (rf.file_path, rf.line_number, rf.cwe_id)
            if key in taint_map:
                # Merge: Taint finding represents proven data-flow, so prioritize it
                tf = taint_map[key]
                covered_taint_keys.add(key)

                # Pick highest severity
                higher_sev = (
                    tf.severity
                    if SEVERITY_ORDER[tf.severity] >= SEVERITY_ORDER[rf.severity]
                    else rf.severity
                )

                # Construct consolidated finding
                merged = Finding(
                    rule_id=tf.rule_id,
                    title=tf.title,
                    category=tf.category,
                    cwe_id=tf.cwe_id,
                    severity=higher_sev,
                    confidence=Confidence.HIGH,  # High confidence because flow is verified
                    line_number=tf.line_number,
                    column=tf.column,
                    end_line_number=tf.end_line_number,
                    file_path=tf.file_path,
                    description=tf.description,
                    evidence=tf.evidence,
                    remediation=tf.remediation,
                    flow_steps=tf.flow_steps,  # Preserve all visual flow steps!
                )
                self._enrich_explanations(merged)
                final_findings.append(merged)
            else:
                # Independent rule finding
                self._enrich_explanations(rf)
                final_findings.append(rf)

        # Add any remaining taint findings that didn't match a rule finding
        for key, tf in taint_map.items():
            if key not in covered_taint_keys:
                self._enrich_explanations(tf)
                final_findings.append(tf)

        # Sort findings: first by severity (highest first), then by line number
        final_findings.sort(
            key=lambda f: (-SEVERITY_ORDER.get(f.severity, 0), f.line_number)
        )
        return final_findings

    def _enrich_explanations(self, finding: Finding) -> None:
        """Populate beginner explanation, developer explanation, and fix suggestion."""
        if not finding.beginner_explanation:
            finding.beginner_explanation = generate_beginner_explanation(finding)
        if not finding.developer_explanation:
            finding.developer_explanation = generate_developer_explanation(finding)
        if not finding.mitigation_code:
            finding.mitigation_code = generate_mitigation_code(finding)
