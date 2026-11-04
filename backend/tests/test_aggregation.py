"""Unit tests for Finding Aggregation, Scoring, and Remediation."""

import pytest
from backend.engine.aggregation import FindingAggregator
from backend.engine.models.finding import Confidence, Finding, FindingStatus, Severity
from backend.engine.scoring import Scorer


@pytest.fixture
def aggregator() -> FindingAggregator:
    return FindingAggregator()


def test_merge_rule_and_taint_findings(aggregator: FindingAggregator):
    """When both a rule and taint finding occur on the same line, merge into high confidence with flow steps."""
    rule_finding = Finding(
        rule_id="SEC-R003",
        title="Potential OS Command Injection Pattern",
        category="Command Injection",
        cwe_id="CWE-78",
        severity=Severity.HIGH,
        confidence=Confidence.MEDIUM,
        line_number=4,
        description="Rule pattern detected shell call",
        evidence="os.system(z)",
        remediation="Use subprocess",
    )

    taint_finding = Finding(
        rule_id="SNK-OS-SYSTEM",
        title="Command Injection via OS Shell (Proven Data Flow)",
        category="Command Injection",
        cwe_id="CWE-78",
        severity=Severity.CRITICAL,
        confidence=Confidence.HIGH,
        line_number=4,
        description="Proven data flow from input to os.system",
        evidence="Source L1 -> Sink L4",
        remediation="Use subprocess",
        flow_steps=[{"step": 1, "type": "SOURCE"}, {"step": 2, "type": "SINK"}],
    )

    merged = aggregator.aggregate([rule_finding], [taint_finding])

    assert len(merged) == 1
    f = merged[0]
    assert f.severity == Severity.CRITICAL
    assert f.confidence == Confidence.HIGH
    assert len(f.flow_steps) == 2
    assert f.beginner_explanation != ""
    assert f.developer_explanation != ""
    assert f.mitigation_code != ""


def test_enrichment_of_independent_findings(aggregator: FindingAggregator):
    """Independent rule finding receives beginner and developer explanations."""
    rule_finding = Finding(
        rule_id="SEC-R001",
        title="Hardcoded Credential",
        category="Hardcoded Credentials",
        cwe_id="CWE-798",
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        line_number=2,
        description="Found password",
        evidence="password = 'secret'",
        remediation="Use os.getenv",
    )

    results = aggregator.aggregate([rule_finding], [])
    assert len(results) == 1
    f = results[0]
    assert "Hardcoded Credentials" in f.beginner_explanation
    assert "os.environ" in f.developer_explanation
    assert "os.getenv" in f.mitigation_code


def test_scorer_risk_calculation_and_summary():
    """Verify Scorer calculates risk score (0-100) and severity breakdowns."""
    findings = [
        Finding(
            rule_id="1",
            title="T1",
            category="Cat",
            cwe_id="CWE-78",
            severity=Severity.CRITICAL,
            confidence=Confidence.HIGH,
            line_number=1,
            description="d",
            evidence="e",
            remediation="r",
        ),
        Finding(
            rule_id="2",
            title="T2",
            category="Cat",
            cwe_id="CWE-89",
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            line_number=2,
            description="d",
            evidence="e",
            remediation="r",
        ),
    ]

    score = Scorer.calculate_risk_score(findings)
    assert score == 40  # 25*1.0 + 15*1.0

    summary = Scorer.get_summary(findings)
    assert summary["total_findings"] == 2
    assert summary["risk_score"] == 40
    assert summary["severity_breakdown"]["CRITICAL"] == 1
    assert summary["severity_breakdown"]["HIGH"] == 1
    assert summary["confidence_breakdown"]["HIGH"] == 2


def test_finding_status_transitions():
    """Verify finding status transitions across review lifecycle."""
    f = Finding(
        rule_id="SEC-R001",
        title="Cred",
        category="Hardcoded Credentials",
        cwe_id="CWE-798",
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        line_number=1,
        description="desc",
        evidence="ev",
        remediation="rem",
    )
    assert f.status == FindingStatus.OPEN
    f.status = FindingStatus.REVIEWED
    assert f.status == FindingStatus.REVIEWED
    f.status = FindingStatus.FIXED
    assert f.status == FindingStatus.FIXED
