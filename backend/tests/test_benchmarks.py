"""Unit tests for SecurePy Benchmarking and Evaluation framework."""

import pytest
from benchmarks.evaluate import calculate_metrics, run_evaluation


def test_calculate_metrics_math():
    """Verify precision, recall, F1, and FPR formulas."""
    tool_results = {
        "results": {
            "file_vuln_1.py": {"findings_count": 1, "detected_cwes": ["CWE-78"]},
            "file_vuln_2.py": {"findings_count": 0, "detected_cwes": []},          # FN
            "file_sec_1.py": {"findings_count": 0, "detected_cwes": []},           # TN
            "file_sec_2.py": {"findings_count": 1, "detected_cwes": ["CWE-78"]},   # FP
        }
    }

    ground_truth = {
        "file_vuln_1.py": {"is_vulnerable": True, "expected_cwe": "CWE-78"},
        "file_vuln_2.py": {"is_vulnerable": True, "expected_cwe": "CWE-78"},
        "file_sec_1.py": {"is_vulnerable": False, "expected_cwe": None},
        "file_sec_2.py": {"is_vulnerable": False, "expected_cwe": None},
    }

    metrics = calculate_metrics(tool_results, ground_truth)

    assert metrics["true_positives"] == 1
    assert metrics["false_positives"] == 1
    assert metrics["true_negatives"] == 1
    assert metrics["false_negatives"] == 1

    # Precision = 1 / (1 + 1) = 0.5
    assert metrics["precision"] == 0.5
    # Recall = 1 / (1 + 1) = 0.5
    assert metrics["recall"] == 0.5
    # F1 = 2 * (0.5 * 0.5) / 1.0 = 0.5
    assert metrics["f1_score"] == 0.5
    # FPR = 1 / (1 + 1) = 0.5
    assert metrics["false_positive_rate"] == 0.5


def test_securepy_benchmark_evaluation():
    """Run full evaluation suite and verify SecurePy performance on controlled dataset."""
    summary = run_evaluation()

    assert "dataset_statistics" in summary
    assert summary["dataset_statistics"]["total_samples"] == 20
    assert summary["dataset_statistics"]["vulnerable_samples"] == 12
    assert summary["dataset_statistics"]["secure_samples"] == 8

    securepy_metrics = summary["tools"]["SecurePy"]["metrics"]

    # SecurePy should correctly flag vulnerable samples and not produce false positives on safe samples
    assert securepy_metrics["true_positives"] >= 11
    assert securepy_metrics["false_positives"] == 0
    assert securepy_metrics["precision"] == 1.0
    assert securepy_metrics["recall"] >= 0.90
    assert securepy_metrics["f1_score"] >= 0.90
    assert securepy_metrics["false_positive_rate"] == 0.0
