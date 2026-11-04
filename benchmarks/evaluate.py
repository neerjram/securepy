"""Benchmark Evaluation and Comparison Framework for SecurePy.

Evaluates static analysis tools against labeled ground-truth datasets and calculates:
- True Positives (TP), False Positives (FP), True Negatives (TN), False Negatives (FN)
- Precision, Recall, F1-Score, and False Positive Rate (FPR)
- Total and average execution time per target file
- Exportable JSON and CSV comparison reports
"""

from __future__ import annotations

import csv
import json
from pathlib import Path
import sys
from typing import Any

# Ensure project root is in pythonpath
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from benchmarks.run_bandit import run_bandit
from benchmarks.run_securepy import run_benchmark as run_securepy
from benchmarks.run_semgrep import run_semgrep


def calculate_metrics(
    tool_results: dict[str, Any], ground_truth: dict[str, Any]
) -> dict[str, Any]:
    """Calculate confusion matrix metrics for a tool against ground truth."""
    tp = 0  # Vulnerable file correctly flagged
    fp = 0  # Secure file incorrectly flagged
    tn = 0  # Secure file correctly clean
    fn = 0  # Vulnerable file missed

    file_results = tool_results.get("results", {})

    for file_key, truth in ground_truth.items():
        is_vuln_expected = truth["is_vulnerable"]
        expected_cwe = truth["expected_cwe"]

        tool_file_res = file_results.get(file_key, {})
        detected_cwes = tool_file_res.get("detected_cwes", [])
        findings_count = tool_file_res.get("findings_count", 0)

        flagged = findings_count > 0

        if is_vuln_expected:
            # Check if flagged and matches expected CWE if defined
            if flagged and (not expected_cwe or expected_cwe in detected_cwes):
                tp += 1
            else:
                fn += 1
        else:
            if flagged:
                fp += 1
            else:
                tn += 1

    precision = round(tp / (tp + fp), 4) if (tp + fp) > 0 else 0.0
    recall = round(tp / (tp + fn), 4) if (tp + fn) > 0 else 0.0
    f1 = round(2 * (precision * recall) / (precision + recall), 4) if (precision + recall) > 0 else 0.0
    fpr = round(fp / (fp + tn), 4) if (fp + tn) > 0 else 0.0

    return {
        "true_positives": tp,
        "false_positives": fp,
        "true_negatives": tn,
        "false_negatives": fn,
        "precision": precision,
        "recall": recall,
        "f1_score": f1,
        "false_positive_rate": fpr,
        "total_time_ms": tool_results.get("total_time_ms", 0.0),
        "avg_time_per_file_ms": tool_results.get("avg_time_per_file_ms", 0.0),
    }


def run_evaluation() -> dict[str, Any]:
    """Execute complete benchmarking evaluation across all tools."""
    benchmarks_dir = Path(__file__).resolve().parent
    truth_file = benchmarks_dir / "expected_results" / "ground_truth.json"
    ground_truth = json.loads(truth_file.read_text(encoding="utf-8"))

    vulnerable_files = sorted(list((benchmarks_dir / "vulnerable").glob("*.py")))
    secure_files = sorted(list((benchmarks_dir / "secure").glob("*.py")))
    all_files = vulnerable_files + secure_files

    # 1. Run SecurePy
    securepy_res = run_securepy(all_files)
    securepy_metrics = calculate_metrics(securepy_res, ground_truth)

    eval_summary: dict[str, Any] = {
        "dataset_statistics": {
            "total_samples": len(all_files),
            "vulnerable_samples": len(vulnerable_files),
            "secure_samples": len(secure_files),
        },
        "tools": {
            "SecurePy": {
                "metrics": securepy_metrics,
                "available": True,
            }
        },
    }

    # 2. Run Bandit if installed
    bandit_res = run_bandit(all_files)
    if bandit_res.get("available"):
        bandit_metrics = calculate_metrics(bandit_res, ground_truth)
        eval_summary["tools"]["Bandit"] = {
            "metrics": bandit_metrics,
            "available": True,
        }
    else:
        eval_summary["tools"]["Bandit"] = {
            "available": False,
            "message": bandit_res.get("message"),
        }

    # 3. Run Semgrep if installed
    semgrep_res = run_semgrep(all_files)
    if semgrep_res.get("available"):
        semgrep_metrics = calculate_metrics(semgrep_res, ground_truth)
        eval_summary["tools"]["Semgrep"] = {
            "metrics": semgrep_metrics,
            "available": True,
        }
    else:
        eval_summary["tools"]["Semgrep"] = {
            "available": False,
            "message": semgrep_res.get("message"),
        }

    # 4. Save results to benchmarks/results/
    results_dir = benchmarks_dir / "results"
    results_dir.mkdir(parents=True, exist_ok=True)

    json_path = results_dir / "benchmark_summary.json"
    json_path.write_text(json.dumps(eval_summary, indent=2), encoding="utf-8")

    # CSV report
    csv_path = results_dir / "benchmark_summary.csv"
    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["Tool", "TP", "FP", "TN", "FN", "Precision", "Recall", "F1-Score", "FPR", "Time(ms)"])
        for tool_name, data in eval_summary["tools"].items():
            if data.get("available") and "metrics" in data:
                m = data["metrics"]
                writer.writerow([
                    tool_name,
                    m["true_positives"],
                    m["false_positives"],
                    m["true_negatives"],
                    m["false_negatives"],
                    f"{m['precision']:.2%}",
                    f"{m['recall']:.2%}",
                    f"{m['f1_score']:.2%}",
                    f"{m['false_positive_rate']:.2%}",
                    f"{m['total_time_ms']:.1f}",
                ])

    return eval_summary


def print_table(summary: dict[str, Any]) -> None:
    """Print ASCII comparison table to stdout."""
    tools = summary.get("tools", {})
    stats = summary.get("dataset_statistics", {})

    print("\n" + "=" * 80)
    print("                      SECUREPY BENCHMARK EVALUATION")
    print("=" * 80)
    print(f"Dataset: {stats.get('total_samples', 0)} samples ({stats.get('vulnerable_samples', 0)} vulnerable, {stats.get('secure_samples', 0)} secure)\n")

    header = f"{'Tool':<12} | {'TP':<4} | {'FP':<4} | {'TN':<4} | {'FN':<4} | {'Precision':<10} | {'Recall':<10} | {'F1-Score':<10} | {'Time (ms)':<10}"
    print(header)
    print("-" * len(header))

    for tool_name, data in tools.items():
        if data.get("available") and "metrics" in data:
            m = data["metrics"]
            p_str = f"{m['precision'] * 100:.1f}%"
            r_str = f"{m['recall'] * 100:.1f}%"
            f_str = f"{m['f1_score'] * 100:.1f}%"
            t_str = f"{m['total_time_ms']:.1f}"
            print(f"{tool_name:<12} | {m['true_positives']:<4} | {m['false_positives']:<4} | {m['true_negatives']:<4} | {m['false_negatives']:<4} | {p_str:<10} | {r_str:<10} | {f_str:<10} | {t_str:<10}")
        else:
            print(f"{tool_name:<12} | [NOT INSTALLED] {data.get('message', '')}")
    print("=" * 80 + "\n")


if __name__ == "__main__":
    results = run_evaluation()
    print_table(results)
