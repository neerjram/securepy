"""Benchmark Runner for SecurePy.

Runs the SecurePy static analysis engine against all benchmark test cases
and returns standardized finding records and execution timings.
"""

from __future__ import annotations

import json
from pathlib import Path
import sys
import time
from typing import Any

# Ensure project root is in pythonpath
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from backend.engine.aggregation import FindingAggregator
from backend.engine.analysis.ast_analyzer import ASTAnalyzer
from backend.engine.parser.python_parser import PythonParser
from backend.engine.rules.rule_engine import RuleEngine
from backend.engine.taint.taint_analyzer import TaintAnalyzer


def run_benchmark(benchmark_files: list[Path]) -> dict[str, Any]:
    """Execute SecurePy analysis across benchmark files and collect metrics."""
    parser = PythonParser()
    ast_analyzer = ASTAnalyzer()
    rule_engine = RuleEngine()
    taint_analyzer = TaintAnalyzer()
    aggregator = FindingAggregator()

    results: dict[str, Any] = {}
    total_start = time.perf_counter()

    for file_path in benchmark_files:
        rel_key = str(file_path.as_posix())
        # Clean relative path
        if "benchmarks/" in rel_key:
            rel_key = "benchmarks/" + rel_key.split("benchmarks/", 1)[1]

        start_time = time.perf_counter()
        code = file_path.read_text(encoding="utf-8")
        parsed = parser.parse_code(code, file_path=file_path.name)

        findings = []
        if parsed.is_valid:
            ir_mod = ast_analyzer.analyze_parsed_module(parsed)
            rf = rule_engine.run(ir_mod, parsed)
            tf = taint_analyzer.analyze(ir_mod, parsed)
            findings = aggregator.aggregate(rf, tf)

        elapsed_ms = (time.perf_counter() - start_time) * 1000

        results[rel_key] = {
            "file": rel_key,
            "findings_count": len(findings),
            "findings": [f.to_dict() for f in findings],
            "execution_time_ms": round(elapsed_ms, 2),
            "detected_cwes": sorted(list({f.cwe_id for f in findings})),
        }

    total_time_ms = (time.perf_counter() - total_start) * 1000

    return {
        "tool": "SecurePy",
        "total_files": len(benchmark_files),
        "total_time_ms": round(total_time_ms, 2),
        "avg_time_per_file_ms": round(total_time_ms / len(benchmark_files), 2) if benchmark_files else 0,
        "results": results,
    }


if __name__ == "__main__":
    benchmarks_dir = Path(__file__).resolve().parent
    vulnerable_files = sorted(list((benchmarks_dir / "vulnerable").glob("*.py")))
    secure_files = sorted(list((benchmarks_dir / "secure").glob("*.py")))
    all_files = vulnerable_files + secure_files

    output = run_benchmark(all_files)
    print(json.dumps(output, indent=2))
