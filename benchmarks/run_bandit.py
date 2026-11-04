"""Benchmark Runner for Bandit.

Runs Bandit if installed in the current environment and normalizes results
for comparative evaluation against SecurePy.
"""

from __future__ import annotations

import json
from pathlib import Path
import shutil
import subprocess
import time
from typing import Any

BANDIT_CWE_MAP: dict[str, str] = {
    "B602": "CWE-78",   # subprocess_popen_with_shell_equals_true
    "B605": "CWE-78",   # start_process_with_a_shell
    "B607": "CWE-78",   # start_process_with_partial_path
    "B608": "CWE-89",   # hardcoded_sql_expressions
    "B105": "CWE-798",  # hardcoded_password_string
    "B106": "CWE-798",  # hardcoded_password_funcarg
    "B107": "CWE-798",  # hardcoded_password_default
    "B307": "CWE-95",   # eval
    "B102": "CWE-95",   # exec
    "B301": "CWE-502",  # pickle
    "B506": "CWE-502",  # yaml_load
}


def is_bandit_available() -> bool:
    """Check if bandit executable or module is available in PATH."""
    return shutil.which("bandit") is not None


def run_bandit(benchmark_files: list[Path]) -> dict[str, Any]:
    """Execute Bandit against benchmark files and normalize results."""
    if not is_bandit_available():
        return {
            "tool": "Bandit",
            "available": False,
            "message": "Bandit CLI is not installed in environment (install with: pip install bandit).",
            "results": {},
        }

    results: dict[str, Any] = {}
    total_start = time.perf_counter()

    for file_path in benchmark_files:
        rel_key = str(file_path.as_posix())
        if "benchmarks/" in rel_key:
            rel_key = "benchmarks/" + rel_key.split("benchmarks/", 1)[1]

        t0 = time.perf_counter()
        cmd = ["bandit", "-f", "json", "-q", str(file_path)]
        try:
            res = subprocess.run(cmd, capture_output=True, text=True)
            elapsed_ms = (time.perf_counter() - t0) * 1000
            data = json.loads(res.stdout) if res.stdout else {"results": []}
            raw_findings = data.get("results", [])

            cwes: set[str] = set()
            for rf in raw_findings:
                test_id = rf.get("test_id", "")
                mapped_cwe = BANDIT_CWE_MAP.get(test_id)
                if mapped_cwe:
                    cwes.add(mapped_cwe)

            results[rel_key] = {
                "file": rel_key,
                "findings_count": len(raw_findings),
                "execution_time_ms": round(elapsed_ms, 2),
                "detected_cwes": sorted(list(cwes)),
            }
        except Exception:
            results[rel_key] = {
                "file": rel_key,
                "findings_count": 0,
                "execution_time_ms": 0.0,
                "detected_cwes": [],
            }

    total_time_ms = (time.perf_counter() - total_start) * 1000

    return {
        "tool": "Bandit",
        "available": True,
        "total_files": len(benchmark_files),
        "total_time_ms": round(total_time_ms, 2),
        "results": results,
    }
