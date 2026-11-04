"""Benchmark Runner for Semgrep.

Runs Semgrep if installed in the current environment and normalizes results
for comparative evaluation against SecurePy.
"""

from __future__ import annotations

import json
from pathlib import Path
import shutil
import subprocess
import time
from typing import Any


def is_semgrep_available() -> bool:
    """Check if semgrep executable is available in PATH."""
    return shutil.which("semgrep") is not None


def run_semgrep(benchmark_files: list[Path]) -> dict[str, Any]:
    """Execute Semgrep against benchmark files and normalize results."""
    if not is_semgrep_available():
        return {
            "tool": "Semgrep",
            "available": False,
            "message": "Semgrep CLI is not installed in environment (install with: pip install semgrep).",
            "results": {},
        }

    results: dict[str, Any] = {}
    total_start = time.perf_counter()

    for file_path in benchmark_files:
        rel_key = str(file_path.as_posix())
        if "benchmarks/" in rel_key:
            rel_key = "benchmarks/" + rel_key.split("benchmarks/", 1)[1]

        t0 = time.perf_counter()
        cmd = ["semgrep", "--config", "auto", "--json", "-q", str(file_path)]
        try:
            res = subprocess.run(cmd, capture_output=True, text=True)
            elapsed_ms = (time.perf_counter() - t0) * 1000
            data = json.loads(res.stdout) if res.stdout else {"results": []}
            raw_findings = data.get("results", [])

            cwes: set[str] = set()
            for rf in raw_findings:
                meta = rf.get("extra", {}).get("metadata", {})
                cwe_list = meta.get("cwe", [])
                if isinstance(cwe_list, str):
                    cwe_list = [cwe_list]
                for c in cwe_list:
                    if "CWE-" in c:
                        cwes.add(c.split(":")[0].strip())

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
        "tool": "Semgrep",
        "available": True,
        "total_files": len(benchmark_files),
        "total_time_ms": round(total_time_ms, 2),
        "results": results,
    }
