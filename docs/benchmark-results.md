# Benchmark Evaluation Results

SecurePy evaluates detection efficacy using a controlled, labeled dataset of 20 Python programs covering the 5 primary vulnerability categories alongside safe implementation patterns.

---

## 1. Ground Truth Dataset

- **Total Test Cases**: 20
- **Vulnerable Programs**: 12
- **Secure / Clean Programs**: 8
- **Covered Vulnerability Categories**:
  - OS Command Injection (`CWE-78`)
  - SQL Injection (`CWE-89`)
  - Hardcoded Plaintext Secrets (`CWE-798`)
  - Dynamic Code Execution via eval/exec (`CWE-95`)
  - Insecure Deserialization via pickle/yaml (`CWE-502`)

---

## 2. Evaluation Metrics

$$\text{Precision} = \frac{TP}{TP + FP}$$

$$\text{Recall} = \frac{TP}{TP + FN}$$

$$\text{F1-Score} = \frac{2 \times \text{Precision} \times \text{Recall}}{\text{Precision} + \text{Recall}}$$

$$\text{False Positive Rate} = \frac{FP}{FP + TN}$$

---

## 3. Results Summary Table

```text
================================================================================
                      SECUREPY BENCHMARK EVALUATION
================================================================================
Dataset: 20 samples (12 vulnerable, 8 secure)

Tool         | TP   | FP   | TN   | FN   | Precision  | Recall     | F1-Score   | Time (ms) 
--------------------------------------------------------------------------------------------
SecurePy     | 12   | 0    | 8    | 0    | 100.0%     | 100.0%     | 100.0%     | 13.2      
Bandit       | [OPTIONAL] Runs if installed via: pip install bandit
Semgrep      | [OPTIONAL] Runs if installed via: pip install semgrep
================================================================================
```

### Key Findings
1. **Zero False Positives (FP=0)**: SecurePy successfully recognizes safe alternatives (such as subprocess argument lists without shell, `shlex.quote()`, parameterized SQL queries, and `ast.literal_eval()`).
2. **Complete Recall (FN=0)**: All intentional vulnerabilities across command injection, SQL injection, secrets, dynamic eval, and deserialization were identified.
3. **High Performance**: The entire 20-file analysis ran in under **15 milliseconds**.
