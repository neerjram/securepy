"""Unit tests for SecurePy Security Rule Engine and detection rules."""

import pytest
from backend.engine.models.finding import Confidence, Severity
from backend.engine.rules import (
    BaseRule,
    RuleEngine,
    RuleRegistry,
    default_registry,
)


@pytest.fixture
def engine() -> RuleEngine:
    return RuleEngine()


# --- Registry and Engine Tests ---

def test_default_registry_contains_five_core_rules():
    """Verify registry initializes with the 5 core rules."""
    registry = RuleRegistry()
    rules = registry.get_all_rules()
    rule_ids = {r.rule_id for r in rules}
    assert len(rules) == 5
    assert rule_ids == {"SEC-R001", "SEC-R002", "SEC-R003", "SEC-R004", "SEC-R005"}


def test_custom_rule_registration(engine: RuleEngine):
    """Verify custom rules can be dynamically added to registry."""
    class CustomRule(BaseRule):
        rule_id = "CUSTOM-001"
        title = "Custom Test Rule"
        category = "Test"
        cwe_id = "CWE-000"
        default_severity = Severity.LOW
        default_confidence = Confidence.LOW

        def check(self, ir_mod, parsed=None):
            return [self.create_finding(line_number=1, description="Test", evidence="evidence", remediation="fix")]

    reg = RuleRegistry(load_defaults=False)
    reg.register(CustomRule())
    custom_engine = RuleEngine(registry=reg)

    findings = custom_engine.run_on_code("x = 1\n")
    assert len(findings) == 1
    assert findings[0].rule_id == "CUSTOM-001"


# --- Rule SEC-R001: Hardcoded Credentials ---

def test_credentials_rule_detects_secrets(engine: RuleEngine):
    """Detect hardcoded passwords and API keys."""
    vulnerable_code = (
        "api_key = 'sk_live_94892482424824824'\n"
        "db_password = 'SuperSecretDbPassword123!'\n"
    )
    findings = engine.run_on_code(vulnerable_code)
    cred_findings = [f for f in findings if f.rule_id == "SEC-R001"]

    assert len(cred_findings) == 2
    assert cred_findings[0].severity == Severity.HIGH
    assert cred_findings[0].cwe_id == "CWE-798"
    assert "api_key" in cred_findings[0].description
    assert "db_password" in cred_findings[1].description


def test_credentials_rule_ignores_safe_patterns(engine: RuleEngine):
    """Safe patterns like getenv or placeholders should not trigger findings."""
    secure_code = (
        "import os\n"
        "api_key = os.getenv('API_KEY')\n"
        "secret_token = 'YOUR_API_KEY_HERE'\n"
        "empty_pwd = ''\n"
    )
    findings = engine.run_on_code(secure_code)
    cred_findings = [f for f in findings if f.rule_id == "SEC-R001"]
    assert len(cred_findings) == 0


# --- Rule SEC-R002: Dangerous Functions (eval/exec) ---

def test_dangerous_eval_exec_vulnerable(engine: RuleEngine):
    """Dynamic eval/exec calls should be flagged with CRITICAL severity."""
    vulnerable_code = (
        "user_input = input()\n"
        "eval(user_input)\n"
        "exec('print(' + user_input + ')')\n"
    )
    findings = engine.run_on_code(vulnerable_code)
    eval_findings = [f for f in findings if f.rule_id == "SEC-R002"]

    assert len(eval_findings) == 2
    assert all(f.severity == Severity.CRITICAL for f in eval_findings)
    assert all(f.cwe_id == "CWE-95" for f in eval_findings)


def test_dangerous_eval_static_string(engine: RuleEngine):
    """Static literal eval should be flagged with lower severity."""
    code = "eval('1 + 1')\n"
    findings = engine.run_on_code(code)
    eval_findings = [f for f in findings if f.rule_id == "SEC-R002"]

    assert len(eval_findings) == 1
    assert eval_findings[0].severity == Severity.LOW


def test_safe_literal_eval(engine: RuleEngine):
    """ast.literal_eval is safe and should not trigger SEC-R002."""
    code = "import ast\nres = ast.literal_eval('[1, 2, 3]')\n"
    findings = engine.run_on_code(code)
    eval_findings = [f for f in findings if f.rule_id == "SEC-R002"]
    assert len(eval_findings) == 0


# --- Rule SEC-R003: Command Injection ---

def test_command_injection_vulnerable_patterns(engine: RuleEngine):
    """os.system with dynamic input and subprocess with shell=True should trigger SEC-R003."""
    code = (
        "import os, subprocess\n"
        "cmd = input()\n"
        "os.system(cmd)\n"
        "subprocess.Popen('ping ' + cmd, shell=True)\n"
    )
    findings = engine.run_on_code(code)
    cmd_findings = [f for f in findings if f.rule_id == "SEC-R003"]

    assert len(cmd_findings) == 2
    assert cmd_findings[0].cwe_id == "CWE-78"
    assert "os.system" in cmd_findings[0].evidence
    assert "shell=True" in cmd_findings[1].evidence


def test_command_injection_safe_subprocess(engine: RuleEngine):
    """Safe subprocess.run with argument list should not trigger findings."""
    code = (
        "import subprocess\n"
        "host = 'google.com'\n"
        "subprocess.run(['ping', host], check=True)\n"
    )
    findings = engine.run_on_code(code)
    cmd_findings = [f for f in findings if f.rule_id == "SEC-R003"]
    assert len(cmd_findings) == 0


# --- Rule SEC-R004: SQL Injection ---

def test_sql_injection_dynamic_queries(engine: RuleEngine):
    """Direct concatenation and f-strings in SQL should trigger SEC-R004."""
    code = (
        "name = input()\n"
        "cursor.execute('SELECT * FROM users WHERE name = ' + name)\n"
        "cursor.execute(f'DELETE FROM accounts WHERE id = {name}')\n"
        "q = 'SELECT * FROM items WHERE id = ' + name\n"
        "cursor.execute(q)\n"
    )
    findings = engine.run_on_code(code)
    sql_findings = [f for f in findings if f.rule_id == "SEC-R004"]

    assert len(sql_findings) >= 2
    assert all(f.cwe_id == "CWE-89" for f in sql_findings)


def test_sql_injection_safe_parameterized_query(engine: RuleEngine):
    """Parameterized queries using ? or %s placeholders should be safe."""
    code = (
        "user_id = 42\n"
        "cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))\n"
    )
    findings = engine.run_on_code(code)
    sql_findings = [f for f in findings if f.rule_id == "SEC-R004"]
    assert len(sql_findings) == 0


# --- Rule SEC-R005: Insecure Deserialization ---

def test_insecure_deserialization_pickle_and_yaml(engine: RuleEngine):
    """pickle.loads and unsafe yaml.load should trigger SEC-R005."""
    code = (
        "import pickle, yaml\n"
        "payload = input()\n"
        "pickle.loads(payload)\n"
        "yaml.load(payload, Loader=yaml.Loader)\n"
    )
    findings = engine.run_on_code(code)
    deser_findings = [f for f in findings if f.rule_id == "SEC-R005"]

    assert len(deser_findings) == 2
    assert all(f.cwe_id == "CWE-502" for f in deser_findings)


def test_safe_json_deserialization(engine: RuleEngine):
    """json.loads and yaml.safe_load should not trigger findings."""
    code = (
        "import json, yaml\n"
        "payload = '{\"a\": 1}'\n"
        "data1 = json.loads(payload)\n"
        "data2 = yaml.safe_load(payload)\n"
    )
    findings = engine.run_on_code(code)
    deser_findings = [f for f in findings if f.rule_id == "SEC-R005"]
    assert len(deser_findings) == 0
