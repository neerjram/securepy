"""Remediation and Explanations Generator for SecurePy.

Produces beginner-friendly and developer-oriented technical explanations
tailored to specific vulnerability categories and CWEs.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from backend.engine.models.finding import Finding


BEGINNER_TEMPLATES: dict[str, str] = {
    "CWE-78": (
        "Command Injection happens when untrusted user input is passed directly to the operating system's command shell. "
        "Imagine letting a visitor write instructions directly on your system terminal—they could type '; rm -rf /' "
        "or download malware. Instead of running commands through a shell string, programs should pass distinct argument "
        "lists so the computer knows what is the command name and what is just plain data."
    ),
    "CWE-89": (
        "SQL Injection occurs when user input is glued directly into database query commands. "
        "If a user enters `' OR '1'='1`, the database gets tricked into returning all records or logging the user in without a password. "
        "To prevent this, use parameterized queries (using '?' or '%s' placeholders). The database will treat the input strictly as data, "
        "making it impossible for input to alter the SQL logic."
    ),
    "CWE-798": (
        "Hardcoded Credentials mean passwords, secret keys, or API tokens are written directly into your Python files. "
        "If you share your code, push it to GitHub, or show it to anyone, your accounts and systems could be compromised immediately. "
        "Always store secrets in environment variables or a configuration file that is ignored by Git (.gitignore)."
    ),
    "CWE-95": (
        "Eval Injection happens when Python's eval() or exec() functions run untrusted text as real Python code. "
        "This gives anyone supplying input total control over your application. Never use eval() on user input. "
        "If you need to parse safe numbers, lists, or dictionaries, use ast.literal_eval() instead."
    ),
    "CWE-502": (
        "Insecure Deserialization happens when Python's pickle module converts untrusted bytes back into Python objects. "
        "Pickle was never designed to be secure against untrusted data; crafted pickle payloads can execute arbitrary commands "
        "as soon as they are loaded. Use safer data formats like JSON (json.loads) instead."
    ),
    "CWE-22": (
        "Path Traversal occurs when a user input controls file path locations (e.g. '../../etc/passwd'). "
        "This allows attackers to read or overwrite critical files outside the intended folder. "
        "Always clean file names with os.path.basename() and verify that the final path stays inside your designated base directory."
    ),
}

DEVELOPER_TEMPLATES: dict[str, str] = {
    "CWE-78": (
        "The application invokes a system shell via `{evidence}` with unvalidated input. "
        "Metacharacters (e.g. `&`, `|`, `;`, `$()`, `` ` ``) in the parameter will be interpreted by `/bin/sh` or `cmd.exe`. "
        "Mitigation: Invoke binaries directly using `subprocess.run(['binary', 'arg1', 'arg2'], shell=False)` without shell interpolation."
    ),
    "CWE-89": (
        "A database query string is dynamically composed using string concatenation or interpolation: `{evidence}`. "
        "This violates SQL lexical parsing separation and allows an attacker to alter the query AST. "
        "Mitigation: Delegate query parsing to the database engine using parameterized statements: `cursor.execute('SELECT ... WHERE col = ?', (val,))`."
    ),
    "CWE-798": (
        "Plaintext secret assignment detected at line {line}: `{evidence}`. "
        "Committing secrets to VCS exposes credentials to repository clones and CI logs. "
        "Mitigation: Load secrets dynamically at runtime: `os.environ.get('SECRET_KEY')` or use a secret management service (Vault/AWS Secrets Manager)."
    ),
    "CWE-95": (
        "Dynamic evaluation of arbitrary expressions via `{evidence}` executes untrusted code in the current Python interpreter context. "
        "An attacker can exploit built-ins (e.g. `__import__('os').system('...')`) to gain complete remote code execution (RCE). "
        "Mitigation: Remove `eval`/`exec`. For literal evaluation, use `ast.literal_eval()`."
    ),
    "CWE-502": (
        "Unsafe deserialization sink invoked: `{evidence}`. "
        "Python's `pickle` stream format invokes `__reduce__` methods during reconstruction, permitting arbitrary callable invocation. "
        "Mitigation: Replace pickle with standard data serialization protocols like JSON, Protocol Buffers, or MessagePack."
    ),
    "CWE-22": (
        "File system access with untrusted path argument: `{evidence}`. "
        "Attackers can leverage directory traversal sequences (`..`) to escape root sandbox boundaries. "
        "Mitigation: Resolve canonical paths with `os.path.realpath()` and verify prefix with `os.path.commonpath()`."
    ),
}


def generate_beginner_explanation(finding: Finding) -> str:
    """Generate a beginner-friendly explanation for the finding's vulnerability."""
    cwe = finding.cwe_id.upper()
    default_text = (
        f"This finding represents a security weakness categorized under {cwe}. "
        f"Untrusted input or unsafe coding patterns may allow attackers to disrupt application security. "
        f"Review the remediation advice below to implement safe coding practices."
    )
    return BEGINNER_TEMPLATES.get(cwe, default_text)


def generate_developer_explanation(finding: Finding) -> str:
    """Generate a technical developer-oriented explanation with AST context."""
    cwe = finding.cwe_id.upper()
    template = DEVELOPER_TEMPLATES.get(cwe)
    if template:
        return template.format(
            evidence=finding.evidence.splitlines()[-1] if finding.evidence else "Call",
            line=finding.line_number,
        )
    return (
        f"Security vulnerability detected under {cwe} at line {finding.line_number}. "
        f"Evidence: {finding.evidence}. Review function callers and data sources to ensure proper sanitization."
    )
