"""Remediation Code Suggestions for SecurePy.

Provides actionable before/after code fix examples for detected security issues.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from backend.engine.models.finding import Finding

MITIGATION_CODE_EXAMPLES: dict[str, str] = {
    "CWE-78": (
        "# SAFE ALTERNATIVE (subprocess argument list):\n"
        "import subprocess\n\n"
        "# Instead of: os.system('ping ' + host)\n"
        "subprocess.run(['ping', host], check=True)\n"
    ),
    "CWE-89": (
        "# SAFE ALTERNATIVE (parameterized query):\n"
        "# Instead of: cursor.execute(f'SELECT * FROM users WHERE name = {user}')\n"
        "cursor.execute('SELECT * FROM users WHERE name = ?', (user,))\n"
    ),
    "CWE-798": (
        "# SAFE ALTERNATIVE (environment variable):\n"
        "import os\n\n"
        "# Instead of: api_key = 'sk_live_secret123'\n"
        "api_key = os.getenv('API_KEY')\n"
    ),
    "CWE-95": (
        "# SAFE ALTERNATIVE (literal eval):\n"
        "import ast\n\n"
        "# Instead of: eval(user_str)\n"
        "safe_data = ast.literal_eval(user_str)\n"
    ),
    "CWE-502": (
        "# SAFE ALTERNATIVE (safe JSON):\n"
        "import json\n\n"
        "# Instead of: pickle.loads(payload)\n"
        "data = json.loads(payload)\n"
    ),
    "CWE-22": (
        "# SAFE ALTERNATIVE (basename sanitization):\n"
        "import os\n\n"
        "# Instead of: open(user_filename)\n"
        "safe_name = os.path.basename(user_filename)\n"
        "with open(os.path.join('/safe/dir', safe_name), 'r') as f:\n"
        "    content = f.read()\n"
    ),
}


def generate_mitigation_code(finding: Finding) -> str:
    """Return concrete Python mitigation code example for the given finding."""
    return MITIGATION_CODE_EXAMPLES.get(
        finding.cwe_id.upper(),
        "# Refer to remediation instructions above to safely refactor this operation.",
    )
