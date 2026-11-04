"""Sample Vulnerable Application for SecurePy Demonstration."""

import os
import sqlite3

# Vulnerability 1: Hardcoded plaintext credentials (CWE-798)
ADMIN_API_KEY = "sk_live_94892482424824824892"
DB_SECRET = "ProductionRootPassword2026!"


def ping_server():
    """Vulnerability 2: Command Injection via tainted input (CWE-78)."""
    target = input("Enter server IP to ping: ")
    cmd = "ping -c 2 " + target
    os.system(cmd)


def search_user(username: str):
    """Vulnerability 3: SQL Injection via concatenated query (CWE-89)."""
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    query = "SELECT * FROM users WHERE username = '" + username + "'"
    cursor.execute(query)
    return cursor.fetchall()


def evaluate_calc(expression: str):
    """Vulnerability 4: Dynamic Code Execution via eval (CWE-95)."""
    return eval(expression)
