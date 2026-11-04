"""Sample Secure Application for SecurePy Demonstration."""

import ast
import os
import sqlite3
import subprocess

# Secure: Credentials loaded dynamically from environment
ADMIN_API_KEY = os.getenv("ADMIN_API_KEY")
DB_SECRET = os.getenv("DB_SECRET")


def ping_server():
    """Secure: Subprocess list execution without shell (shell=False)."""
    target = input("Enter server IP to ping: ")
    # Safe argument list prevents shell metacharacter interpretation
    subprocess.run(["ping", "-c", "2", target], check=True)


def search_user(username: str):
    """Secure: Parameterized SQL query prevents injection."""
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    # Placeholder ensures database engine handles input strictly as data
    cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
    return cursor.fetchall()


def evaluate_calc(expression: str):
    """Secure: ast.literal_eval only evaluates safe literal Python types."""
    return ast.literal_eval(expression)
