# Vulnerable: SQL injection through formatted string literal
import sqlite3

cursor = sqlite3.connect(":memory:").cursor()
account_id = input("ID: ")
cursor.execute(f"DELETE FROM accounts WHERE id = {account_id}")
