# Secure: Parameterized SQL statement with placeholders
import sqlite3

cursor = sqlite3.connect(":memory:").cursor()
user_id = input("ID: ")
cursor.execute("SELECT * FROM accounts WHERE id = ?", (user_id,))
