# Vulnerable: SQL injection through string concatenation
import sqlite3

conn = sqlite3.connect("users.db")
cursor = conn.cursor()

user = input("User: ")
cursor.execute("SELECT * FROM accounts WHERE name = '" + user + "'")
