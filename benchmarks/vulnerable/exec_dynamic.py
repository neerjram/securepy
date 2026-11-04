# Vulnerable: Arbitrary Python code execution
code = input("Code snippet: ")
exec(code)
