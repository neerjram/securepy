# Secure: Using ast.literal_eval for safe data structure parsing
import ast

data_str = '{"user": "alice", "roles": ["admin"]}'
parsed = ast.literal_eval(data_str)
print("Parsed role:", parsed.get("roles"))
