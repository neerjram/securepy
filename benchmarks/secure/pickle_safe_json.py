# Secure: Using JSON serializer for untrusted payload exchange
import json

payload = '{"action": "query", "id": 123}'
data = json.loads(payload)
print("Action:", data.get("action"))
