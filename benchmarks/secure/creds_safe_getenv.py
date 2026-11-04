# Secure: Loading credentials from environment variable
import os

api_key = os.getenv("APP_API_KEY")
print("Connecting with key...")
