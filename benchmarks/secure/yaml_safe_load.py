# Secure: Using yaml.safe_load without arbitrary Python code execution
import yaml

content = "app_name: SecurePy\nport: 8000\n"
config = yaml.safe_load(content)
print("Config port:", config.get("port"))
