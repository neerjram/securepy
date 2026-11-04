# Vulnerable: Insecure PyYAML loading without SafeLoader
import yaml

content = input("YAML text: ")
parsed = yaml.load(content, Loader=yaml.Loader)
