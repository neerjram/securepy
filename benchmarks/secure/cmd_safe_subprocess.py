# Secure: Subprocess argument list execution without shell
import subprocess

host = input("Host: ")
subprocess.run(["ping", "-c", "1", host], check=True)
