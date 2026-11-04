# Vulnerable: Subprocess invocation with shell=True
import subprocess

user_script = input("Script: ")
subprocess.Popen("sh " + user_script, shell=True)
