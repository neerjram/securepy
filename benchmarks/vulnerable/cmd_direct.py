# Vulnerable: Direct OS command injection via input()
import os

user_cmd = input("Command: ")
os.system(user_cmd)
