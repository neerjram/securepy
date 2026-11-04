# Vulnerable: OS command injection via string concatenation
import os

host = input("Host: ")
command = "ping -c 1 " + host
os.system(command)
