# Secure: Quoting parameters before shell execution
import os
import shlex

host = input("Host: ")
safe_host = shlex.quote(host)
os.system("ping -c 1 " + safe_host)
