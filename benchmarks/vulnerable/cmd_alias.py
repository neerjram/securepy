# Vulnerable: Multi-hop variable alias propagation to shell
import os

a = input("Enter payload: ")
b = a
c = b
os.system(c)
