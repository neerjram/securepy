# Vulnerable: Insecure deserialization of user bytes
import pickle

data = input("Base64 payload: ")
obj = pickle.loads(data)
