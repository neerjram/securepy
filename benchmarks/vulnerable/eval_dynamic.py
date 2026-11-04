# Vulnerable: Arbitrary expression evaluation
expr = input("Calculate: ")
result = eval(expr)
print("Result:", result)
