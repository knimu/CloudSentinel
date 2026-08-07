from scanner.engine import run_scan

def start_backend():
    print("Backend initialized")
    results =run_scan()
    print(results)