from scanner.engine import run_all_scans

def start_backend():
    print("Backend initialized")
    results = run_all_scans()
    # print(results)
    for finding in results:
     print(finding)
     