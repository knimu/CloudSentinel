from scanner.s3_scanner import scan_s3

def run_scan():
    results = []

    results.append(scan_s3())

    return results