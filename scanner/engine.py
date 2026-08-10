from config.config_loader import load_config
from scanner.s3_scanner import scan_s3


def run_all_scans():
    config = load_config()

    results = []

    if not config["scanning"]["enabled"]:
        return results

    if "S3" in config["services"]:
        severity = config["scanning"]["default_severity"]

        results.append(scan_s3(severity))

    return results