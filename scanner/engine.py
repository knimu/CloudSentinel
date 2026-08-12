from config.config_loader import load_config
from scanner.models import Finding
from scanner.registry import get_scanner





def run_all_scans():
    config = load_config()

    results = []

    if not config["scanning"]["enabled"]:
        return results

    severity = config["scanning"]["default_severity"]

    for service in config["services"]:

        scanner = get_scanner(service)

        if scanner:
          results.append(scanner(severity))
        else:
         results.append(
        Finding(
            service=service,
            resource="N/A",
            status="FAIL",
            severity="HIGH",
            message="No scanner available for this service",
            recommendation="Remove the unsupported service or add a scanner"
        )
    )

    return results