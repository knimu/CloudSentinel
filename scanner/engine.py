from config.config_loader import load_config
from scanner.models import Finding
from scanner.registry import get_scanner
from scanner.providers.aws_provider import get_aws_resources


def run_all_scans():
    config = load_config()
    resources = get_aws_resources()

    results = []

    if not config["scanning"]["enabled"]:
        return results

    severity = config["scanning"]["default_severity"]

    for service, service_resources in resources.items():

        scanner = get_scanner(service)

        if scanner:
            for resource in service_resources:
                results.append(scanner(resource, severity))

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