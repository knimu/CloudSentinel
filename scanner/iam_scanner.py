from scanner.models import Finding


def scan_iam(resource, severity):
    finding = Finding(
        service="IAM",
        resource=resource,
        status="FAIL",
        severity=severity,
        message="IAM user has excessive permissions",
        recommendation="Follow the principle of least privilege"
    )

    return finding