from scanner.models import Finding

def scan_s3(resource,severity):
    finding = Finding(
        service="S3",
        resource=resource,
        status="FAIL",
        severity=severity,
        message="Bucket is publicly accessible",
        recommendation="Disable public access"
    )

    return finding