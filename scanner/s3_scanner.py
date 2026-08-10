from scanner.models import Finding

def scan_s3(severity):
    finding = Finding(
        service="S3",
        resource="demo-bucket",
        status="FAIL",
        severity=severity,
        message="Bucket is publicly accessible",
        recommendation="Disable public access"
    )

    return finding