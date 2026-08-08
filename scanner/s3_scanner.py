from scanner.models import Finding

def scan_s3():
    finding = Finding(
        service="S3",
        resource="demo-bucket",
        status="FAIL",
        severity="HIGH",
        message="Bucket is publicly accessible",
        recommendation="Disable public access"
    )

    return finding