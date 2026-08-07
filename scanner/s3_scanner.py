def scan_s3():
    return{
        "service": "S3",
        "resources": "demo-bucket",
        "status": "PASS",
        "message": "Bucket is private"
    }