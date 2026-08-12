from scanner.s3_scanner import scan_s3
from scanner.iam_scanner import scan_iam


SCANNERS = {
    "S3": scan_s3,
    "IAM": scan_iam
}


def get_scanner(service):
    return SCANNERS.get(service)