import boto3
from botocore.exceptions import ClientError

from scanner.models import Finding


def scan_s3(resource, severity):

    try:
        s3 = boto3.client("s3")

        response = s3.get_public_access_block(
            Bucket=resource
        )

        config = response["PublicAccessBlockConfiguration"]

        fully_enabled = (
            config["BlockPublicAcls"]
            and config["IgnorePublicAcls"]
            and config["BlockPublicPolicy"]
            and config["RestrictPublicBuckets"]
        )

        if fully_enabled:
            return Finding(
                service="S3",
                resource=resource,
                status="PASS",
                severity="LOW",
                message="S3 Block Public Access is fully enabled",
                recommendation="No action required"
            )

        return Finding(
            service="S3",
            resource=resource,
            status="FAIL",
            severity=severity,
            message="S3 Block Public Access is not fully enabled",
            recommendation="Enable all S3 Block Public Access settings"
        )

    except ClientError as error:

        return Finding(
            service="S3",
            resource=resource,
            status="ERROR",
            severity="HIGH",
            message=f"AWS API error: {error.response['Error']['Code']}",
            recommendation="Verify AWS permissions and resource availability"
        )