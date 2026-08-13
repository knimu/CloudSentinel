from aws.s3_resources import get_s3_buckets
from aws.iam_resources import get_iam_users


def get_aws_resources():
    return {
        "S3": get_s3_buckets(),
        "IAM": get_iam_users()
    }