import boto3


def get_s3_buckets():
    s3 = boto3.client("s3")

    response = s3.list_buckets()

    buckets = []

    for bucket in response.get("Buckets", []):
        buckets.append(bucket["Name"])

    return buckets