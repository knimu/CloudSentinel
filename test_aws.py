from aws.s3_resources import get_s3_buckets


buckets = get_s3_buckets()

print("Discovered S3 buckets:")

for bucket in buckets:
    print(bucket)