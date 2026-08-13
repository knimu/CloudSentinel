from aws.iam_resources import get_iam_users


users = get_iam_users()

print("Discovered IAM users:")

for user in users:
    print(user)