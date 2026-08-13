import boto3


def get_iam_users():
    iam = boto3.client("iam")

    response = iam.list_users()

    users = []

    for user in response["Users"]:
        users.append(user["UserName"])

    return users