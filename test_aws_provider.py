from scanner.providers.aws_provider import get_aws_resources


resources = get_aws_resources()

print("Discovered AWS resources:")

for service, service_resources in resources.items():
    print(f"\nService: {service}")

    for resource in service_resources:
        print(f"Resource: {resource}")