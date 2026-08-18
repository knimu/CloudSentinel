# Day 10 – IAM Policy Analysis

## 1. IAM Policy Structure

An IAM policy contains:
- Effect
- Action
- Resource
- Condition

## 2. Action

Action defines what AWS operation is allowed.

Example:
s3:GetObject

## 3. Service-Level Wildcard

Example:
s3:*

This means all actions supported by S3.

## 4. Action Wildcard

Example:
*

This means all IAM actions.

## 5. Resource

Resource defines which AWS resources the action applies to.

## 6. Broad Resource

Resource: "*"

The permission can apply to all resources supported by that action.

## 7. Scoped Resource

Example:

arn:aws:s3:::cloudsentinel-test-552109716254/*

The permission is restricted to a particular S3 bucket's objects.

## 8. ARN

ARN means Amazon Resource Name.

General structure:

arn:partition:service:region:account-id:resource

CloudSentinel parses ARNs to identify:
- partition
- service
- region
- account
- resource

## 9. Resource-Level Permissions

Some AWS actions support resource-level permissions.

For example:

Action:
s3:GetObject

Resource:
arn:aws:s3:::bucket-name/*

This is more specific than:

Resource:
*

## 10. Conditions

Conditions add additional restrictions to a policy.

Example:

"Condition": {
    "Bool": {
        "aws:SecureTransport": "true"
    }
}

This means the permission is conditional on HTTPS/TLS transport.

Another example:

"Condition": {
    "StringEquals": {
        "aws:PrincipalTag/Environment": "Production"
    }
}

## 11. CloudSentinel Analysis

CloudSentinel analyzes Allow statements and extracts:

- Action
- Resource
- Condition

It then evaluates the action/resource combination.

## 12. Current Risk Classification

### CRITICAL

Action "*" + Resource "*"

### HIGH

Service wildcard such as:

s3:*

with Resource "*"

### MEDIUM

Broad action such as:

s3:Get*
s3:List*

with Resource "*"

or a specific action with Resource "*".

### LOW

Specific/scoped resource ARN.

## 13. Test Policies

Day 10 includes test policies for:

- broad resource
- scoped resource
- condition-based permissions

## 14. Important Principle

CloudSentinel follows the principle of least privilege:

Only grant the actions and resources that are actually required.