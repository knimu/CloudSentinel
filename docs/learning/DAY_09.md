

````markdown
# Day 09 — IAM Policy Scope & Multi-Source Permission Scanning

## Objective

Extend CloudSentinel's IAM scanner to detect risky permissions across different IAM policy sources.

The scanner now checks:

- User managed policies
- User inline policies
- Group managed policies
- Group inline policies

It also collects multiple IAM findings instead of returning only the highest-risk finding.

---

## 1. IAM Policy Types

### User Managed Policy

A managed policy is a reusable IAM policy that can be attached to users, groups, or roles.

Example:

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": "s3:*",
            "Resource": "*"
        }
    ]
}
````

The policy exists independently and can be attached to multiple identities.

---

### User Inline Policy

An inline policy is embedded directly inside one IAM identity.

For a user:

```text
IAM User
   |
   └── Inline Policy
```

It is directly associated with that user.

CloudSentinel retrieves user inline policies using:

```python
iam.list_user_policies(
    UserName=resource
)
```

and:

```python
iam.get_user_policy(
    UserName=resource,
    PolicyName=policy_name
)
```

---

### Group Managed Policy

A managed policy can be attached to an IAM group.

Example:

```text
CloudSentinel-Test-Group
        |
        └── CloudSentinel-Group-Managed-Test
```

Every user who belongs to that group receives the permissions from the attached policy.

CloudSentinel checks group membership using:

```python
iam.list_groups_for_user(
    UserName=resource
)
```

and then checks attached group policies.

---

### Group Inline Policy

A group can also have an inline policy directly embedded in the group.

Example:

```text
CloudSentinel-Test-Group
        |
        └── Group Inline Policy
```

CloudSentinel retrieves these using:

```python
iam.list_group_policies(
    GroupName=group_name
)
```

and:

```python
iam.get_group_policy(
    GroupName=group_name,
    PolicyName=policy_name
)
```

---

# 2. Why IAM Groups Matter

Groups are used to manage permissions for multiple users.

Instead of attaching the same policy separately to:

```text
User A
User B
User C
User D
```

we can create:

```text
Group
 |
 └── Policy
```

and put the users into that group.

For example:

```text
Developers Group
      |
      ├── Alice
      ├── Bob
      └── Charlie

Developers Group
      |
      └── Development Permissions
```

This makes permission management easier and more consistent.

---

# 3. Effective Permissions

A user's effective IAM permissions can come from multiple places.

For CloudSentinel:

```text
                    IAM User
                       |
        ┌──────────────┼──────────────┐
        |              |              |
 User Managed    User Inline       Groups
                                   |
                              ┌────┴────┐
                              |         |
                       Group Managed  Group Inline
```

Therefore, checking only user policies is insufficient.

CloudSentinel now checks all of these sources.

---

# 4. Wildcard Permission Detection

CloudSentinel classifies wildcard permissions into different risk levels.

## Critical

Action:

```text
*
```

Resource:

```text
*
```

This means the policy can allow every IAM action against every resource.

Example:

```json
{
    "Effect": "Allow",
    "Action": "*",
    "Resource": "*"
}
```

CloudSentinel classifies this as:

```text
CRITICAL
```

---

## High

Example:

```text
Action: s3:*
Resource: *
```

This allows all S3 actions against all resources.

CloudSentinel classifies this as:

```text
HIGH
```

---

## Medium

Examples:

```text
s3:Get*
s3:List*
iam:Get*
iam:List*
```

combined with:

```text
Resource: *
```

These are broad action patterns.

CloudSentinel classifies them as:

```text
MEDIUM
```

---

## Low

Example:

```text
Action: s3:GetObject
Resource: *
```

The action is specific, but the resource scope is broad.

CloudSentinel classifies this as:

```text
LOW
```

and recommends reviewing the wildcard resource scope.

---

# 5. Multiple Findings

Previously, CloudSentinel stored only the highest-risk finding.

Conceptually:

```text
Finding 1 → HIGH
Finding 2 → MEDIUM
Finding 3 → HIGH
        |
        └── Only one finding returned
```

This meant useful information could be hidden.

The scanner now collects all findings:

```text
findings = []

Finding 1 → findings[]
Finding 2 → findings[]
Finding 3 → findings[]
```

The scanner then determines the highest severity separately.

---

# 6. Severity Score

CloudSentinel uses:

```python
RISK_SCORES = {
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4
}
```

Therefore:

```text
LOW       = 1
MEDIUM    = 2
HIGH      = 3
CRITICAL  = 4
```

The highest score becomes the overall IAM severity.

For example:

```text
HIGH
HIGH
MEDIUM
MEDIUM
```

Overall:

```text
HIGH
```

---

# 7. Current CloudSentinel Test

The current test environment produced:

```text
5 IAM security issues
```

Detected policies:

1. User Inline Policy
2. Group Inline Policy
3. Group Managed Policy
4. IAMReadOnlyAccess
5. AmazonS3ReadOnlyAccess

The resulting overall severity was:

```text
HIGH
```

because the highest detected issue was a service-level wildcard such as:

```text
s3:*
```

on:

```text
Resource: *
```

---

# 8. Important Security Concept — Least Privilege

The principle of least privilege means an identity should receive only the permissions required to perform its intended task.

Avoid:

```text
Action: *
Resource: *
```

Prefer:

```text
Action: s3:GetObject
Resource: arn:aws:s3:::specific-bucket/*
```

when that is sufficient for the application.

The goal is to minimize the possible impact if credentials are compromised.

---

# 9. CloudSentinel Architecture After Day 9

```text
AWS Account
     |
     v
Resource Discovery
     |
     v
IAM Scanner
     |
     ├── User Managed Policies
     |
     ├── User Inline Policies
     |
     ├── Group Managed Policies
     |
     └── Group Inline Policies
             |
             v
       Policy Analysis
             |
             v
       Wildcard Detection
             |
             v
       Severity Classification
             |
             v
       Collect All Findings
             |
             v
       Determine Highest Severity
             |
             v
        Finding Object
```

---

# 10. Day 9 Result

CloudSentinel can now:

* Discover IAM groups associated with a user
* Inspect user inline policies
* Inspect group inline policies
* Inspect group managed policies
* Inspect user managed policies
* Parse IAM policy documents
* Detect wildcard actions
* Detect wildcard resources
* Classify risk severity
* Collect multiple findings
* Identify the highest overall severity
* Provide a consolidated recommendation

## Key Takeaway

IAM permissions do not come from only one place.

A security scanner must understand the complete permission path:

```text
User
  +
User Policies
  +
Groups
  +
Group Policies
  =
Effective Permission Surface
```

CloudSentinel's IAM scanner now accounts for this broader permission surface.

````
