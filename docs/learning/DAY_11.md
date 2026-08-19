# Day 11 – Dangerous IAM Actions and Permission Risk Analysis

## 1. Goal of Day 11

Today I extended CloudSentinel's IAM scanner so that it can detect not only wildcard permissions and broad resources, but also **dangerous IAM actions**.

The main idea was:

> Some AWS permissions are dangerous even when they are not written as `*`.

For example:

```text
iam:CreateUser
iam:CreateAccessKey
iam:PassRole
s3:DeleteBucket
ec2:TerminateInstances
```

These permissions can have a serious impact if they are given to the wrong user, role, or group.

So the goal of Day 11 was to make CloudSentinel identify these high-risk permissions automatically.

---

# 2. What is an IAM Action?

An IAM policy contains permissions that describe what an identity is allowed to do.

For example:

```json
{
    "Effect": "Allow",
    "Action": "s3:GetObject",
    "Resource": "*"
}
```

Here:

* `Effect` = `Allow`
* `Action` = `s3:GetObject`
* `Resource` = `*`

The action tells AWS **what operation is allowed**.

Examples:

```text
s3:GetObject
s3:PutObject
iam:CreateUser
iam:PassRole
ec2:TerminateInstances
```

---

# 3. Why Dangerous Actions Matter

Previously, CloudSentinel mainly looked for things such as:

```text
Action: *
Resource: *
```

or:

```text
Action: s3:*
Resource: *
```

These are obviously dangerous because they provide very broad permissions.

But a policy can still be dangerous without using a wildcard.

For example:

```json
{
    "Effect": "Allow",
    "Action": "iam:CreateAccessKey",
    "Resource": "*"
}
```

There is no `Action: "*"` here.

However, `iam:CreateAccessKey` can still be a sensitive permission.

Therefore, CloudSentinel should also understand **specific high-risk actions**.

---

# 4. High-Risk Actions Added

For Day 11, I created a list called:

```python
HIGH_RISK_ACTIONS
```

It contains actions that CloudSentinel considers highly sensitive.

The actions are:

```text
iam:CreateUser
iam:CreateAccessKey
iam:AttachUserPolicy
iam:AttachGroupPolicy
iam:AttachRolePolicy
iam:PutUserPolicy
iam:PutGroupPolicy
iam:PutRolePolicy
iam:CreatePolicyVersion
iam:SetDefaultPolicyVersion
iam:PassRole
s3:DeleteBucket
ec2:TerminateInstances
```

---

# 5. Why These Actions Are Dangerous

## iam:CreateUser

Allows an identity to create another IAM user.

This can be risky because an attacker who gains this permission may create another AWS identity.

---

## iam:CreateAccessKey

Allows creation of access keys.

Access keys can be used for programmatic access to AWS.

Therefore, allowing an untrusted identity to create access keys can be dangerous.

---

## iam:AttachUserPolicy

Allows attaching a managed policy to a user.

This can potentially increase the permissions of that user.

---

## iam:AttachGroupPolicy

Allows attaching a policy to a group.

Since users can belong to groups, changing a group's policies can affect multiple identities.

---

## iam:AttachRolePolicy

Allows attaching policies to IAM roles.

Roles are commonly used by AWS services and applications, so changing their permissions can have a large impact.

---

## iam:PutUserPolicy

Allows creating or modifying an inline policy for a user.

This can directly change what the user is allowed to do.

---

## iam:PutGroupPolicy

Allows creating or modifying an inline policy for a group.

This can change permissions for multiple users at the same time.

---

## iam:PutRolePolicy

Allows creating or modifying an inline policy for a role.

This can be dangerous because roles are often used by applications and AWS services.

---

## iam:CreatePolicyVersion

Allows creating a new version of a managed policy.

Changing policy versions can change the permissions provided by that policy.

---

## iam:SetDefaultPolicyVersion

Allows changing which version of a policy is active.

This can potentially activate a more permissive policy version.

---

## iam:PassRole

This is an especially important IAM permission.

`iam:PassRole` allows an identity to pass an IAM role to an AWS service.

For example, if a user can pass a powerful role to a service, that service may operate with the permissions of that role.

Therefore, `iam:PassRole` needs careful control.

---

## s3:DeleteBucket

Allows deleting an S3 bucket.

This is a destructive operation and can cause data or service availability problems.

---

## ec2:TerminateInstances

Allows terminating EC2 instances.

This is also a destructive operation because an EC2 instance can be permanently terminated.

---

# 6. Medium-Risk Actions

I also created a second set:

```python
MEDIUM_RISK_ACTIONS
```

It contains:

```text
iam:DeleteUser
iam:DeleteAccessKey
iam:DeletePolicy
s3:PutObject
s3:DeleteObject
ec2:StopInstances
```

These actions are also important from a security perspective, but I classified them as MEDIUM instead of HIGH.

Examples:

```text
s3:PutObject
```

allows writing objects to an S3 bucket.

```text
s3:DeleteObject
```

allows deleting objects.

```text
ec2:StopInstances
```

allows stopping an EC2 instance.

The exact risk depends on the environment and what resource the permission applies to.

---

# 7. How CloudSentinel Detects Dangerous Actions

The scanner first gets the actions from the IAM policy statement.

For example:

```json
"Action": [
    "iam:CreateUser",
    "iam:CreateAccessKey",
    "iam:PassRole"
]
```

CloudSentinel compares these actions with:

```python
HIGH_RISK_ACTIONS
```

and:

```python
MEDIUM_RISK_ACTIONS
```

Conceptually:

```text
Policy Action
      |
      v
Is it in HIGH_RISK_ACTIONS?
      |
     YES
      |
      v
Create CRITICAL finding
```

If it is not high-risk, the scanner checks the medium-risk list.

```text
Policy Action
      |
      v
Is it in MEDIUM_RISK_ACTIONS?
      |
     YES
      |
      v
Create MEDIUM finding
```

---

# 8. Day 11 Test Policy

To test this functionality, I created:

```text
day11-dangerous-action.json
```

The policy contains:

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "iam:CreateUser",
                "iam:CreateAccessKey",
                "iam:PassRole",
                "s3:DeleteBucket",
                "ec2:TerminateInstances"
            ],
            "Resource": "*"
        }
    ]
}
```

This was intentionally created as a test policy.

It contains five dangerous actions.

---

# 9. Creating the Test Policy

Initially, I tried creating the policy using the AWS CLI.

The command was:

```cmd
aws iam create-policy ^
  --policy-name CloudSentinel-Day11-DangerousActions ^
  --policy-document file://day11-dangerous-action.json
```

At first, AWS returned:

```text
AccessDenied
```

because the `cloudsentinel-user` did not have permission to perform:

```text
iam:CreatePolicy
```

This was actually useful because it demonstrated the principle of **least privilege** in practice.

The scanner user itself did not have permission to create IAM policies.

I therefore created/attached the test policy using an identity with sufficient IAM privileges.

---

# 10. Verifying the Policy Attachment

I checked the policies attached to the test user using:

```cmd
aws iam list-attached-user-policies --user-name cloudsentinel-user
```

The output showed:

```text
CloudSentinel-Day11-DangerousActions
```

This confirmed that the test policy was attached to the user.

I also checked inline policies with:

```cmd
aws iam list-user-policies --user-name cloudsentinel-user
```

This showed the existing:

```text
group-inline-policy.json
```

---

# 11. Testing CloudSentinel

After attaching the dangerous policy, I ran:

```cmd
python main.py
```

CloudSentinel detected the new dangerous permissions.

The important finding was:

```text
CRITICAL
Policy: CloudSentinel-Day11-DangerousActions
Type: User Managed Policy
Attached To: cloudsentinel-user

Issue:
Policy "CloudSentinel-Day11-DangerousActions"
allows high-risk action(s):

iam:CreateUser
iam:CreateAccessKey
iam:PassRole
s3:DeleteBucket
ec2:TerminateInstances
```

The total number of IAM findings increased because CloudSentinel was now detecting the newly attached dangerous policy.

---

# 12. Why the Finding Was CRITICAL

The policy contained several high-risk actions.

These included:

```text
iam:CreateUser
iam:CreateAccessKey
iam:PassRole
s3:DeleteBucket
ec2:TerminateInstances
```

These actions can affect:

* IAM identities
* credentials
* roles
* S3 data
* EC2 infrastructure

Therefore, CloudSentinel classified this finding as:

```text
CRITICAL
```

---

# 13. Testing the Removal

After testing the scanner, I removed the dangerous test policy.

The `cloudsentinel-user` was not allowed to detach or delete the policy itself because it did not have:

```text
iam:DetachUserPolicy
```

or:

```text
iam:DeletePolicy
```

permissions.

Again, this demonstrated least privilege.

I used an identity with sufficient administrative permission to remove the test policy.

After removal, I ran:

```cmd
python main.py
```

again.

The dangerous policy finding disappeared.

CloudSentinel returned to the previous IAM findings.

This confirmed that the scanner was actually reading the current IAM configuration rather than simply printing a hardcoded result.

---

# 14. Existing Wildcard Detection Still Works

Day 11 did not replace the existing IAM checks.

CloudSentinel still detects cases such as:

```text
Action: *
Resource: *
```

and:

```text
Action: s3:*
Resource: *
```

For example:

```text
Policy "CloudSentinel-Group-Inline-Test"
allows s3:* on all resources
```

is still detected as a HIGH severity issue.

So the scanner now has multiple layers of IAM analysis.

---

# 15. IAM Risk Analysis in CloudSentinel

The scanner now checks several different things.

### 1. Full wildcard

```text
Action: *
Resource: *
```

Very broad permission.

---

### 2. Service wildcard

```text
Action: s3:*
Resource: *
```

Allows all actions for a particular service.

---

### 3. Broad action wildcard

Examples:

```text
s3:Get*
iam:List*
```

These can allow many related actions.

---

### 4. Specific action with wildcard resource

Example:

```text
Action: s3:GetObject
Resource: *
```

The action itself may be specific, but the resource is unrestricted.

---

### 5. Dangerous specific actions

Examples:

```text
iam:CreateUser
iam:CreateAccessKey
iam:PassRole
s3:DeleteBucket
ec2:TerminateInstances
```

This is the main addition in Day 11.

---

# 16. Resource Scope

Another important concept from the IAM scanner is **resource scope**.

Consider:

```json
"Action": "s3:GetObject",
"Resource": "*"
```

The action is specific, but the resource is broad.

Compare this with:

```json
"Action": "s3:GetObject",
"Resource": "arn:aws:s3:::cloudsentinel-test-552109716254/*"
```

The second policy is more restricted because it applies to a specific S3 bucket.

This is related to the **principle of least privilege**.

---

# 17. Least Privilege

The main security principle behind Day 11 is:

> Give an identity only the permissions it actually needs.

For example, if an application only needs to read objects from one bucket, it should not receive:

```text
s3:*
```

on:

```text
*
```

Instead, it should receive only the required action and resource.

Example:

```text
s3:GetObject
```

on:

```text
arn:aws:s3:::specific-bucket/*
```

---

# 18. Conditions

Another IAM concept implemented in the scanner is policy conditions.

Example:

```json
"Condition": {
    "Bool": {
        "aws:SecureTransport": "true"
    }
}
```

This means the permission has an additional condition.

The scanner can inspect the condition and identify:

```text
Operator: Bool
Key: aws:SecureTransport
Value: true
```

Conditions are important because an IAM permission is not always simply:

```text
ALLOW or DENY
```

A permission can also depend on additional context.

---

# 19. Example of a Condition

Example policy:

```json
{
    "Effect": "Allow",
    "Action": "s3:GetObject",
    "Resource": "arn:aws:s3:::cloudsentinel-test-552109716254/*",
    "Condition": {
        "Bool": {
            "aws:SecureTransport": "true"
        }
    }
}
```

Here the policy allows `s3:GetObject`, but it also contains a condition related to secure transport.

This is different from simply allowing the action without any condition.

---

# 20. Important Files Created/Modified

Day 11 mainly involved:

```text
scanner/iam_scanner.py
```

This contains the IAM scanning logic.

Test policy:

```text
day11-dangerous-action.json
```

This was used to test dangerous IAM actions.

The previous IAM test cases from earlier days were also kept because they are useful for regression testing.

---

# 21. Commands Used

### Check Python syntax

```cmd
python -m py_compile scanner/iam_scanner.py
```

If there is no output, the Python file passed the syntax check.

---

### Run CloudSentinel

```cmd
python main.py
```

---

### Check current AWS identity

```cmd
aws sts get-caller-identity
```

This showed that the scanner was running using:

```text
arn:aws:iam::552109716254:user/cloudsentinel-user
```

---

### Check attached user policies

```cmd
aws iam list-attached-user-policies --user-name cloudsentinel-user
```

---

### Check inline user policies

```cmd
aws iam list-user-policies --user-name cloudsentinel-user
```

---

### Check Git status

```cmd
git status
```

---

### Check recent commits

```cmd
git log --oneline -3
```

---

# 22. Git Commit

After testing the Day 11 implementation, I committed the changes using:

```cmd
git add scanner/iam_scanner.py day11-dangerous-action.json
```

Then:

```cmd
git commit -m "feat: detect dangerous IAM actions"
```

The commit created was:

```text
e76aa3e feat: detect dangerous IAM actions
```

The branch was:

```text
day-11
```

and it was pushed to GitHub.

---

# 23. What I Learned Today

Today I understood that IAM security is not only about checking for:

```text
Action: *
```

There can also be dangerous permissions hidden inside specific actions.

For example:

```text
iam:PassRole
iam:CreateAccessKey
iam:CreateUser
```

can be security-sensitive even though they are not wildcard permissions.

I also understood that:

* IAM policies contain actions and resources.
* Wildcard resources can make permissions broader.
* Some individual AWS actions are inherently sensitive.
* `iam:PassRole` needs special attention.
* Conditions can further restrict when a permission applies.
* Least privilege is one of the main principles of IAM security.
* The identity running the scanner also needs appropriate permissions.
* AWS `AccessDenied` errors can actually help identify missing permissions.
* Security tools should test real AWS configurations instead of only checking static files.

---

# 24. Final Day 11 Understanding

The main improvement in CloudSentinel on Day 11 was:

```text
Before Day 11
        |
        v
Check wildcard permissions
        |
        v
Check broad resources
```

After Day 11:

```text
                 IAM Policy
                     |
          +----------+----------+
          |          |          |
          v          v          v
      Actions    Resources   Conditions
          |
          v
  Risk Classification
          |
    +-----+------+
    |            |
    v            v
High Risk    Medium Risk
    |            |
    v            v
CRITICAL       MEDIUM
```

So CloudSentinel is becoming more than a simple AWS configuration checker.

It is gradually becoming an **IAM security analysis tool** that can identify different types of permission risks.

---

# 25. Day 11 Summary

**Main topic:** Dangerous IAM Action Detection

**Main implementation:** Added high-risk and medium-risk IAM action analysis.

**High-risk examples:**

```text
iam:CreateUser
iam:CreateAccessKey
iam:PassRole
s3:DeleteBucket
ec2:TerminateInstances
```

**Medium-risk examples:**

```text
iam:DeleteUser
s3:PutObject
s3:DeleteObject
ec2:StopInstances
```

**Test file:**

```text
day11-dangerous-action.json
```

**Result:**

CloudSentinel successfully detected the dangerous test policy as a CRITICAL IAM finding.

**Main concept learned:**

> IAM security is not only about wildcard permissions. Specific actions can also be dangerous, so a security scanner should understand the risk associated with individual permissions.
