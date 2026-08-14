````markdown
# Day 8 — IAM Permission Risk Analysis

## 1. Goal

The goal of Day 8 was to make CloudSentinel's IAM scanner more realistic.

Instead of only checking whether an IAM user has `AdministratorAccess`, the scanner now reads IAM policy documents and analyzes the permissions inside them.

The scanner checks:

- AdministratorAccess
- Wildcard actions
- Service-level wildcards
- Broad action patterns
- Wildcard resources
- Inline policies
- Policies attached directly to users
- Policies inherited through groups

---

# 2. IAM Policy Structure

An IAM policy contains statements that describe what a user, role, or other principal is allowed or denied to do.

The important elements we are using are:

```text
Effect
Action
Resource
````

For example:

```json
{
    "Effect": "Allow",
    "Action": "s3:GetObject",
    "Resource": "arn:aws:s3:::my-bucket/*"
}
```

This means:

* `Effect: Allow` → permission is granted
* `Action: s3:GetObject` → the user can read S3 objects
* `Resource` → the permission applies to the specified bucket objects

AWS documents `Action` as the element that specifies the AWS operations being allowed or denied. `Resource` specifies which resources those actions apply to.

---

# 3. AdministratorAccess Detection

CloudSentinel first checks whether the IAM user has the AWS managed policy:

```text
AdministratorAccess
```

This policy provides extremely broad permissions.

CloudSentinel reports:

```text
Severity: CRITICAL
```

because administrator-level access can allow a principal to perform a very large range of operations across the AWS account.

Example finding:

```text
IAM user has AdministratorAccess permissions
```

Recommendation:

```text
Follow the principle of least privilege
```

---

# 4. Wildcard Actions

A wildcard action is represented by:

```text
*
```

For example:

```json
"Action": "*"
```

This can allow actions across AWS services.

When combined with:

```json
"Resource": "*"
```

the permission becomes extremely broad.

CloudSentinel classifies this as:

```text
CRITICAL
```

Example:

```text
Policy "CloudSentinel-Test-Wildcard"
allows wildcard action "*" on all resources
```

---

# 5. Service-Level Wildcards

A service-level wildcard looks like:

```text
s3:*
```

or:

```text
iam:*
```

This is different from:

```text
*
```

because it applies to one AWS service rather than every AWS service.

For example:

```json
{
    "Effect": "Allow",
    "Action": "s3:*",
    "Resource": "*"
}
```

allows all S3 actions within the scope of the statement.

CloudSentinel classifies this as:

```text
HIGH
```

because the permission is extremely broad within one service.

---

# 6. Broad Action Patterns

AWS also supports wildcards inside action names.

Examples:

```text
s3:Get*
s3:List*
iam:Get*
iam:List*
```

These do not mean every action in the service.

For example:

```text
iam:Get*
```

matches multiple IAM Get operations.

Similarly:

```text
iam:List*
```

matches multiple IAM List operations.

CloudSentinel classifies broad action patterns combined with wildcard resources as:

```text
MEDIUM
```

Example finding:

```text
Policy "IAMReadOnlyAccess" allows
iam:Get*, iam:List* on all resources
```

Recommendation:

```text
Restrict the resource scope to only those required
```

---

# 7. Wildcard Resources

The following:

```json
"Resource": "*"
```

means the statement applies broadly to resources.

However, CloudSentinel does NOT automatically treat every wildcard resource as a critical vulnerability.

Some AWS actions do not support resource-level permissions and therefore require:

```text
Resource: "*"
```

AWS documents this behavior in its IAM policy documentation.

Therefore CloudSentinel considers the Action and Resource together.

For example:

```text
s3:Get*
Resource: *
```

is more concerning than:

```text
s3:GetObject
Resource: *
```

but neither should automatically be treated as equivalent to:

```text
Action: *
Resource: *
```

---

# 8. Risk Classification

CloudSentinel currently uses the following model:

```text
Action "*" + Resource "*"
        ↓
CRITICAL
```

```text
Service wildcard such as s3:* + Resource "*"
        ↓
HIGH
```

```text
Broad actions such as s3:Get* + Resource "*"
        ↓
MEDIUM
```

```text
Specific action + Resource "*"
        ↓
LOW
```

```text
Specific action + specific resource
        ↓
No high-risk wildcard finding
```

The purpose is not to say that every LOW or MEDIUM finding is automatically exploitable.

The purpose is to identify permission patterns that deserve review.

---

# 9. Direct User Policies

CloudSentinel checks policies attached directly to the IAM user.

It uses:

```python
iam.list_attached_user_policies()
```

Then retrieves the policy:

```python
iam.get_policy()
```

and its active version:

```python
iam.get_policy_version()
```

The policy document is then analyzed statement by statement.

---

# 10. Group Policies

IAM users can inherit permissions through groups.

Therefore, checking only policies directly attached to the user would give an incomplete security picture.

CloudSentinel also calls:

```python
iam.list_groups_for_user()
```

and then:

```python
iam.list_attached_group_policies()
```

This allows CloudSentinel to detect excessive permissions inherited through an IAM group.

---

# 11. Inline Policies

CloudSentinel also checks:

```python
iam.list_user_policies()
```

Inline policies are policies embedded directly into an IAM identity.

CloudSentinel currently reports their presence for review:

```text
IAM user has inline policies that require review
```

The scanner does not automatically classify every inline policy as dangerous.

The policy itself must still be analyzed to understand what permissions it grants.

---

# 12. Highest-Risk Finding

A user can have multiple policies.

For example:

```text
IAMReadOnlyAccess
        ↓
MEDIUM

CloudSentinel-Test-ServiceWildcard
        ↓
HIGH
```

CloudSentinel should report the highest-risk finding:

```text
HIGH
```

Similarly:

```text
IAMReadOnlyAccess
        ↓
MEDIUM

CloudSentinel-Test-Wildcard
        ↓
CRITICAL
```

CloudSentinel reports:

```text
CRITICAL
```

This prevents a less serious policy from hiding a more serious permission.

---

# 13. Error Handling

AWS API calls can fail because of:

* Missing permissions
* Invalid resources
* AWS API errors
* Configuration problems
* Network problems

The scanner therefore catches exceptions and returns:

```text
Status: ERROR
Severity: HIGH
```

instead of crashing the entire CloudSentinel application.

---

# 14. Testing Performed

We tested CloudSentinel using different IAM permission patterns.

### Test 1 — Full wildcard

```text
Action: *
Resource: *
```

Result:

```text
CRITICAL
```

---

### Test 2 — Service wildcard

```text
Action: s3:*
Resource: *
```

Result:

```text
HIGH
```

---

### Test 3 — Broad action wildcard

```text
Action: iam:Get*
Action: iam:List*
Resource: *
```

Result:

```text
MEDIUM
```

---

### Test 4 — Existing AWS managed policy

CloudSentinel detected:

```text
IAMReadOnlyAccess
```

and produced:

```text
Status: FAIL
Severity: MEDIUM
Message:
Policy "IAMReadOnlyAccess" allows
iam:Get*, iam:List* on all resources
```

This demonstrated that the scanner is reading the actual AWS policy document instead of relying only on the policy name.

---

# 15. Principle of Least Privilege

The main security principle behind this scanner is:

> Give a user or service only the permissions required to perform its job.

For example, if an application only needs:

```text
s3:GetObject
```

it should not automatically receive:

```text
s3:*
```

and definitely should not receive:

```text
*
```

The smaller the permission scope, the smaller the potential impact if the identity is compromised.

AWS recommends granting only the permissions required for a task and refining permissions toward least privilege.

---

# 16. Day 8 Architecture

The IAM scanning flow is now:

```text
IAM User
    |
    +---- Direct Policies
    |
    +---- Group Policies
    |
    +---- Inline Policies
             |
             v
      Policy Documents
             |
             v
        Statements
             |
             v
      Action + Resource
             |
             v
       Risk Classification
             |
             v
    Highest-Risk Finding
             |
             v
        Finding Object
```

---

# 17. What I Learned

Day 8 helped me understand that IAM security is not simply about checking whether a user is an administrator.

A user can still have excessive permissions without having `AdministratorAccess`.

For example:

```text
s3:*
```

can provide very broad S3 access.

Similarly:

```text
iam:Get*
iam:List*
```

can provide a broad collection of IAM read operations.

Therefore, a security scanner needs to inspect the actual policy statements.

I also learned that:

```text
Action
```

and:

```text
Resource
```

must be analyzed together.

A wildcard does not always mean the same level of risk.

The scanner therefore classifies different wildcard patterns instead of treating all of them as identical.

---

# 18. Day 8 Result

By the end of Day 8, CloudSentinel can:

* Discover IAM users
* Discover S3 buckets
* Check S3 Block Public Access
* Detect AdministratorAccess
* Read IAM managed policies
* Inspect policy versions
* Analyze policy statements
* Detect full wildcard actions
* Detect service-level wildcards
* Detect broad action patterns
* Detect wildcard resources
* Check group-inherited permissions
* Detect inline policies
* Assign severity levels
* Return the highest-risk IAM finding
* Handle AWS API errors safely

The IAM scanner has moved from a simple hardcoded check to a basic policy-analysis engine.

````

The important AWS concepts in these notes are consistent with AWS's current IAM documentation: `Action` defines allowed/denied operations, `Resource` defines the resources affected, and wildcard use can have different meanings depending on the action and service. AWS also explicitly recommends least privilege. :contentReference[oaicite:0]{index=0}

### Now do the final Day 8 test

1. Remove `CloudSentinel-Test-ServiceWildcard`.
2. Run:

```text
.venv\Scripts\python.exe main.py
````

3. Make sure you are back to the `IAMReadOnlyAccess` **MEDIUM** result.
4. Save `docs/learning/DAY_08.md`.
5. Then run:

