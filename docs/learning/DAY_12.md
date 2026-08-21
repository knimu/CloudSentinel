# Day 12 — IAM Condition Context Analysis

## 1. What did we work on today?

Today we extended **CloudSentinel's IAM scanner** to understand the `Condition` part of an AWS IAM policy.

Earlier, CloudSentinel was mainly checking things like:

* Wildcard actions such as `*`
* Service-level wildcards such as `s3:*`
* Broad actions such as `s3:Get*`
* Wildcard resources such as `"Resource": "*"`
* Dangerous IAM actions such as `iam:CreateUser` and `iam:PassRole`

But an IAM policy can also contain a **Condition**.

A condition can restrict when a permission is allowed.

For example, instead of simply saying:

```json
"Action": "s3:GetObject",
"Resource": "*"
```

a policy can say:

```json
"Action": "s3:GetObject",
"Resource": "*",
"Condition": {
    "Bool": {
        "aws:SecureTransport": "true"
    }
}
```

This means the permission has an additional condition related to secure transport.

So the goal of Day 12 was to make CloudSentinel **aware of these condition controls**.

---

# 2. What is an IAM Condition?

An IAM `Condition` is an optional part of an IAM policy statement.

It allows AWS to check additional information before allowing an action.

A simplified policy structure is:

```text
Statement
│
├── Effect
├── Action
├── Resource
└── Condition
```

For example:

```json
{
    "Effect": "Allow",
    "Action": "s3:GetObject",
    "Resource": "*",
    "Condition": {
        "Bool": {
            "aws:SecureTransport": "true"
        }
    }
}
```

Here:

* `Effect` → Allow
* `Action` → `s3:GetObject`
* `Resource` → `*`
* `Condition` → Secure transport must be true

So the condition adds another layer of control to the permission.

---

# 3. Why are Conditions important for security?

Conditions are important because they can make a broad permission more restricted.

For example:

```json
"Resource": "*"
```

looks broad.

But if a condition is also present, the permission may only be usable when that condition is satisfied.

Some useful conditions can restrict access based on things such as:

* Whether secure transport is being used
* Source IP address
* Principal tags
* Other AWS request/context information

Therefore, simply seeing `"Resource": "*"` does not always tell us the whole story.

CloudSentinel should eventually be able to understand this context.

---

# 4. What did we add?

We added a helper function to:

```text
scanner/iam_scanner.py
```

The function is:

```python
analyze_condition_context(condition)
```

Its purpose is to look at the `Condition` section and convert useful condition information into simple human-readable descriptions.

It returns a list.

For example:

```python
[
    "SecureTransport=true"
]
```

or:

```python
[
    "SourceIp=['203.0.113.0/24']"
]
```

---

# 5. Why did we make a separate helper function?

Instead of putting all the condition-processing logic directly inside `scan_iam()`, we created:

```python
analyze_condition_context()
```

as a separate function.

This makes the code easier to understand.

The responsibilities are separated:

```text
scan_iam()
    ↓
reads IAM policies
    ↓
gets Condition
    ↓
analyze_condition_context()
    ↓
understands useful condition controls
```

This is better than putting everything into one huge function.

It also makes it easier to extend the scanner later.

For example, in the future we could add more condition keys without rewriting the main IAM scanning logic.

---

# 6. How does the helper work?

The function first checks whether a condition exists.

```python
if not condition:
    return controls
```

If there is no condition, it simply returns:

```text
[]
```

Then it loops through the condition operators.

For example:

```json
"Condition": {
    "Bool": {
        "aws:SecureTransport": "true"
    }
}
```

Here:

```text
operator = Bool
```

and:

```text
condition_values =
{
    "aws:SecureTransport": "true"
}
```

Then it checks the condition keys.

---

# 7. SecureTransport condition

One condition we specifically handle is:

```text
aws:SecureTransport
```

Example:

```json
"Condition": {
    "Bool": {
        "aws:SecureTransport": "true"
    }
}
```

Our helper converts this into:

```text
SecureTransport=true
```

The test we ran was:

```cmd
python -c "import json; from scanner.iam_scanner import analyze_condition_context; p=json.load(open('day12-secure-transport.json')); print(analyze_condition_context(p['Statement'][0].get('Condition')))"
```

Output:

```text
['SecureTransport=true']
```

So the helper successfully detected the SecureTransport condition.

---

# 8. Source IP condition

Another condition we handle is:

```text
aws:SourceIp
```

Example:

```json
"Condition": {
    "IpAddress": {
        "aws:SourceIp": [
            "203.0.113.0/24"
        ]
    }
}
```

This condition contains an IP range.

Our helper converts it into:

```text
SourceIp=['203.0.113.0/24']
```

We tested it using:

```cmd
python -c "import json; from scanner.iam_scanner import analyze_condition_context; p=json.load(open('day12-source-ip.json')); print(analyze_condition_context(p['Statement'][0].get('Condition')))"
```

Output:

```text
["SourceIp=['203.0.113.0/24']"]
```

So CloudSentinel is able to recognize the source IP condition.

---

# 9. PrincipalTag condition

We also added support for condition keys beginning with:

```text
aws:PrincipalTag/
```

Example:

```json
"Condition": {
    "StringEquals": {
        "aws:PrincipalTag/Environment": "Production"
    }
}
```

The helper identifies this as a principal tag condition.

The output was:

```text
PrincipalTag condition: aws:PrincipalTag/Environment=Production
```

We tested it using:

```cmd
python -c "import json; from scanner.iam_scanner import analyze_condition_context; p=json.load(open('day12-principal-tag.json')); print(analyze_condition_context(p['Statement'][0].get('Condition')))"
```

Output:

```text
['PrincipalTag condition: aws:PrincipalTag/Environment=Production']
```

---

# 10. What happens when there is no Condition?

We also tested a policy that doesn't have a `Condition`.

Example:

```json
{
    "Effect": "Allow",
    "Action": "s3:GetObject",
    "Resource": "*"
}
```

There is no:

```json
"Condition": {}
```

at all.

The helper receives:

```python
None
```

and returns:

```text
[]
```

We tested:

```cmd
python -c "import json; from scanner.iam_scanner import analyze_condition_context; p=json.load(open('day12-no-condition.json')); print(analyze_condition_context(p['Statement'][0].get('Condition')))"
```

Output:

```text
[]
```

This confirms that the helper handles policies without conditions correctly.

---

# 11. What are our four Day 12 test files?

We created four JSON files to test different situations.

### 1. `day12-no-condition.json`

Tests a policy without any condition.

```text
Expected output:
[]
```

### 2. `day12-secure-transport.json`

Tests:

```text
aws:SecureTransport
```

Expected:

```text
SecureTransport=true
```

### 3. `day12-source-ip.json`

Tests:

```text
aws:SourceIp
```

Expected:

```text
SourceIp=['203.0.113.0/24']
```

### 4. `day12-principal-tag.json`

Tests:

```text
aws:PrincipalTag/Environment
```

Expected:

```text
PrincipalTag condition: aws:PrincipalTag/Environment=Production
```

These files are basically our **test inputs** for the new condition-analysis functionality.

---

# 12. How does the JSON reach the helper?

The flow is:

```text
Day 12 JSON file
        ↓
Python loads JSON
        ↓
Statement is selected
        ↓
Condition is extracted
        ↓
analyze_condition_context()
        ↓
Condition information is returned
```

For example:

```python
p['Statement'][0].get('Condition')
```

means:

1. Get the JSON policy.
2. Get the first statement.
3. Look for its `Condition`.
4. If there is no condition, return `None`.

That value is then passed to:

```python
analyze_condition_context()
```

---

# 13. What changed inside `scan_iam()`?

Inside the IAM scanner, we now retrieve the condition:

```python
condition = statement.get(
    "Condition",
    {}
)
```

Then we call:

```python
condition_controls = analyze_condition_context(
    condition
)
```

This means the scanner now understands that a policy statement can contain condition information.

---

# 14. Is the condition changing the severity yet?

**No.**

This is important.

Day 12 is currently an **informational analysis step**.

The existing IAM security detection logic is still responsible for deciding:

```text
CRITICAL
HIGH
MEDIUM
LOW
```

The condition helper currently only extracts useful information.

We intentionally did not change the existing severity logic yet.

This avoids accidentally changing the results of the security checks that were already working.

So right now:

```text
Condition analysis
        ↓
understand the policy context
        ↓
do not change severity yet
```

---

# 15. Why didn't we immediately change severity?

Suppose a policy contains:

```text
Resource: *
```

There are many possible conditions.

A condition might make a permission more restricted, but we should not automatically assume that every condition makes a permission safe.

So before changing severity, CloudSentinel needs more careful logic about:

* Which condition is present
* Which action is being allowed
* Which resource is involved
* Whether the condition actually reduces the security risk
* Whether the condition is correctly configured

For Day 12, we are first building the **foundation** for this analysis.

---

# 16. What I learned from Day 12

Today I understood that IAM permissions are not only about:

```text
Action + Resource
```

There can also be:

```text
Condition
```

which provides additional context about when a permission can be used.

I also learned how to:

* Read the `Condition` field from an IAM policy
* Extract nested JSON values
* Create a helper function for reusable analysis
* Detect `aws:SecureTransport`
* Detect `aws:SourceIp`
* Detect `aws:PrincipalTag/...`
* Handle policies where the condition is missing
* Test Python functions using JSON files
* Keep new analysis separate from existing severity logic

---

# 17. Day 12 implementation flow

The overall CloudSentinel IAM flow is becoming:

```text
AWS IAM
   ↓
Retrieve policies
   ↓
Read policy statements
   ↓
Check Effect
   ↓
Analyze Actions
   ↓
Analyze Resources
   ↓
Analyze Conditions
   ↓
Detect security issues
   ↓
Generate Finding
   ↓
Display result
```

Day 12 added the **Analyze Conditions** part.

---

# 18. Files added/modified

### Modified

```text
scanner/iam_scanner.py
```

Added:

```text
analyze_condition_context()
```

and connected it to the IAM policy analysis.

### Added

```text
day12-no-condition.json
day12-secure-transport.json
day12-source-ip.json
day12-principal-tag.json
```

These are the test cases for the condition analysis.

---

# 19. Validation performed

We checked the Python file:

```cmd
python -m py_compile scanner/iam_scanner.py
```

No error was returned, so the file compiled successfully.

We also checked formatting:

```cmd
git diff --check
```

No output was returned, which means Git found no whitespace errors.

Then we ran:

```cmd
python main.py
```

CloudSentinel started successfully and continued detecting the existing IAM security issues.

The existing findings were still detected, which means the Day 12 changes did not break the previous IAM scanner functionality.

---

# 20. Git commit

Day 12 was committed with:

```text
feat: analyze IAM condition context
```

Commit:

```text
b2a2499
```

The branch was pushed using:

```cmd
git push origin day-12
```

So the Day 12 implementation is safely stored in GitHub.

---

# Final Day 12 Summary

The main goal of Day 12 was to make CloudSentinel understand **IAM condition context**.

Before Day 12:

```text
Action
Resource
```

were the main things being analyzed.

After Day 12:

```text
Action
Resource
Condition
```

are available to the scanner.

We added:

```python
analyze_condition_context()
```

to extract useful condition information such as:

```text
SecureTransport=true
SourceIp=['203.0.113.0/24']
PrincipalTag condition: aws:PrincipalTag/Environment=Production
```

The condition analysis is currently informational and does not change severity.

This gives us a foundation for making CloudSentinel's IAM security analysis more intelligent in later days.
