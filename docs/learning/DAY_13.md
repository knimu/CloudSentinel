# Day 13 — IAM Explicit Deny Handling

## 1. What did we work on today?

Today I worked on an important IAM concept called **Explicit Deny**.

Until Day 12, CloudSentinel mainly analyzed `Allow` statements and looked for dangerous permissions such as:

* `s3:*`
* broad wildcard resources
* dangerous IAM actions
* missing or useful IAM conditions

Today I added support for recognizing IAM statements where:

```text
Effect = Deny
```

The main purpose is to make sure CloudSentinel understands that an explicit Deny is normally a **security control**, not a security vulnerability.

---

# 2. What is IAM Explicit Deny?

An IAM policy statement can have an `Effect`.

The two important values are:

```text
Allow
Deny
```

For example:

```json
{
    "Effect": "Deny",
    "Action": "s3:DeleteObject",
    "Resource": "*"
}
```

This means the specified action is explicitly denied.

In simple words:

> The user or role is not allowed to perform that action, even if another policy gives permission for it.

---

# 3. Allow vs Deny

### Allow

An Allow statement gives permission.

Example:

```json
{
    "Effect": "Allow",
    "Action": "s3:*",
    "Resource": "*"
}
```

This gives very broad S3 permissions.

CloudSentinel can consider this a security issue because the permission is too broad.

---

### Deny

A Deny statement removes permission.

Example:

```json
{
    "Effect": "Deny",
    "Action": "s3:DeleteObject",
    "Resource": "*"
}
```

This prevents the specified action.

This is generally a security control because it restricts what the identity can do.

---

# 4. Important IAM Rule — Explicit Deny Overrides Allow

This is the most important concept from Day 13.

Suppose we have:

```json
{
    "Effect": "Allow",
    "Action": "s3:*",
    "Resource": "*"
}
```

and another statement:

```json
{
    "Effect": "Deny",
    "Action": "s3:DeleteObject",
    "Resource": "*"
}
```

The final result for:

```text
s3:DeleteObject
```

is:

```text
DENIED
```

The Deny takes priority over the Allow.

So:

```text
Allow + Deny
    ↓
Deny wins
```

This is why CloudSentinel should not treat every `Deny` statement as a vulnerability.

---

# 5. Why did we need to change CloudSentinel?

Before Day 13, the scanner basically did this:

```python
if statement.get("Effect") != "Allow":
    continue
```

This means:

```text
Allow → analyze
Deny  → ignore
```

Ignoring Deny completely isn't ideal because CloudSentinel should understand what is inside the policy.

So we added logic to identify explicit Deny statements separately.

---

# 6. New Helper — analyze_explicit_deny()

We added:

```python
def analyze_explicit_deny(statement):
```

This helper is responsible for checking whether a policy statement is an explicit Deny.

It does not create a security finding.

Its job is to understand and extract useful information from the Deny statement.

---

# 7. How analyze_explicit_deny() works

First it checks whether the input is actually a dictionary:

```python
if not isinstance(statement, dict):
    return None
```

Then it reads the Effect:

```python
effect = statement.get("Effect")
```

If the Effect is not Deny:

```python
if effect != "Deny":
    return None
```

So an Allow statement returns:

```text
None
```

---

# 8. Extracting Action and Resource

If the statement is a Deny, we extract:

```python
actions = statement.get("Action", [])
resources = statement.get("Resource", [])
```

For example:

```json
{
    "Effect": "Deny",
    "Action": "s3:DeleteObject",
    "Resource": "*"
}
```

becomes:

```python
{
    "actions": ["s3:DeleteObject"],
    "resources": ["*"]
}
```

---

# 9. Why do we convert strings into lists?

IAM policies can contain either a single string or multiple values.

For example:

```json
"Action": "s3:DeleteObject"
```

or:

```json
"Action": [
    "s3:DeleteObject",
    "s3:DeleteBucket"
]
```

Our scanner wants to work with a consistent structure.

So if Action is a string:

```python
if isinstance(actions, str):
    actions = [actions]
```

The same thing is done for Resource.

This means both forms can be handled consistently.

---

# 10. Return value of the helper

For an explicit Deny, the helper returns:

```python
return {
    "actions": actions,
    "resources": resources,
}
```

For example:

```text
{
    'actions': ['s3:DeleteObject'],
    'resources': ['*']
}
```

This gives the scanner useful information about what was denied.

---

# 11. Day 13 Test File — Explicit Deny

We created:

```text
day13-explicit-deny.json
```

It contains:

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Deny",
            "Action": "s3:DeleteObject",
            "Resource": "*"
        }
    ]
}
```

This represents a policy that explicitly prevents deleting S3 objects.

---

# 12. Testing Explicit Deny

We tested it using:

```cmd
python -c "import json; from scanner.iam_scanner import analyze_explicit_deny; p=json.load(open('day13-explicit-deny.json')); print(analyze_explicit_deny(p['Statement'][0]))"
```

The result was:

```text
{'actions': ['s3:DeleteObject'], 'resources': ['*']}
```

This confirmed that our helper correctly detected the Deny statement.

---

# 13. Second Test — Allow + Deny

We also created:

```text
day13-allow-and-deny.json
```

It contains two statements:

```json
{
    "Effect": "Allow",
    "Action": "s3:*",
    "Resource": "*"
}
```

and:

```json
{
    "Effect": "Deny",
    "Action": "s3:DeleteObject",
    "Resource": "*"
}
```

This was useful because it represents a realistic situation where a broad permission exists but a specific dangerous action is explicitly denied.

---

# 14. Testing Allow + Deny

We ran:

```cmd
python -c "import json; from scanner.iam_scanner import analyze_explicit_deny; p=json.load(open('day13-allow-and-deny.json')); print(analyze_explicit_deny(p['Statement'][0])); print(analyze_explicit_deny(p['Statement'][1]))"
```

The result was:

```text
None
{'actions': ['s3:DeleteObject'], 'resources': ['*']}
```

This is exactly what we wanted.

The first statement is Allow, so:

```text
None
```

The second statement is Deny, so:

```text
{'actions': ['s3:DeleteObject'], 'resources': ['*']}
```

---

# 15. How did we integrate it into the scanner?

Inside `scan_iam()`, we now first check the statement's Effect:

```python
effect = statement.get("Effect")
```

Then:

```python
if effect == "Deny":
    deny_context = analyze_explicit_deny(statement)

    # Explicit Deny is a security control.
    # It is intentionally not reported as a vulnerability.
    _ = deny_context

    continue
```

After that:

```python
if effect != "Allow":
    continue
```

This keeps the existing Allow analysis working.

---

# 16. Why do we use continue?

When CloudSentinel sees:

```text
Effect = Deny
```

we understand the statement and then move to the next statement.

We don't want the Deny statement to continue into the existing Allow vulnerability checks.

Otherwise the scanner could incorrectly report a Deny as something dangerous.

So the flow is:

```text
Deny
 ↓
Analyze Deny
 ↓
Do not report as vulnerability
 ↓
continue
```

---

# 17. What happens with Allow statements?

Allow statements continue through the existing scanner logic.

For example:

```json
{
    "Effect": "Allow",
    "Action": "s3:*",
    "Resource": "*"
}
```

still gets detected as a HIGH security issue.

So Day 13 did not remove our existing security checks.

It added another layer of IAM understanding.

---

# 18. Testing the complete application

After making the changes, we ran:

```cmd
python -m py_compile scanner/iam_scanner.py
```

There was no output, which means the Python file compiled successfully.

We also ran:

```cmd
git diff --check
```

There was no output, so there were no whitespace or formatting errors detected by Git.

Then we ran:

```cmd
python main.py
```

The application started normally.

---

# 19. Important result from main.py

CloudSentinel still detected the existing IAM problems:

```text
3 HIGH findings
2 MEDIUM findings
```

The important part was that the Explicit Deny did **not** appear as a new vulnerability.

That means the new logic did not break the existing scanner.

---

# 20. What exactly changed in CloudSentinel?

Before Day 13:

```text
IAM Statement
      ↓
Is it Allow?
      ↓
Analyze it
```

Day 13:

```text
IAM Statement
      ↓
Check Effect
   /       \
 Deny      Allow
  ↓          ↓
Analyze    Existing
Deny       scanner logic
  ↓
Do not report
as vulnerability
```

This makes the IAM scanner more aware of how permissions actually work.

---

# 21. Security Understanding

The important lesson is that we cannot judge an IAM policy only by looking at individual Allow statements.

We also need to understand:

* Allow statements
* Explicit Deny statements
* Conditions
* Resources
* Actions
* How different statements interact

For example:

```text
Allow: s3:*
Deny:  s3:DeleteObject
```

should not simply be interpreted as:

```text
Everything is allowed
```

The Deny changes the effective permission for `s3:DeleteObject`.

---

# 22. What I learned today

Today I understood:

1. IAM policies can contain Allow and Deny statements.
2. Explicit Deny has priority over Allow.
3. A Deny is normally a security control.
4. CloudSentinel should not report every Deny as a vulnerability.
5. We can use a helper function to analyze Deny statements separately.
6. IAM Action and Resource can be represented as either strings or lists.
7. The scanner should normalize these values before processing them.
8. Existing Allow-based security checks should continue working.
9. Testing individual JSON policy files helps verify scanner functions.
10. Testing `main.py` confirms that the change did not break the complete application.

---

# 23. Day 13 Files

Files added today:

```text
day13-explicit-deny.json
day13-allow-and-deny.json
```

File modified:

```text
scanner/iam_scanner.py
```

Main function added:

```text
analyze_explicit_deny()
```

---

# 24. Git Commit

The implementation was committed with:

```text
feat: handle explicit IAM deny statements
```

Commit:

```text
be8f460
```

The Day 13 branch was also pushed to GitHub.

---

# 25. Day 13 Summary

Today I added support for **IAM Explicit Deny handling** in CloudSentinel.

The scanner can now recognize Deny statements, extract their Actions and Resources, and avoid incorrectly reporting them as security vulnerabilities.

The main concept to remember is:

```text
Explicit Deny overrides Allow.
```

So when analyzing IAM permissions, we need to understand the complete policy instead of looking at Allow permissions alone.

This is another step toward making CloudSentinel's IAM analysis more realistic and security-aware.
