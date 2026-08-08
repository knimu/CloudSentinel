# Day 4 — Findings Model & Scanner Pipeline

## What We Built

Today we built the first complete working pipeline of CloudSentinel.

The flow is:

```text
main.py
   ↓
backend/app.py
   ↓
scanner/engine.py
   ↓
scanner/s3_scanner.py
   ↓
scanner/models.py
   ↓
Finding
   ↓
Back to engine
   ↓
Backend displays the result
```

---

## 1. `main.py`

`main.py` is the starting point of the application.

It starts CloudSentinel and calls the backend.

```text
main.py
   ↓
start_backend()
```

---

## 2. `backend/app.py`

The backend receives the scan results from the engine.

It calls:

```python
run_all_scans()
```

and then displays the findings.

The backend does **not** perform the actual S3 security check.

Its responsibility is to handle the application flow and present the results.

---

## 3. `scanner/engine.py`

The engine coordinates the different scanners.

Currently we have only the S3 scanner.

Example:

```python
results = []

results.append(scan_s3())

return results
```

### Why use a list?

Because later we will have multiple scanners:

```text
S3 Scanner
IAM Scanner
EC2 Scanner
...
```

The engine can collect all their findings into one list.

For example:

```python
results = [
    s3_finding,
    iam_finding,
    ec2_finding
]
```

The engine's responsibility is to **coordinate the scanners and collect their results**.

---

## 4. `scanner/s3_scanner.py`

This is where the S3 security check is performed.

The S3 scanner is responsible for checking the S3 resource and creating a `Finding` object containing the result.

Example finding:

```text
Service: S3
Resource: demo-bucket
Status: FAIL
Severity: HIGH
Message: Bucket is publicly accessible
Recommendation: Disable public access
```

The scanner is responsible for the **actual security check**.

---

# 5. `scanner/models.py`

This is where we created the `Finding` model.

The model gives every finding a common structure:

```text
service
resource
status
severity
message
recommendation
```

This is useful because S3, IAM, EC2 and other scanners should return findings in the same format.

Instead of every scanner creating its own different structure, they can all use the same `Finding` model.

---

## `Finding` Class

A class can be used as a blueprint for creating `Finding` objects.

Example:

```python
class Finding:

    def __init__(self, service, resource, status, severity, message, recommendation):
        self.service = service
        self.resource = resource
        self.status = status
        self.severity = severity
        self.message = message
        self.recommendation = recommendation
```

---

## `__init__`

`__init__` runs when a new object is created.

We use it to initialize and store the object's data.

```python
def __init__(self, service, resource, status, severity, message, recommendation):
    self.service = service
    self.resource = resource
    self.status = status
    self.severity = severity
    self.message = message
    self.recommendation = recommendation
```

### What is `self`?

`self` refers to the **current object**.

For example:

```python
self.service = service
```

means:

> Store the `service` value inside this particular `Finding` object.

If we create:

```python
finding = Finding(
    "S3",
    "demo-bucket",
    "FAIL",
    "HIGH",
    "Bucket is publicly accessible",
    "Disable public access"
)
```

then the object contains:

```text
finding.service          → S3
finding.resource         → demo-bucket
finding.status           → FAIL
finding.severity         → HIGH
finding.message          → Bucket is publicly accessible
finding.recommendation   → Disable public access
```

### Simple way to remember

```text
__init__ → sets up the object and stores its data
```

---

# 6. `__str__`

`__str__` controls how our object is represented as human-readable text when we print it.

Example:

```python
def __str__(self):
    return f"{self.service} | {self.resource} | {self.status} | {self.severity}"
```

Then:

```python
print(finding)
```

produces:

```text
S3 | demo-bucket | FAIL | HIGH
```

We can also include more information:

```python
def __str__(self):
    return (
        f"Service: {self.service}\n"
        f"Resource: {self.resource}\n"
        f"Status: {self.status}\n"
        f"Severity: {self.severity}\n"
        f"Message: {self.message}\n"
        f"Recommendation: {self.recommendation}"
    )
```

This produces:

```text
Service: S3
Resource: demo-bucket
Status: FAIL
Severity: HIGH
Message: Bucket is publicly accessible
Recommendation: Disable public access
```

### What does `\n` mean?

`\n` means **new line**.

For example:

```python
"Hello\nWorld"
```

produces:

```text
Hello
World
```

### Simple way to remember

```text
__str__ → controls the readable text representation of an object
```

---

# 7. `__init__` vs `__str__`

| Method     | Purpose                                          |
| ---------- | ------------------------------------------------ |
| `__init__` | Initializes and stores object data               |
| `__str__`  | Defines the human-readable string representation |

Think of it as:

```text
__init__
   ↓
Build / initialize the object

__str__
   ↓
Represent the object as readable text
```

---

# 8. Scanner vs Finding

One important concept from today:

```text
Scanner
   ↓
Performs the security check
```

while:

```text
Finding
   ↓
Stores the result of the security check
```

For example:

```python
def scan_s3():
    finding = Finding(
        "S3",
        "demo-bucket",
        "FAIL",
        "HIGH",
        "Bucket is publicly accessible",
        "Disable public access"
    )

    return finding
```

The scanner performs the check and returns a structured `Finding`.

---

# 9. Why Structured Data?

We could simply print:

```text
Bucket is publicly accessible!
```

But that would make the result difficult for other parts of the application to use.

Instead, we return structured data:

```text
Service
Resource
Status
Severity
Message
Recommendation
```

This allows CloudSentinel to later:

* display findings
* count failures
* filter by severity
* generate reports
* export JSON
* store findings
* test scanner results

---

# Today's Main Learning

We separated responsibilities between files.

```text
main.py
→ starts the application

app.py
→ handles the backend/application flow

engine.py
→ coordinates scanners

s3_scanner.py
→ performs the S3 security check

models.py
→ defines the common Finding structure
```

This separation will become increasingly important when we add more scanners.

---

# Day 4 Learning Targets

Today I learned:

### 1. What is a security finding?

A finding is the structured result of a security check.

It tells us:

```text
What was checked?
What was the result?
How serious is it?
What should be done?
```

---

### 2. Why do we need severity?

Not every security problem has the same impact.

CloudSentinel currently uses:

```text
LOW
MEDIUM
HIGH
CRITICAL
```

Severity helps users prioritize security issues.

---

### 3. Why should scanners use the same format?

If every scanner returns a different structure, the engine becomes difficult to work with.

Using a common `Finding` model means:

```text
S3 → Finding
IAM → Finding
EC2 → Finding
```

All scanners produce a consistent result.

---

### 4. Why does `models.py` exist?

`models.py` defines the structure of the data used by the application.

In our case:

```text
models.py
   ↓
Finding
```

The `Finding` model provides a common structure for security findings.

---

### 5. Scanner vs Scanner Engine

The **scanner** performs a specific security check.

Example:

```text
S3 scanner
→ checks S3
```

The **engine** coordinates the scanners.

Example:

```text
Engine
├── S3 scanner
├── IAM scanner
├── EC2 scanner
└── ...
```

---

### 6. Why return structured data instead of printing?

Returning structured data allows other parts of the application to use the result.

For example:

```text
Scanner
   ↓
Finding
   ↓
Engine
   ↓
Backend
   ↓
CLI / Report / JSON / Dashboard
```

If the scanner only printed text, other parts of the application would have much less control over the result.

---

# Important Python Concepts Learned

```text
class
   ↓
Blueprint for creating objects

object
   ↓
An instance created from a class

__init__
   ↓
Initializes the object's data

self
   ↓
Refers to the current object

__str__
   ↓
Defines the object's human-readable string representation

return
   ↓
Sends a value back to the caller
```

---

# What I Understood Today

I understood how the different parts of CloudSentinel communicate with each other.

I learned how Python classes can be used to create a common structure for data.

I understood the difference between:

```text
__init__ → sets up/stores object data

__str__ → controls how the object is represented as readable text
```

I also learned the difference between a scanner and a finding:

```text
Scanner → performs the security check

Finding → stores the result
```

I realized that my Python fundamentals still need improvement.

I will improve Python alongside the project instead of stopping the project until I become perfect at Python.

---

# Project Principle

> We are not adding AWS/boto3 just because CloudSentinel is a cloud security project.

First, we build and understand the application architecture.

Then we can replace the dummy S3 check with a real AWS check using `boto3`.

This way, when we eventually use `boto3`, I will understand exactly **where it belongs and why**.

---

# Day 4 Summary

The CloudSentinel pipeline is now becoming more structured:

```text
User
 ↓
main.py
 ↓
Backend
 ↓
Scanner Engine
 ↓
S3 Scanner
 ↓
Finding Model
 ↓
Structured Security Finding
 ↓
Back to Engine
 ↓
Backend
 ↓
Display Result
```

The key idea from Day 4:

> **The scanner performs the check, the Finding describes the result, and the engine coordinates the scanners.**

also 

# Day 4 — Findings Model & Scanner Pipeline

## What I worked on today

Today I learned how to make the CloudSentinel results more structured.

Yesterday, the S3 scanner was returning something very simple like:

```python
{
    "service": "S3",
    "resource": "demo-bucket",
    "status": "PASS"
}
```

Today I learned that a security scanner needs to give us more information.

A finding should tell us:

```text
Service
Resource
Status
Severity
Message
Recommendation
```

For example:

```text
Service: S3
Resource: demo-bucket
Status: FAIL
Severity: HIGH
Message: Bucket is publicly accessible
Recommendation: Disable public access
```

---

# 1. Understanding the project flow

I understood the basic flow of my application today.

```text
main.py
   ↓
backend/app.py
   ↓
scanner/engine.py
   ↓
scanner/s3_scanner.py
   ↓
Finding
   ↓
Back to engine
   ↓
Backend displays the result
```

I was initially confused about which file should do what.

Now I understand it like this:

```text
main.py
→ starts the application

app.py
→ calls the scanner engine and gets the results

engine.py
→ calls the different scanners and collects their results

s3_scanner.py
→ performs the S3 security check

models.py
→ defines what a Finding should look like
```

---

# 2. Why do we need a Finding?

At first I thought I could just keep adding more fields directly inside `s3_scanner.py`.

For example:

```python
return {
    "service": "S3",
    "resource": "demo-bucket",
    "status": "FAIL",
    "severity": "HIGH"
}
```

But then I realized that if I add IAM, EC2, etc., every scanner could start creating its own different format.

That would become messy.

So we created a common `Finding` structure.

The idea is:

```text
S3 Scanner → Finding
IAM Scanner → Finding
EC2 Scanner → Finding
```

All scanners can use the same structure.

---

# 3. My first class — `Finding`

I learned that a Python class can act like a blueprint.

We created:

```python
class Finding:

    def __init__(self, service, resource, status, severity, message, recommendation):
        self.service = service
        self.resource = resource
        self.status = status
        self.severity = severity
        self.message = message
        self.recommendation = recommendation
```

At first I was confused about why we needed a class instead of just using a dictionary.

I am still learning the difference, but I understand that the class gives us a common structure that we can create objects from.

---

# 4. What is `self`?

This was one of the things I was confused about today.

I learned that `self` refers to the **current object**.

For example:

```python
self.service = service
```

basically means:

```text
this object's service = the service value passed to it
```

If I create:

```python
finding = Finding(
    "S3",
    "demo-bucket",
    "FAIL",
    "HIGH",
    "Bucket is publicly accessible",
    "Disable public access"
)
```

then the object stores:

```text
finding.service
finding.resource
finding.status
finding.severity
finding.message
finding.recommendation
```

I don't think I fully understand classes yet, but I now understand the basic purpose of `self`.

---

# 5. Understanding `__init__`

I learned that `__init__` runs when we create an object.

For example:

```python
finding = Finding(...)
```

causes the `__init__` method to run.

It is used to initialize the object's data.

So the simple way I remember it is:

```text
__init__
↓
sets up the object
```

---

# 6. Understanding `__str__`

This was another thing I didn't understand at first.

I thought that after creating the `Finding` class, Python would automatically know how to display it.

But when we print a custom object, Python doesn't automatically give us a useful representation.

So we can define:

```python
def __str__(self):
    return f"{self.service} | {self.resource} | {self.status} | {self.severity}"
```

Then:

```python
print(finding)
```

can give:

```text
S3 | demo-bucket | FAIL | HIGH
```

I learned that:

```text
__init__
→ sets up the object's data

__str__
→ controls how the object is represented as text
```

---

# 7. Why use `return` instead of `print`?

This was also important.

Inside `__str__`, we use:

```python
return
```

instead of:

```python
print()
```

because `__str__` is supposed to **return a string**.

For example:

```python
def __str__(self):
    return f"{self.service} | {self.resource}"
```

Then Python can use that string when we do:

```python
print(finding)
```

So I learned:

```text
return → sends a value back

print → displays something on the screen
```

---

# 8. Scanner vs Finding

This was probably the most important concept for me today.

I was initially thinking that I needed a function for every finding.

But I learned that this isn't how we should think about it.

```text
Scanner
↓
does the security check

Finding
↓
stores the result of that check
```

For example:

```python
def scan_s3():
    finding = Finding(
        "S3",
        "demo-bucket",
        "FAIL",
        "HIGH",
        "Bucket is publicly accessible",
        "Disable public access"
    )

    return finding
```

The function performs the check and returns a Finding.

We don't need:

```text
finding_1()
finding_2()
finding_3()
```

for every finding.

---

# 9. Why does the engine use a list?

Right now CloudSentinel only has one scanner:

```text
S3
```

But later we might have:

```text
S3
IAM
EC2
VPC
RDS
```

So the engine can collect all the results in a list.

For example:

```python
results = []

results.append(scan_s3())

return results
```

Later it could become something like:

```python
results = []

results.append(scan_s3())
results.append(scan_iam())
results.append(scan_ec2())

return results
```

So the engine's job is basically to **run the scanners and collect their results**.

---

# 10. Why return structured data?

We could just do:

```python
print("Bucket is publicly accessible")
```

But then the rest of the application can't easily work with that information.

Instead, we return a `Finding`.

That means other parts of CloudSentinel can later:

```text
display it
filter it
count it
save it
create reports
export it
test it
```

This is why structured data is useful.

---

# What I learned today

Today I learned:

* What a security finding is
* Why severity is important
* Why scanners should use a common result structure
* Why we created `models.py`
* What a Python class is
* What `self` means
* What `__init__` does
* What `__str__` does
* The difference between `return` and `print`
* The difference between a scanner and a finding
* Why the engine collects scanner results in a list

---

# Things I am still learning

I realized that my Python fundamentals are not very strong yet, especially classes and objects.

I got confused about:

```text
self
__init__
__str__
objects
classes
```

But instead of stopping the CloudSentinel project until I become good at Python, I want to learn Python while building the project.

I think this will help me understand **why** these Python concepts are useful instead of just learning the syntax.

---

# Day 4 Takeaway

The main thing I understood today is:

```text
Scanner
↓
performs the security check

Finding
↓
stores the result

Engine
↓
runs scanners and collects findings

Backend
↓
receives the results and displays them
```

And eventually:

```text
CloudSentinel
↓
S3 Scanner
IAM Scanner
EC2 Scanner
etc.
↓
Common Finding Model
↓
Engine
↓
Results
```

For now, I am keeping the architecture simple and focusing on understanding the Python and project structure before adding real AWS functionality with `boto3`.
