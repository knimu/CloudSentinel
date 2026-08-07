Day 3 Notes - CloudSentinel

Topic: Scanner Architecture & Data Flow

1. What did we build today?

Today we built the heart of CloudSentinel.

Instead of directly connecting to AWS, we built the architecture that will later communicate with AWS.

Current architecture:

User
 │
 ▼
main.py
 │
 ▼
backend
 │
 ▼
scanner engine
 │
 ▼
scanner modules

We focused on how different parts of the application communicate.

2. What is a Scanner?

A scanner is not an antivirus.

In CloudSentinel,

A scanner means:

A program that automatically checks whether AWS resources are secure.

Examples:

Is the S3 bucket public?
Is MFA enabled?
Is the Security Group open to the internet?
Is IAM following best practices?

Instead of checking manually, CloudSentinel performs these checks automatically.

3. Why separate the Scanner?

Imagine writing everything inside one file.

scan_s3()

scan_iam()

scan_ec2()

scan_lambda()

scan_vpc()

Initially it looks simple.

But after adding 20 AWS services, the file becomes thousands of lines long.

Instead we separate them.

scanner/
│
├── engine.py
├── s3_scanner.py
├── iam_scanner.py
├── ec2_scanner.py

Each file has only one responsibility.

This makes the project easier to understand and maintain.

4. What is engine.py?

Think of an orchestra.

There are:

🎻 Violin players

🥁 Drummers

🎸 Guitar players

Who coordinates everyone?

The conductor.

Similarly,

engine.py coordinates all scanners.

It says:

results.append(scan_s3())

results.append(scan_iam())

results.append(scan_ec2())

The engine does not perform the scan.

It only coordinates different scanners.

5. Why not write everything inside main.py?

Suppose main.py directly called:

scan_s3()

scan_iam()

scan_ec2()

scan_lambda()

Later,

adding new services would require modifying main.py repeatedly.

Instead,

main.py only says:

run_scan()

Everything else is hidden inside the scanner.

This is called abstraction.

6. What is Abstraction?

Abstraction means:

Use something without worrying about how it works internally.

Example:

results = run_scan()

Backend does not know:

how S3 scanning works
how IAM scanning works
how boto3 works

It simply receives the scan results.

7. Data Flow

Today's biggest concept.

User
 │
 ▼
python main.py
 │
 ▼
main()
 │
 ▼
start_backend()
 │
 ▼
run_scan()
 │
 ▼
scan_s3()
 │
 ▼
returns dictionary
 │
 ▼
engine collects result
 │
 ▼
backend receives result
 │
 ▼
display to user

Every function has one job.

8. return vs print

This is one of the most important Python concepts.

print()
print("Bucket is private")

Purpose:

Show information to the user.

After printing,

the value is gone.

Another function cannot use it.

return
return "Bucket is private"

Purpose:

Give data back to another function.

The returned value can now be

saved
modified
sent to AWS
stored in database
displayed on UI
Easy way to remember

print() is for humans.

return is for programs.

9. Why create a results list?

Instead of

return scan_s3()

we created

results = []

results.append(scan_s3())

return results

Why?

Because tomorrow we will have

scan_s3()

scan_iam()

scan_ec2()

scan_vpc()

scan_lambda()

A list allows us to collect every scanner's output.

It is designed for future expansion.

10. What is a Dictionary?

Today's scanner returned

{
    "service": "S3",
    "resource": "demo-bucket",
    "status": "PASS"
}

This is a dictionary.

Think of it as

Label  →  Value

service → S3

status → PASS

Unlike a list,

every value has a meaningful name.

11. What is a List?

A list stores multiple objects.

Example

[
    {"service": "S3"},

    {"service": "IAM"},

    {"service": "EC2"}
]

So today

our engine returned

a list of dictionaries.

This is one of the most common data structures in APIs.

12. Software Engineering Principle

Today's biggest lesson.

One file = One responsibility

Examples

main.py

Starts application
backend

Handles backend logic
engine.py

Coordinates scanners
s3_scanner.py

Scans S3 only

This principle makes projects easier to maintain.

13. Commands Used Today
git status

git add .

git commit -m "Initialize CloudSentinel project structure"

git push -u origin main
14. Mistakes I Made Today

✅ I accidentally initialized Git on Desktop.

Solution:

Initialize Git only inside the project.

Useful command:

git rev-parse --show-toplevel

It tells us the root of the repository.

15. Things I Learned Today
A scanner is a security auditing tool.
Engine coordinates scanners.
return sends data to another function.
print() only displays data.
A dictionary stores labeled information.
A list stores multiple objects.
Software projects are divided according to responsibility.
Git should always be initialized in the project folder.
⭐ Memory Trick

Imagine CloudSentinel as a company.

CEO

↓

main.py
Manager

↓

backend
Project Manager

↓

engine.py
Employees

↓

s3_scanner.py

iam_scanner.py

ec2_scanner.py

Every person has one responsibility.

No one tries to do someone else's job.

⭐ Today's Interview Question

Q: Why do we use return instead of print in backend applications?

Answer:

Because backend functions need to pass data to other functions, APIs, or databases. print() only displays information on the screen, whereas return allows the program to use that data further.

⭐ Homework Thought

Today you naturally started thinking about system design instead of just code. When you suggested Option C, you weren't asking "How do I write this?"—you were asking "What information would be useful to the user?" That's exactly the kind of thinking we'll keep developing as we build CloudSentinel.