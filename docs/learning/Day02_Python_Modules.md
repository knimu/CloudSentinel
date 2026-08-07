Day 2 Notes – CloudSentinel
1. What is main.py?

Think of it as the starting point of the application.

When we run:

python main.py

Python starts executing from this file.

2. Why create a main() function?

Instead of writing:

print("Starting")

we write:

def main():
    print("Starting")

A function is like a set of instructions.

Writing the instructions doesn't execute them.

They run only when called:

main()

This keeps the code organized and lets us control when the application starts.

3. What does this mean?
if __name__ == "__main__":
    main()

This tells Python:

If this file is being run directly, start the application.

If another file imports main.py, the application won't start automatically.

This prevents accidental execution.

4. What is __init__.py?

This is not the same as:

def __init__(self):

inside a class.

__init__.py is simply a file that tells Python:

"Treat this folder as a Python package."

That allows imports like:

from backend.app import start_backend

5. What is a package?

Normal folder:

backend/

Python package:

backend/
    __init__.py
    app.py

A package is just a folder containing Python modules that can be imported.

6. What is a module?

Every Python file is a module.

Example:

app.py

is a module.

So:

from backend.app import start_backend

means:

From the backend package, import the start_backend function from the app module.

7. What is Git telling me?

When I ran:

git status

Git showed:

Untracked files

Meaning:

Git can see these files, but it isn't tracking them yet.

After:

git add .

they become tracked (staged for the next commit).

After:

git commit

their current state is saved in Git history.

8. Biggest mistake I made today 😅

I accidentally initialized Git on my Desktop instead of inside the project.

Because of that:

git status

showed every folder on my Desktop.

We fixed it by:

Removing the wrong .git
Running git init inside CloudSentinel1

Lesson:

Always check where Git is initialized.

Useful command:

git rev-parse --show-toplevel

This shows the root of the Git repository.

9. Project structure
CloudSentinel1
│
├── backend/
│   ├── __init__.py
│   └── app.py
│
├── scanner/
├── docs/
├── infrastructure/
├── tests/
│
├── main.py
├── README.md
└── requirements.txt

Each folder has one responsibility.

10. Today's takeaway

Functions organize work. Packages organize code. Git organizes history.

Inside backend I see:

__pycache__/

Do you know what that is?

When Python runs your code, it automatically creates compiled bytecode files (.pyc) inside __pycache__ so that future runs are a little faster.

These files are generated automatically.

Just like .venv, we do not commit them.
