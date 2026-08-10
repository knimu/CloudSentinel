import yaml


def load_config():
    with open("config/config.yaml", "r") as file:
        return yaml.safe_load(file)

# Instead of:

# python

# use:

# .venv\Scripts\python.exe

# And instead of:

# pip

# use:

# .venv\Scripts\python.exe -m pip

# This guarantees we're using the correct environment.
