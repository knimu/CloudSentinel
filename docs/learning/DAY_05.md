# Day 05 — YAML & Configuration in CloudSentinel

## 1. What is YAML?

**YAML = YAML Ain't Markup Language**

YAML is a **human-readable data serialization format**. It is mainly used to store and exchange configuration/data.

It is similar to JSON and XML, but YAML is generally easier for humans to read and write.

Common extensions:

```text
.yaml
.yml
```

Example:

```yaml
project:
  name: CloudSentinel
  version: 1.0

scanning:
  enabled: true
  default_severity: HIGH

services:
  - S3
```

YAML stores **data, not program instructions/commands**.

---

## 2. Markup Language vs YAML

A **markup language** is mainly used to structure/describe documents.

Example:

```html
<h1>Hello</h1>
<p>This is a webpage.</p>
```

HTML is a markup language because it uses tags to structure content.

YAML is different. It represents **data/configuration**.

---

## 3. Serialization & Deserialization

### Serialization

Converting data/object into a format that can be stored or transmitted.

```text
Python Object/Data
       ↓
 Serialization
       ↓
 YAML / JSON / XML
```

### Deserialization

Converting the stored/transmitted data back into a usable program data structure.

```text
YAML / JSON / XML
       ↓
Deserialization
       ↓
Python Data/Object
```

In our project:

```text
config.yaml
     ↓
yaml.safe_load()
     ↓
Python dictionary
```

**Important:** We did NOT convert YAML directly into JSON.
PyYAML converted the YAML into a **Python dictionary**.

---

# 4. Basic YAML Syntax

### Key-value pairs

```yaml
name: Nimisha
age: 20
```

`name` → key
`Nimisha` → value

YAML is **case-sensitive**.

---

### Lists

Lists use `-`:

```yaml
services:
  - S3
  - IAM
  - EC2
```

Inline form is also possible:

```yaml
services: [S3, IAM, EC2]
```

---

### Nested data

Indentation is important:

```yaml
project:
  name: CloudSentinel
  version: 1.0
```

The indentation shows the relationship between the data.

---

### Comments

Use `#`:

```yaml
# Scanner configuration
enabled: true
```

---

### Different data types

```yaml
name: Nimisha
age: 20
marks: 96.22
active: true
```

Common types include:

* String
* Integer
* Float
* Boolean
* Null
* Lists
* Maps/dictionaries

---

### Multi-line strings

`|` preserves line breaks:

```yaml
bio: |
  I am learning DevOps.
  I am building CloudSentinel.
```

`>` folds multiple lines into one line:

```yaml
message: >
  This is written
  on multiple lines
```

---

## 5. Documents

`---` starts a new YAML document.

```yaml
---
name: Nimisha
---
name: Kunal
```

`...` can indicate the end of a document.

---

# 6. YAML vs JSON vs XML

### YAML

```yaml
student:
  name: Nimisha
  marks: 90
```

### JSON

```json
{
  "student": {
    "name": "Nimisha",
    "marks": 90
  }
}
```

### XML

```xml
<student>
  <name>Nimisha</name>
  <marks>90</marks>
</student>
```

All three can represent structured data, but YAML is particularly convenient for **configuration files**.

---

# 7. Advanced YAML Concepts

We learned that YAML can represent more complex structures too:

### Sequence

```yaml
student: !!seq
  - marks
  - name
  - roll
```

### Nested sequence

A sequence can contain other sequences.

### Map

Maps represent key-value relationships:

```yaml
person:
  name: Nimisha
  age: 20
```

### Pairs

`!!pairs` can represent multiple key-value pairs where duplicate keys may be allowed.

### Set

`!!set` represents unique values.

### Ordered map

`!!omap` can represent ordered mappings.

These are **advanced YAML features** and we don't currently need them in CloudSentinel.

---

# 8. YAML Anchors

Anchors allow us to **reuse existing YAML data** instead of writing the same thing repeatedly.

```yaml
likings: &base
  fav_fruit: mango
  dislikes: grapes

person:
  name: Nimisha
  <<: *base
```

`&base` creates an anchor.

`*base` references it.

`<<` merges the referenced properties.

We can also overwrite a reused value.

---

# 9. YAML Tools

We learned about tools that can help work with/validate YAML, such as:

* Lens
* Monokle
* Datree

The important concept is that YAML can be **validated** before being used by systems such as Kubernetes or DevOps tools.

---

# 10. PyYAML

To make Python work with YAML, we used **PyYAML**.

We added it to:

```text
requirements.txt
```

```text
PyYAML==6.0.3
```

PyYAML allows Python to parse YAML files.

---

# 11. Our `config.yaml`

We created:

```text
config/
├── config.yaml
└── config_loader.py
```

Our configuration contains:

```yaml
project:
  name: CloudSentinel
  version: 1.0

scanning:
  enabled: true
  default_severity: HIGH

services:
  - S3
```

---

# 12. Loading YAML in Python

We created `config_loader.py`:

```python
import yaml


def load_config():
    with open("config/config.yaml", "r") as file:
        return yaml.safe_load(file)
```

### What happens?

```text
config.yaml
     ↓
open()
     ↓
yaml.safe_load()
     ↓
Python dictionary
```

We tested it and got:

```python
{
    'project': {
        'name': 'CloudSentinel',
        'version': 1.0
    },
    'scanning': {
        'enabled': True,
        'default_severity': 'HIGH'
    },
    'services': ['S3']
}
```

---

# 13. Why `load_config()` uses `return`

We don't want the loader to print the configuration.

Instead:

```python
return yaml.safe_load(file)
```

returns the configuration to whoever calls the function.

For example:

```python
config = load_config()
```

Now `config` contains the Python dictionary.

---

# 14. Connecting YAML to CloudSentinel

Previously:

```text
main.py
   ↓
backend
   ↓
engine
   ↓
S3 scanner
   ↓
Finding
```

We changed it to:

```text
                    config.yaml
                        ↓
main.py → backend → engine → scanner
                        ↓
                     Finding
```

The engine now loads the configuration.

---

## 15. `scanning.enabled`

We added:

```python
if not config["scanning"]["enabled"]:
    return results
```

Therefore:

```yaml
enabled: true
```

→ scanning runs.

```yaml
enabled: false
```

→ scanning does not run.

This means **configuration can control application behavior without changing Python code**.

---

# 16. `services`

We then used:

```yaml
services:
  - S3
```

The engine checks:

```python
if "S3" in config["services"]:
    results.append(scan_s3(severity))
```

So:

```yaml
services:
  - S3
```

→ S3 scanner runs.

If S3 isn't listed:

```yaml
services:
  - IAM
```

→ S3 scanner doesn't run.

This gives us a foundation for adding:

```text
S3
IAM
EC2
RDS
...
```

later.

---

# 17. `default_severity`

Initially the scanner had a hardcoded value:

```python
severity = "HIGH"
```

We changed the design so the value comes from YAML:

```yaml
default_severity: HIGH
```

Engine:

```python
severity = config["scanning"]["default_severity"]
```

Then:

```python
scan_s3(severity)
```

So changing:

```yaml
default_severity: CRITICAL
```

produced:

```text
Severity: CRITICAL
```

without changing the scanner code.

---

# 18. Final Day 5 Flow

Our project now works like this:

```text
                    config.yaml
                        │
                        ▼
                  config_loader
                        │
                  Python dictionary
                        │
                        ▼
main.py → backend/app.py → scanner/engine.py
                              │
                    ┌─────────┴─────────┐
                    │                   │
             enabled?              services?
                    │                   │
                    └─────────┬─────────┘
                              ▼
                         scan_s3()
                              │
                              ▼
                           Finding
                              │
                              ▼
                            Output
```

### Main thing learned today

> **YAML is not just something to memorize. We use it to keep configuration separate from application logic.**

That is the important DevOps connection we built today.
