````markdown
# Day 6 — Configuration-Driven Scanner Architecture

## 1. Goal of Today

Today we made CloudSentinel more flexible by allowing the YAML configuration to control which scanners run.

Instead of hardcoding every scanner in the engine, the engine now reads the services from `config.yaml`.

---

## 2. YAML Controls the Scanning

Our `config.yaml` contains:

```yaml
scanning:
  enabled: true
  default_severity: CRITICAL

services:
  - S3
  - IAM
````

This means:

* `enabled` → decides whether scanning should run.
* `default_severity` → gives the scanners the default severity.
* `services` → tells CloudSentinel which services to scan.

So YAML is not just storing data anymore. It is controlling application behavior.

---

## 3. Configuration-Driven Scanning

In `engine.py`:

```python
for service in config["services"]:
```

The engine goes through every service mentioned in YAML.

For example:

```text
S3
IAM
```

Then it finds the correct scanner and executes it.

This means we can add or remove services from YAML without changing the scanning logic.

---

## 4. Scanner Registry

We created:

```text
scanner/registry.py
```

It contains:

```python
SCANNERS = {
    "S3": scan_s3,
    "IAM": scan_iam
}
```

The registry maps a service name to its scanner function.

```text
"S3"  → scan_s3
"IAM" → scan_iam
```

This avoids writing separate `if` statements for every service.

---

## 5. Functions Can Be Stored in a Dictionary

We wrote:

```python
"S3": scan_s3
```

not:

```python
"S3": scan_s3()
```

`scan_s3` refers to the function itself.

Later, the function is executed when we do:

```python
scanner(severity)
```

So the process is:

```text
"S3"
 ↓
find scan_s3
 ↓
scanner = scan_s3
 ↓
scanner(severity)
 ↓
scan_s3 runs
```

---

## 6. `get_scanner()`

We added:

```python
def get_scanner(service):
    return SCANNERS.get(service)
```

Now `engine.py` does not need to directly work with the dictionary.

It simply asks:

```python
scanner = get_scanner(service)
```

This keeps responsibilities separated.

---

## 7. Unsupported Services

We tested what happens if YAML contains:

```yaml
services:
  - S3
  - IAM
  - ABC
```

There is no scanner for `ABC`.

Instead of silently ignoring it, CloudSentinel creates a `Finding`:

```text
Service: ABC
Resource: N/A
Status: FAIL
Severity: HIGH
Message: No scanner available for this service
```

This is better because the user knows that a configured service was not scanned.

---

## 8. Common Finding Structure

All scanners return a `Finding`.

For example:

```text
S3  → Finding
IAM → Finding
ABC → Finding
```

This keeps the output consistent.

The backend can therefore process all findings in the same way.

---

## 9. Enabling and Disabling Scanning

We tested:

```yaml
scanning:
  enabled: false
```

When scanning is disabled, the engine returns an empty result:

```python
if not config["scanning"]["enabled"]:
    return results
```

Therefore no scanner runs.

Changing it back to:

```yaml
enabled: true
```

allows scanning again.

---

## 10. Separation of Responsibilities

Our project is becoming more organized:

```text
main.py
   ↓
backend/app.py
   ↓
scanner/engine.py
   ↓
config/config.yaml
   ↓
registry.py
   ↓
S3 / IAM scanners
   ↓
Finding
   ↓
backend output
```

Each file has a different responsibility:

* `main.py` → starts the application
* `app.py` → starts the backend and displays results
* `engine.py` → controls the scanning process
* `config_loader.py` → reads YAML
* `registry.py` → maps services to scanner functions
* `s3_scanner.py` → scans S3
* `iam_scanner.py` → scans IAM
* `models.py` → defines the Finding structure

---

## 11. What We Built Today

Today we:

* Added an IAM scanner.
* Created a scanner registry.
* Removed hardcoded service-specific logic from the engine.
* Added `get_scanner()`.
* Made YAML control which services are scanned.
* Added handling for unsupported services.
* Tested disabling scanning through YAML.
* Improved the readability of scanner output.
* Kept all scanner results in the same `Finding` format.

---

## 12. Main Concept to Remember

The important idea from today:

> **Configuration decides WHAT should run, the registry decides WHICH function runs, the scanner decides HOW the service is checked, and `Finding` defines the result.**

This makes CloudSentinel easier to extend when we add more cloud services later.

````

### One thing I want you to notice

Today's architecture is becoming much more professional:

```text
YAML
 ↓
Configuration
 ↓
Engine
 ↓
Registry
 ↓
Scanner
 ↓
Finding
````

