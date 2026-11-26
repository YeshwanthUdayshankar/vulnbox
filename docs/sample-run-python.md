# Sample Run 1: Python Repository (`tests/fixtures/py_sample_app`)

End-to-end hardened Docker sandbox capture (`vulnbox-sandbox:latest` with `--network=none`, `--cap-drop=ALL`, `--read-only`, `--security-opt=no-new-privileges:true`, non-root user) against [`tests/fixtures/py_sample_app`](../tests/fixtures/py_sample_app).

## Command & Captured CLI Output

```bash
$ .venv/bin/vulnbox doctor
                    VulnBox v0.1.0 Environment Check
┏━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Component              ┃ Status ┃ Details                            ┃
┡━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│ Python                 │ OK     │ 3.12.16                            │
│ Node.js                │ OK     │ /usr/bin/node                      │
│ curl                   │ OK     │ /usr/bin/curl                      │
│ Docker Sandbox         │ READY  │ Docker daemon reachable            │
│ Local Isolated Sandbox │ READY  │ Stripped env + rlimits + temp copy │
└────────────────────────┴────────┴────────────────────────────────────┘

$ .venv/bin/vulnbox remediate tests/fixtures/py_sample_app --backend docker --out /tmp/vulnbox-docker-py
Remediation bundle complete: 8 findings, 7/7 verified patches, 2 actively confirmed & fixed via live curl probe.
Report:  /tmp/vulnbox-docker-py/report.md
SARIF:   /tmp/vulnbox-docker-py/findings.sarif.json
Patches: /tmp/vulnbox-docker-py/patches
```

## Executive Summary & Findings Overview

- **Sandbox Backend:** `docker` (`vulnbox-sandbox:latest`, `--network=none`)
- **Pre-Sandbox Secret Scrubbing:** `1` file scrubbed (`.env`), `2` secrets redacted (`DATABASE_URL`, `API_TOKEN`) — original `.env` untouched.
- **Total Findings:** `8` | **Dual-Verified Patches:** `7 / 7` | **Actively Confirmed & Fixed via `curl`:** `2`

| Finding ID | Rule | CWE | Severity | Location | Reachability | Active `curl` Probe | Patch Status |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| `PY-YAML-001-e119e444` | `PY-YAML-001` | `CWE-502` | **HIGH** | `app.py:17` | `reachable` | **CONFIRMED → FIXED** | **VERIFIED** |
| `PY-PATH-001-456896a5` | `PY-PATH-001` | `CWE-22` | **HIGH** | `app.py:22` | `reachable` | **CONFIRMED → FIXED** | **VERIFIED** |
| `PY-TLS-001-8289e912` | `PY-TLS-001` | `CWE-295` | **MEDIUM** | `app.py:29` | `reachable` | Static/Unit | **VERIFIED** |
| `CFG-DOCKER-002-6842e569` | `CFG-DOCKER-002` | `CWE-829` | **MEDIUM** | `Dockerfile:1` | `not_applicable` | Static/Unit | **VERIFIED** |
| `CFG-DOCKER-001-f5629fdf` | `CFG-DOCKER-001` | `CWE-250` | **HIGH** | `Dockerfile:4` | `not_applicable` | Static/Unit | **VERIFIED** |
| `CFG-SECRET-001-d6512cd1` | `CFG-SECRET-001` | `CWE-798` | **HIGH** | `.env:1` | `not_applicable` | N/A (scrubbed) | **Manual review** |
| `DEP-CVE-2020-14343-5d36c384` | `DEP-CVE-2020-14343` | `CWE-502` | **CRITICAL** | `requirements.txt:1` | `reachable` | Static/Unit | **VERIFIED** |
| `DEP-CVE-2023-45803-b11e1512` | `DEP-CVE-2023-45803` | `CWE-200` | **MEDIUM** | `requirements.txt:2` | `not_reachable` | Static/Unit | **VERIFIED** |

---

## 1. `PY-YAML-001` — Unsafe YAML Deserialization (`app.py:17`, `CWE-502`)

- **Core Issue:** `parse_config()` passes untrusted HTTP request bodies directly to `yaml.load(raw, Loader=yaml.FullLoader)`. Unlike `SafeLoader`, `FullLoader` honors Python-specific YAML object tags (`!!python/...`), allowing callers to instantiate arbitrary Python types during deserialization.
- **How the `curl` Probe Verifies It:** VulnBox boots `app.py` inside the network-isolated Docker sandbox and sends a benign Python-tagged YAML document (`!!python/tuple [1, 2]`) to `POST /parse`. Because `FullLoader` executes Python tag constructors instead of restricting input to standard YAML primitives, the unpatched server returns `HTTP 200` with the deserialized tuple (`{"parsed": "(1, 2)"}`).
- **How the Fix Resolves It:** Replacing `yaml.load(raw, Loader=yaml.FullLoader)` with `yaml.safe_load(raw)` restricts parsing to basic YAML types (strings, numbers, lists, dicts). Re-running the exact same `curl` command is rejected with `HTTP 400` (`could not determine a constructor for the tag 'tag:yaml.org,2002:python/tuple'`), while normal YAML configs continue passing all unit tests.

**Active Loopback `curl` Probe Executed Inside Docker Sandbox:**
```bash
curl -sS -i -X POST -H 'Content-Type: text/plain' --data '!!python/tuple [1, 2]' 'http://127.0.0.1:$PORT/parse'
```

**Before Remediation (Vulnerability Actively Reproduced):**
```http
HTTP/1.0 200 OK
server: BaseHTTP/0.6 Python/3.12.16
content-type: application/json
content-length: 20

{"parsed": "(1, 2)"}
```
- `matched_vulnerable=True`, `matched_fixed=False`
- Generated regression test (`tests/test_security_py_yaml_001_e119e444.py`): `FAILED` (`rc=1`, `AssertionError: yaml.load() must use SafeLoader or yaml.safe_load()`)
- Baseline existing test suite (`python3 -m pytest -q`): `2 passed in 0.02s` (`rc=0`)

**Generated & Verified Patch (`patches/PY-YAML-001-e119e444.patch`):**
```diff
--- a/app.py
+++ b/app.py
@@ -14,7 +14,7 @@
 
 def parse_config(raw: str):
     """Parse YAML payload (intentionally uses FullLoader for sandbox testing)."""
-    return yaml.load(raw, Loader=yaml.FullLoader)
+    return yaml.safe_load(raw)
 
 
 def read_public_file(name: str) -> str:
```

**After Remediation (Exact Same `curl` Probe Re-Run in Patched Sandbox):**
```http
HTTP/1.0 400 Bad Request
server: BaseHTTP/0.6 Python/3.12.16
content-type: application/json
content-length: 185

{"error": "invalid yaml: could not determine a constructor for the tag 'tag:yaml.org,2002:python/tuple'\n  in \"<unicode string>\", line 1, column 1:\n    !!python/tuple [1, 2]\n    ^"}
```
- `matched_vulnerable=False`, `matched_fixed=True` (`dynamic_confirmed_and_fixed=True`)
- Static re-scan: `finding_resolved=True`, `no_new_findings=True`
- Generated regression test: `1 passed in 0.00s` (`rc=0`)
- Existing test suite (`python3 -m pytest -q`): `2 passed in 0.02s` (`rc=0`)

---

## 2. `PY-PATH-001` — Unconstrained `os.path.join` Before File Read (`app.py:22`, `CWE-22`)

- **Core Issue:** `read_public_file(name)` combines `PUBLIC_DIR` with the caller-supplied `name` query parameter via `os.path.join(PUBLIC_DIR, name)` and immediately opens the file without canonicalizing or verifying that the resolved path stays inside `PUBLIC_DIR`. Relative `../` segments escape the intended directory.
- **How the `curl` Probe Verifies It:** VulnBox creates a synthetic non-sensitive marker file (`vulnbox_boundary_marker.txt`) outside `public/` in the ephemeral sandbox and requests `GET /files?name=../vulnbox_boundary_marker.txt`. The unpatched server traverses up out of `public/` and leaks the marker with `HTTP 200` (`VULNBOX_BOUNDARY_MARKER_9F3A`).
- **How the Fix Resolves It:** The patch canonicalizes both `PUBLIC_DIR` and the requested path with `Path.resolve()` and enforces `target.is_relative_to(_base_dir)`, raising `ValueError` if the path escapes the root. Re-running the exact same `curl` probe now returns `HTTP 403` (`{"error": "Path escapes allowed base directory"}`), while legitimate files inside `public/` still return `200`.

**Active Loopback `curl` Probe Executed Inside Docker Sandbox** *(against synthetic boundary marker `vulnbox_boundary_marker.txt` placed outside `public/` in the ephemeral sandbox)*:
```bash
curl -sS -i -X GET 'http://127.0.0.1:$PORT/files?name=../vulnbox_boundary_marker.txt'
```

**Before Remediation (Vulnerability Actively Reproduced):**
```http
HTTP/1.0 200 OK
server: BaseHTTP/0.6 Python/3.12.16
content-type: text/plain
content-length: 28

VULNBOX_BOUNDARY_MARKER_9F3A
```
- `matched_vulnerable=True`, `matched_fixed=False`
- Generated regression test (`tests/test_security_py_path_001_456896a5.py`): `FAILED` (`rc=1`, `AssertionError: Path resolution must enforce base directory confinement`)

**Generated & Verified Patch (`patches/PY-PATH-001-456896a5.patch`):**
```diff
--- a/app.py
+++ b/app.py
@@ -1,6 +1,7 @@
 """Sample runnable Python HTTP application with intentional test vulnerabilities."""
 
 from __future__ import annotations
+from pathlib import Path
 
 import json
 import os
@@ -19,7 +20,10 @@
 
 def read_public_file(name: str) -> str:
     """Read a file from the public directory (intentionally lacks path confinement)."""
-    target = os.path.join(PUBLIC_DIR, name)
+    _base_dir = Path(PUBLIC_DIR).resolve()
+    target = (_base_dir / name).resolve()
+    if not target.is_relative_to(_base_dir):
+        raise ValueError("Path escapes allowed base directory")
     with open(target, encoding="utf-8") as fh:
         return fh.read()
```

**After Remediation (Exact Same `curl` Probe Re-Run in Patched Sandbox):**
```http
HTTP/1.0 403 Forbidden
server: BaseHTTP/0.6 Python/3.12.16
content-type: application/json
content-length: 48

{"error": "Path escapes allowed base directory"}
```
- `matched_vulnerable=False`, `matched_fixed=True` (`dynamic_confirmed_and_fixed=True`)
- Static re-scan: `finding_resolved=True`, `no_new_findings=True`
- Generated regression test: `1 passed in 0.00s` (`rc=0`)
- Existing test suite (`python3 -m pytest -q`): `2 passed in 0.02s` (`rc=0`)

---

## 3. Additional Findings & Verified Patches

- **`PY-TLS-001` (`app.py:29`, `CWE-295` — TLS Certificate Verification Disabled):**
  - **Core Issue:** `fetch_upstream_status()` calls `requests_mod.get(url, verify=False, ...)`, disabling TLS certificate validation and exposing outbound HTTPS requests to man-in-the-middle interception.
  - **Verification & Fix:** Verified via AST check + generated regression test (`FAIL → PASS`). Switching `verify=False` to `verify=True` restores standard CA certificate validation.
- **`CFG-DOCKER-002` (`Dockerfile:1`, `CWE-829` — Unpinned Container Base Image):**
  - **Core Issue:** `FROM python:latest` pulls a mutable floating tag, making builds non-reproducible and risking unexpected breaking or vulnerable base image changes.
  - **Verification & Fix:** Verified via config analyzer + Dockerfile regression test (`FAIL → PASS`). Pinning to `FROM python:3.12-slim` locks the runtime baseline.
- **`CFG-DOCKER-001` (`Dockerfile:4`, `CWE-250` — Container Runs as Root):**
  - **Core Issue:** The `Dockerfile` omits a `USER` instruction, so the containerized app runs as UID `0` (`root`), amplifying blast radius if the process is compromised.
  - **Verification & Fix:** Verified via config analyzer + Dockerfile regression test (`FAIL → PASS`). Adding `RUN useradd --create-home --uid 1000 appuser` and `USER appuser` drops privileges to a non-root user.
- **`CFG-SECRET-001` (`.env:1`, `CWE-798` — Sensitive `.env` File in Repository):**
  - **Core Issue:** A `.env` file containing credentials (`DATABASE_URL`, `API_TOKEN`) is present in the repository tree.
  - **Verification & Fix:** Automatically scrubbed (`REDACTED_BY_VULNBOX_*`) before mounting into the sandbox and flagged for manual removal, `.gitignore` enforcement, and credential rotation.
- **`DEP-CVE-2020-14343` (`requirements.txt:1`, `CWE-502` — Reachable PyYAML CVE):**
  - **Core Issue:** `PyYAML==5.3.1` is vulnerable to arbitrary code execution via `FullLoader`/`yaml.load`, and AST call-graph analysis confirms it is **reachable** (`app.py:17`).
  - **Verification & Fix:** Verified via reachability analyzer + manifest version regression test (`FAIL → PASS`). Bumping to `PyYAML>=6.0.2` moves off the vulnerable release.
- **`DEP-CVE-2023-45803` (`requirements.txt:2`, `CWE-200` — Unreachable `urllib3` CVE):**
  - **Core Issue:** `urllib3==1.26.5` does not strip request bodies on cross-origin redirects; AST analysis classifies it as **`not_reachable`** (never imported in source), reducing triage urgency while still offering a clean upgrade path.
  - **Verification & Fix:** Verified via manifest version regression test (`FAIL → PASS`) with zero impact on existing unit tests by upgrading to `urllib3>=2.2.3`.

All 5 auto-remediable diffs below transitioned regression tests `FAIL → PASS` and kept existing tests green (`2 passed`):

```diff
# patches/PY-TLS-001-8289e912.patch (CWE-295)
--- a/app.py
+++ b/app.py
@@ -26,7 +26,7 @@
 def fetch_upstream_status(requests_mod, url: str):
     """Example TLS misconfiguration."""
-    return requests_mod.get(url, verify=False, timeout=5)
+    return requests_mod.get(url, verify=True, timeout=5)

# patches/CFG-DOCKER-002-6842e569.patch (CWE-829)
--- a/Dockerfile
+++ b/Dockerfile
@@ -1,4 +1,4 @@
-FROM python:latest
+FROM python:3.12-slim
 WORKDIR /app

# patches/CFG-DOCKER-001-f5629fdf.patch (CWE-250)
--- a/Dockerfile
+++ b/Dockerfile
@@ -1,4 +1,6 @@
 FROM python:latest
 WORKDIR /app
 COPY . /app
+RUN useradd --create-home --uid 1000 appuser
+USER appuser
 CMD ["python3", "app.py"]

# patches/DEP-CVE-2020-14343-5d36c384.patch (Reachable CVE: app.py:17 yaml.load / FullLoader)
--- a/requirements.txt
+++ b/requirements.txt
@@ -1,2 +1,2 @@
-PyYAML==5.3.1
+PyYAML>=6.0.2
 urllib3==1.26.5

# patches/DEP-CVE-2023-45803-b11e1512.patch (Not reachable in source, safe bump verified)
--- a/requirements.txt
+++ b/requirements.txt
@@ -1,2 +1,2 @@
 PyYAML==5.3.1
-urllib3==1.26.5
+urllib3>=2.2.3
```
