# VulnBox

Sandboxed security testing, **active before/after loopback `curl` verification**, and dual-verified patch remediation for Python and Node.js repositories—packaged as both a standalone CLI and a portable Agent Skill (`skills/vulnbox/`).

## Features

- **Zero-Mutation Secret-Scrubbed Sandbox**: Copies your repository to an ephemeral workspace, strips `.git/config`, and scrubs `.env`/keys/tokens before running anything—never mutating your working tree.
- **Pluggable Hardened Sandbox**: Runs inside hardened Docker containers (`--network=none`, `--cap-drop=ALL`, `--read-only`, `--security-opt=no-new-privileges:true`, non-root UID, CPU/RAM/PID caps) with an automatic isolated local fallback when Docker daemon is unavailable.
- **4-Layer Analysis**: Python AST SAST, Node.js SAST, Dockerfile/config/secret hygiene, and Dependency CVE reachability (`reachable` / `not_reachable` / `under_investigation`).
- **Active Before/After Loopback Verification (`curl`)**: Boots the target app on `127.0.0.1:<ephemeral_port>` inside the sandbox, runs a reproducible `curl` probe to prove the vulnerability exists live, applies the candidate fix, and re-runs the **exact same `curl` probe** to prove the fix works.
- **Dual-Verified Patching & Regression Tests**: Confirms SAST clean + active `curl` probe fixed + generated defensive regression test transitions `FAIL → PASS` + repo's existing test suite passes with zero regressions.
- **Standard Outputs**: Markdown report, verified `.patch` unified diffs, generated security regression tests, and schema-validated **SARIF 2.1.0** JSON.

## Quick Start

```bash
git clone https://github.com/YeshwanthUdayshankar/vulnbox.git
cd vulnbox
uv sync --extra dev

# Check environment & sandbox backends
uv run vulnbox doctor

# Profile a repository (read-only)
uv run vulnbox profile /path/to/repo

# Build the hardened Docker sandbox image
docker build -t vulnbox-sandbox:latest -f docker/sandbox.Dockerfile .

# Run end-to-end sandboxed scan, active curl probing, and dual-verified remediation
uv run vulnbox remediate /path/to/repo --backend docker --out ./vulnbox-out

# Verify a custom/agent-authored patch + custom loopback curl probe
uv run vulnbox verify-patch /path/to/repo --patch fix.patch --probe probe.json --backend docker
```

---

## End-to-End Sample Runs (Captured Docker Sandbox Output)

The entire pipeline was tested end-to-end inside the hardened **`vulnbox-sandbox:latest`** Docker container (`--network=none`, `--cap-drop=ALL`, `--read-only`, `--security-opt=no-new-privileges:true`) against two runnable sample repositories bundled in `tests/fixtures/`:
- Python sample app: [`tests/fixtures/py_sample_app`](tests/fixtures/py_sample_app)
- Node.js sample app: [`tests/fixtures/node_sample_app`](tests/fixtures/node_sample_app)

### Environment & CLI Execution Output

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

$ .venv/bin/vulnbox remediate tests/fixtures/node_sample_app --backend docker --out /tmp/vulnbox-docker-node
Remediation bundle complete: 5 findings, 5/5 verified patches, 2 actively confirmed & fixed via live curl probe.
Report:  /tmp/vulnbox-docker-node/report.md
SARIF:   /tmp/vulnbox-docker-node/findings.sarif.json
Patches: /tmp/vulnbox-docker-node/patches
```

---

### Sample Repo 1: Python (`tests/fixtures/py_sample_app`)

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

#### 1. `PY-YAML-001` — Unsafe YAML Deserialization (`app.py:17`, `CWE-502`)

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

#### 2. `PY-PATH-001` — Unconstrained `os.path.join` Before File Read (`app.py:22`, `CWE-22`)

- **Core Issue:** `read_public_file(name)` combines `PUBLIC_DIR` with the caller-supplied `name` query parameter via `os.path.join(PUBLIC_DIR, name)` and immediately opens the file without canonicalizing or verifying that the resolved path stays inside `PUBLIC_DIR`. Relative `../` segments escape the intended directory.
- **How the `curl` Probe Verifies It:** VulnBox creates a synthetic non-sensitive marker file (`vulnbox_boundary_marker.txt`) outside `public/` in the ephemeral sandbox and requests `GET /files?name=../vulnbox_boundary_marker.txt`. The unpatched server traverses up out of `public/` and leaks the marker with `HTTP 200` (`VULNBOX_BOUNDARY_MARKER_9F3A`).
- **How the Fix Resolves It:** The patch canonicalizes both `PUBLIC_DIR` and the requested path with `Path.resolve()` and enforces `target.is_relative_to(_base_dir)`, raising `ValueError` if the path escapes the root. Re-running the exact same `curl` probe now returns `HTTP 403` (`{"error": "Path escapes allowed base directory"}`), while legitimate files inside `public/` still return `200`.

**Active Loopback `curl` Probe Executed Inside Docker Sandbox** *(against a synthetic non-sensitive boundary marker `vulnbox_boundary_marker.txt` placed outside `public/` in the ephemeral sandbox)*:
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

#### 3. Additional Findings & Verified Patches in Python Sample Repo

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

---

### Sample Repo 2: Node.js (`tests/fixtures/node_sample_app`)

- **Sandbox Backend:** `docker` (`vulnbox-sandbox:latest`, `--network=none`)
- **Total Findings:** `5` | **Dual-Verified Patches:** `5 / 5` | **Actively Confirmed & Fixed via `curl`:** `2`

| Finding ID | Rule | CWE | Severity | Location | Reachability | Active `curl` Probe | Patch Status |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| `JS-TLS-001-c9bb02c4` | `JS-TLS-001` | `CWE-295` | **MEDIUM** | `server.mjs:10` | `reachable` | Static/Unit | **VERIFIED** |
| `JS-PATH-001-00bcd807` | `JS-PATH-001` | `CWE-22` | **HIGH** | `server.mjs:14` | `reachable` | **CONFIRMED → FIXED** | **VERIFIED** |
| `JS-CORS-001-8ae3bda7` | `JS-CORS-001` | `CWE-942` | **HIGH** | `server.mjs:29` | `reachable` | **CONFIRMED → FIXED** | **VERIFIED** |
| `DEP-CVE-2021-23337-00acf476` | `DEP-CVE-2021-23337` | `CWE-78` | **HIGH** | `package.json:10` | `not_reachable` | Static/Unit | **VERIFIED** |
| `DEP-CVE-2021-44906-bf28f816` | `DEP-CVE-2021-44906` | `CWE-1321` | **CRITICAL** | `package.json:11` | `not_reachable` | Static/Unit | **VERIFIED** |

#### 1. `JS-PATH-001` — Unconstrained `path.join` Before File Read (`server.mjs:14`, `CWE-22`)

- **Core Issue:** `readPublicFile(name)` constructs a path with `path.join(PUBLIC_DIR, name)` and reads it directly via `fs.readFileSync(target, "utf8")`. Because `path.join()` resolves `..` sequences without checking whether the output stays under `PUBLIC_DIR`, callers can traverse outside the public directory.
- **How the `curl` Probe Verifies It:** VulnBox writes a synthetic boundary marker (`vulnbox_boundary_marker.txt`) one directory above `public/` inside the ephemeral Docker sandbox and sends `GET /files?name=../vulnbox_boundary_marker.txt`. The unpatched server resolves the parent traversal and returns `HTTP 200` with `VULNBOX_BOUNDARY_MARKER_9F3A`.
- **How the Fix Resolves It:** The patch resolves `_baseDir = path.resolve(PUBLIC_DIR)` and `target = path.resolve(_baseDir, name)` and throws an error unless `target` stays inside `_baseDir + path.sep`. Re-running the exact same `curl` probe now returns `HTTP 403` (`{"error":"Path escapes allowed base directory"}`), while normal public files continue passing `node --test`.

**Active Loopback `curl` Probe Executed Inside Docker Sandbox:**
```bash
curl -sS -i -X GET 'http://127.0.0.1:$PORT/files?name=../vulnbox_boundary_marker.txt'
```

**Before Remediation (Vulnerability Actively Reproduced):**
```http
HTTP/1.1 200 OK
content-type: text/plain

VULNBOX_BOUNDARY_MARKER_9F3A
```
- `matched_vulnerable=True`, `matched_fixed=False`
- Generated regression test (`node --test tests/security_js_path_001_00bcd807.test.mjs`): `fail 1` (`rc=1`)
- Baseline existing test suite (`node --test`): `pass 1, fail 0` (`rc=0`)

**Generated & Verified Patch (`patches/JS-PATH-001-00bcd807.patch`):**
```diff
--- a/server.mjs
+++ b/server.mjs
@@ -11,7 +11,11 @@
 };
 
 export function readPublicFile(name) {
-  const target = path.join(PUBLIC_DIR, name);
+  const _baseDir = path.resolve(PUBLIC_DIR);
+  const target = path.resolve(_baseDir, name);
+  if (target !== _baseDir && !target.startsWith(_baseDir + path.sep)) {
+    throw new Error("Path escapes allowed base directory");
+  }
   return fs.readFileSync(target, "utf8");
 }
```

**After Remediation (Exact Same `curl` Probe Re-Run in Patched Sandbox):**
```http
HTTP/1.1 403 Forbidden
content-type: application/json

{"error":"Path escapes allowed base directory"}
```
- `matched_vulnerable=False`, `matched_fixed=True` (`dynamic_confirmed_and_fixed=True`)
- Generated regression test: `pass 1, fail 0` (`rc=0`)
- Existing test suite (`node --test`): `pass 1, fail 0` (`rc=0`)

---

#### 2. `JS-CORS-001` — Permissive CORS Origin Reflection with Credentials (`server.mjs:29`, `CWE-942`)

- **Core Issue:** The `/api/data` route copies any incoming `Origin` request header directly into `Access-Control-Allow-Origin` (`req.headers.origin || "*"`) while also sending `Access-Control-Allow-Credentials: true`. This lets any untrusted third-party site issue credentialed cross-origin requests from a victim's browser and read private API responses.
- **How the `curl` Probe Verifies It:** VulnBox sends `GET /api/data` with an untrusted header `Origin: https://untrusted.example`. The unpatched server reflects `access-control-allow-origin: https://untrusted.example` together with `access-control-allow-credentials: true`, confirming live arbitrary-origin reflection.
- **How the Fix Resolves It:** The patch validates `req.headers.origin` against an explicit allowlist (`const _allowedOrigins = new Set(["http://localhost:3000"])`) and only sets `Access-Control-Allow-Origin` for approved origins. Re-running the exact same `curl` probe confirms `access-control-allow-origin` is omitted for `https://untrusted.example`.

**Active Loopback `curl` Probe Executed Inside Docker Sandbox:**
```bash
curl -sS -i -X GET -H 'Origin: https://untrusted.example' 'http://127.0.0.1:$PORT/api/data'
```

**Before Remediation (Untrusted Origin Reflected with Credentials):**
```http
HTTP/1.1 200 OK
access-control-allow-origin: https://untrusted.example
access-control-allow-credentials: true
content-type: application/json

{"items":["alpha","beta"]}
```
- `matched_vulnerable=True`, `matched_fixed=False`
- Generated regression test (`node --test tests/security_js_cors_001_8ae3bda7.test.mjs`): `fail 1` (`rc=1`)

**Generated & Verified Patch (`patches/JS-CORS-001-8ae3bda7.patch`):**
```diff
--- a/server.mjs
+++ b/server.mjs
@@ -26,7 +26,11 @@
     }
 
     if (reqUrl.pathname === "/api/data") {
-      res.setHeader("Access-Control-Allow-Origin", req.headers.origin || "*");
+      const _allowedOrigins = new Set(["http://localhost:3000"]);
+  const _safeOrigin = _allowedOrigins.has(req.headers.origin) ? req.headers.origin : null;
+  if (_safeOrigin) {
+    res.setHeader("Access-Control-Allow-Origin", _safeOrigin);
+  }
       res.setHeader("Access-Control-Allow-Credentials", "true");
       res.writeHead(200, { "Content-Type": "application/json" });
       res.end(JSON.stringify({ items: ["alpha", "beta"] }));
```

**After Remediation (Exact Same `curl` Probe Re-Run in Patched Sandbox):**
```http
HTTP/1.1 200 OK
access-control-allow-credentials: true
content-type: application/json

{"items":["alpha","beta"]}
```
- `Access-Control-Allow-Origin` is **no longer emitted** for untrusted origins (`matched_vulnerable=False`, `matched_fixed=True`, `dynamic_confirmed_and_fixed=True`)
- Generated regression test: `pass 1, fail 0` (`rc=0`)
- Existing test suite (`node --test`): `pass 1, fail 0` (`rc=0`)

---

#### 3. Additional Findings & Verified Patches in Node.js Sample Repo

- **`JS-TLS-001` (`server.mjs:10`, `CWE-295` — TLS Certificate Validation Disabled):**
  - **Core Issue:** `upstreamTlsOptions` sets `rejectUnauthorized: false`, disabling TLS certificate verification on outbound connections and allowing MITM attacks.
  - **Verification & Fix:** Verified via SAST + generated `node:test` regression test (`FAIL → PASS`). Setting `rejectUnauthorized: true` enforces strict certificate validation.
- **`DEP-CVE-2021-23337` (`package.json:10`, `CWE-78` — `lodash` Command Injection in `template()`):**
  - **Core Issue:** `lodash` `4.17.20` is vulnerable to command injection in `template()`; import/symbol reachability analysis confirms it is **`not_reachable`** in `server.mjs`.
  - **Verification & Fix:** Verified via version regression test (`FAIL → PASS`) and existing `node --test` suite by upgrading to `^4.17.21`.
- **`DEP-CVE-2021-44906` (`package.json:11`, `CWE-1321` — `minimist` Prototype Pollution):**
  - **Core Issue:** `minimist` `1.2.5` is vulnerable to prototype pollution; reachability analysis marks it **`not_reachable`** in source while still validating a clean upgrade.
  - **Verification & Fix:** Verified via version regression test (`FAIL → PASS`) and existing `node --test` suite by upgrading to `^1.2.8`.

```diff
# patches/JS-TLS-001-c9bb02c4.patch (CWE-295)
--- a/server.mjs
+++ b/server.mjs
@@ -7,7 +7,7 @@
 export const upstreamTlsOptions = {
-  rejectUnauthorized: false,
+  rejectUnauthorized: true,
 };

# patches/DEP-CVE-2021-23337-00acf476.patch (lodash < 4.17.21)
--- a/package.json
+++ b/package.json
@@ -7,7 +7,7 @@
   "dependencies": {
-    "lodash": "4.17.20",
+    "lodash": "^4.17.21",
     "minimist": "1.2.5"
   }

# patches/DEP-CVE-2021-44906-bf28f816.patch (minimist < 1.2.6)
--- a/package.json
+++ b/package.json
@@ -8,6 +8,6 @@
   "dependencies": {
     "lodash": "4.17.20",
-    "minimist": "1.2.5"
+    "minimist": "^1.2.8"
   }
```

---

## Output Bundle Structure

Every `vulnbox remediate` run writes a self-contained review bundle (without touching your target repo):

```text
vulnbox-out/
├── report.md                     # Executive summary, before/after curl proof, diffs, HITL checklist
├── findings.sarif.json           # Schema-validated SARIF 2.1.0 report
├── manifest.json                 # Full machine-readable AuditReport (headers, excerpts, logs)
├── patches/
│   └── <finding_id>.patch        # Verified git-compatible unified diffs
└── regression_tests/
    └── test_security_<id>.py     # (or security_<id>.test.mjs) permanent defensive tests
```

## Agent Skill

`vulnbox` ships as a portable Antigravity/Agent Skill at [`skills/vulnbox/SKILL.md`](skills/vulnbox/SKILL.md). To install it globally for Antigravity:

```bash
mkdir -p ~/.gemini/config/skills
ln -sfn "$(pwd)/skills/vulnbox" ~/.gemini/config/skills/vulnbox
```
