# Sample Run 2: Node.js Repository (`tests/fixtures/node_sample_app`)

End-to-end hardened Docker sandbox capture (`vulnbox-sandbox:latest` with `--network=none`, `--cap-drop=ALL`, `--read-only`, `--security-opt=no-new-privileges:true`, non-root user) against [`tests/fixtures/node_sample_app`](../tests/fixtures/node_sample_app).

## Command & Captured CLI Output

```bash
$ .venv/bin/vulnbox remediate tests/fixtures/node_sample_app --backend docker --out /tmp/vulnbox-docker-node
Remediation bundle complete: 5 findings, 5/5 verified patches, 2 actively confirmed & fixed via live curl probe.
Report:  /tmp/vulnbox-docker-node/report.md
SARIF:   /tmp/vulnbox-docker-node/findings.sarif.json
Patches: /tmp/vulnbox-docker-node/patches
```

## Executive Summary & Findings Overview

- **Sandbox Backend:** `docker` (`vulnbox-sandbox:latest`, `--network=none`)
- **Total Findings:** `5` | **Dual-Verified Patches:** `5 / 5` | **Actively Confirmed & Fixed via `curl`:** `2`

| Finding ID | Rule | CWE | Severity | Location | Reachability | Active `curl` Probe | Patch Status |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| `JS-TLS-001-c9bb02c4` | `JS-TLS-001` | `CWE-295` | **MEDIUM** | `server.mjs:10` | `reachable` | Static/Unit | **VERIFIED** |
| `JS-PATH-001-00bcd807` | `JS-PATH-001` | `CWE-22` | **HIGH** | `server.mjs:14` | `reachable` | **CONFIRMED → FIXED** | **VERIFIED** |
| `JS-CORS-001-8ae3bda7` | `JS-CORS-001` | `CWE-942` | **HIGH** | `server.mjs:29` | `reachable` | **CONFIRMED → FIXED** | **VERIFIED** |
| `DEP-CVE-2021-23337-00acf476` | `DEP-CVE-2021-23337` | `CWE-78` | **HIGH** | `package.json:10` | `not_reachable` | Static/Unit | **VERIFIED** |
| `DEP-CVE-2021-44906-bf28f816` | `DEP-CVE-2021-44906` | `CWE-1321` | **CRITICAL** | `package.json:11` | `not_reachable` | Static/Unit | **VERIFIED** |

---

## 1. `JS-PATH-001` — Unconstrained `path.join` Before File Read (`server.mjs:14`, `CWE-22`)

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

## 2. `JS-CORS-001` — Permissive CORS Origin Reflection with Credentials (`server.mjs:29`, `CWE-942`)

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

## 3. Additional Findings & Verified Patches

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
