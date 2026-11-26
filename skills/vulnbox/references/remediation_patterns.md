# VulnBox Remediation & Custom Probe Reference

## Declarative Loopback Probe Schema (`probe.json`)

Pass `--probe probe.json` to `vulnbox probe`, `vulnbox remediate`, or `vulnbox verify-patch` to actively confirm any HTTP endpoint vulnerability before patching and verify the fix afterward with the exact same `curl` request:

```json
{
  "probe_id": "probe-custom-yaml",
  "finding_id": "PY-YAML-001-example",
  "rule_id": "PY-YAML-001",
  "description": "Verify POST /parse rejects non-safe YAML tags after patching to yaml.safe_load",
  "method": "POST",
  "path": "/parse",
  "headers": {
    "Content-Type": "text/plain"
  },
  "body": "!!python/tuple [1, 2]",
  "vulnerable_expectation": {
    "status_codes": [200]
  },
  "fixed_expectation": {
    "status_codes": [400, 422]
  }
}
```

### Supported Expectation Fields
- `status_codes`: list of expected HTTP status codes (e.g., `[200]` vs `[400, 403]`).
- `body_contains` / `body_not_contains`: substrings expected or forbidden in the response body.
- `headers_contain` / `headers_not_contain`: case-insensitive HTTP header substring checks.
- `setup_marker_file` / `setup_marker_content`: optional synthetic non-sensitive boundary marker file created inside the sandbox temp dir for path-confinement testing and automatically deleted after the probe.

## Secure Remediation Patterns

| Rule ID | CWE | Preferred Fix |
| :--- | :--- | :--- |
| `PY-YAML-001` | CWE-502 | Replace `yaml.load()` / `full_load()` / `unsafe_load()` with `yaml.safe_load()`. |
| `PY-PATH-001` | CWE-22 | Resolve `base = Path(root).resolve()`, `target = (base / rel).resolve()`, enforce `target.is_relative_to(base)`. |
| `PY-TLS-001` | CWE-295 | Set `verify=True` (or a pinned CA bundle path). |
| `PY-SQL-001` | CWE-89 | Use parameterized SQL placeholders (`?` / `%s`) with bound tuples. |
| `PY-CMD-001` | CWE-78 | Use `subprocess.run([...], shell=False)` with explicit argument arrays. |
| `JS-PATH-001` | CWE-22 | Resolve `base = path.resolve(root)`, `target = path.resolve(base, rel)`, enforce `target.startsWith(base + path.sep)`. |
| `JS-CORS-001` | CWE-942 | Validate `req.headers.origin` against an explicit `Set` of trusted origins before setting `Access-Control-Allow-Origin`. |
| `JS-TLS-001` | CWE-295 | Set `rejectUnauthorized: true` and remove `NODE_TLS_REJECT_UNAUTHORIZED="0"`. |
| `CFG-DOCKER-001` | CWE-250 | Create and switch to a non-root `USER` before `CMD`/`ENTRYPOINT`. |
| `CFG-DOCKER-002` | CWE-829 | Pin container base image tags (avoid `:latest` or bare names). |
