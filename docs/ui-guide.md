# VulnBox Local Web UI Guide (`vulnbox ui`)

Launch the zero-dependency local Web UI backed by `VulnBoxEngine` on **Linux, macOS, or Windows**:

| OS / Shell | Command |
| :--- | :--- |
| **Linux / macOS** | `./start-ui.sh` |
| **Windows (PowerShell / `pwsh`)** | `.\start-ui.ps1` |
| **Windows (CMD / Double-click)** | `start-ui.bat` |
| **Universal Python / `uv`** | `python scripts/start_ui.py` or `uv run vulnbox ui --port 8787` |

All launchers keep setup, `.venv/`, and `uv`/`pip` caches (`.vulnbox-cache/`) **strictly local to the repository** (setting `PIP_REQUIRE_VIRTUALENV=1`, `PIP_USER=0`, `PYTHONNOUSERSITE=1`, `UV_PROJECT_ENVIRONMENT=.venv`, and `UV_CACHE_DIR=.vulnbox-cache/uv`). They accept `--host`, `--port`, `--no-browser`, `--install` (force re-sync), `--no-install`, and `--dry-run`, and respect `VULNBOX_UI_HOST`, `VULNBOX_UI_PORT`, and `VULNBOX_NO_BROWSER`. Opens `http://127.0.0.1:8787` by default.

## 1. Dashboard Overview & Guarded `--llm` Controls

The top environment doctor bar reports live readiness for Python, Node.js, `curl`, the hardened Docker sandbox, and the isolated local sandbox. One-click sample buttons load bundled Python, Node.js, or LLM SQL fixtures, and the optional **Guarded LLM Synthesis (`--llm`)** panel configures Ollama, Gemini, OpenAI, or custom OpenAI-compatible endpoints.

![VulnBox Web UI Dashboard Overview](images/ui-dashboard-overview.png)

---

## 2. Live Docker Remediation Results, Before/After `curl` Proof & Diff Viewer

After running end-to-end remediation inside the hardened Docker sandbox (`--network=none`), the UI displays executive KPI cards, downloadable `report.md` / `findings.sarif.json` / `manifest.json` artifacts, side-by-side **Before Patch vs. After Patch `curl` responses**, syntax-highlighted unified diffs with one-click copy, expandable generated regression tests, and the **Guardrail Audit Trail**.

![VulnBox Web UI Remediation Results with Live curl Verification](images/ui-remediate-results.png)

---

## 3. Active Loopback `curl` Probe Runner

Test any custom or preset declarative `DynamicProbeSpec` JSON against a repository booted strictly on `127.0.0.1` inside the sandbox to actively reproduce vulnerabilities before authoring a patch.

![VulnBox Web UI Active Loopback curl Probe Tab](images/ui-active-probe.png)

---

## Built-In Web UI Security Controls

- **Loopback-Only Binding:** Binds strictly to `127.0.0.1` by default (refuses `0.0.0.0` unless explicitly overridden in code).
- **Per-Session CSRF Protection:** Every `POST /api/*` endpoint requires a random per-session `X-VulnBox-Token` header verified with constant-time comparison.
- **Host & Origin Validation:** Rejects cross-origin and non-loopback `Host`/`Origin` requests with `HTTP 403`.
- **Hardened HTTP Headers & XSS-Safe Rendering:** Sends strict `Content-Security-Policy`, `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, and `Referrer-Policy: no-referrer`, and renders all repository data via safe DOM `.textContent` nodes.
