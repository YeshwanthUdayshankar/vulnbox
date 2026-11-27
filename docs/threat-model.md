# VulnBox Sandbox Threat Model

This document describes the security boundaries, threat model, hardening controls, and explicit non-goals of **VulnBox** when analyzing and executing untrusted local repositories.

---

## 1. Assets Protected

1. **Host Filesystem & Source Repository:** The target repository working tree, host user files (`$HOME`, `~/.ssh`, `~/.aws`), and host Python/Node global environments.
2. **Developer & Production Secrets:** `.env*` files, private keys (`*.pem`, `*.key`, `id_rsa`), cloud/registry auth tokens (`.npmrc`, `.pypirc`, AWS/GitHub/OpenAI keys).
3. **Host Network & Internal Services:** Prevention of data exfiltration, accidental outbound calls to production APIs (Stripe, Slack, cloud APIs), or SSRF pivoting to cloud metadata (`169.254.169.254`) / LAN hosts.
4. **LLM / AI Boundary Integrity:** Preventing repository prompt-injection payloads or unredacted secrets from escaping to external LLM endpoints when `--llm` is opted in.

---

## 2. Trust Boundaries & Controls

| Boundary | Threat | VulnBox Mitigation |
| :--- | :--- | :--- |
| **Workspace Copy & Secret Scrubber** (`scrubber.py`) | Target repo mutates itself, reads real `.env` secrets, or leaks keys to logs/LLM. | Copies the repo into an ephemeral temp workspace (source stays strictly read-only), strips `.git`/venvs/symlinks, replaces `.env*` secrets with format-preserving `REDACTED_BY_VULNBOX_*` dummies, and redacts inline secret tokens before any code runs. |
| **Docker Execution Sandbox** (`--backend docker`) | Malicious or buggy repo code tries to escape container, exfiltrate data, fork-bomb, or write rootfs. | Enforces `--rm`, `--init`, `--network=none`, `--ipc=none`, `--cap-drop=ALL`, `--security-opt=no-new-privileges:true`, `--read-only`, `--tmpfs /tmp:rw,noexec,nosuid,size=256m`, `--ulimit nofile=512:512`, `--memory`, `--cpus`, `--pids-limit`, non-root `--user`, and hard timeout container `docker rm -f`. |
| **Two-Phase `--build-deps` Layer** (`dep_builder.py`) | Untrusted repo executes code during online dependency installation (`postinstall`, `setup.py`). | Phase 1 copies **only** top-level manifest/lockfiles (never app source or `.env`) into an ephemeral Docker build context and enforces `npm ci --ignore-scripts`. Phase 2 executes app code exclusively under `--network=none`. *(Note: PyPI source distributions with custom `setup.py` hooks can still execute at build time; use pinned wheels or pre-built `--image` for hostile repos.)* |
| **Air-Gapped Integration Mocks & Sidecars** (`_mock_server.py`, `sidecars.py`) | App tries to hit real third-party APIs or exfiltrate via sidecar network. | HTTP/HTTPS preload interceptors reroute non-loopback requests to `127.0.0.1:<mock_port>` inside `--network=none` (also acting as an SSRF canary). Opt-in `--services postgres,redis` use an ephemeral Docker **`--internal`** network (zero internet egress) torn down in `finally`. |
| **Isolated Local Fallback** (`--backend local`) | Docker daemon unavailable on host. | Strips host environment variables, isolates `HOME`/`TMPDIR` to ephemeral temp directories, applies `RLIMIT_CPU`/`RLIMIT_NOFILE`, and terminates full process groups on timeout. **Not a kernel/filesystem containment boundary**—use `--backend docker` for untrusted third-party code. |
| **Web UI (`vulnbox ui`) & MCP (`vulnbox mcp`)** | Cross-site request forgery (CSRF), DNS rebinding, or remote code execution via browser. | Web UI binds strictly to `127.0.0.1`, checks `Host`/`Origin`, enforces per-session constant-time `X-VulnBox-Token` CSRF header on all `POST /api/*`, sets strict `Content-Security-Policy` (zero `'unsafe-inline'`) + `X-Frame-Options: DENY`, and renders via `.textContent`. MCP communicates strictly over local stdio pipes. |
| **Optional Guarded LLM (`--llm`)** (`guardrails.py`) | Prompt injection in untrusted repo comments, secret exfiltration, or unsafe/test-tampering patches. | 7 deterministic gates block outbound live tokens, wrap code in XML delimiters, reject protected-path/test-tampering diffs and external/destructive probes, and require sandbox dual-verification before marking any patch `VERIFIED`. |

---

## 3. Explicit Non-Goals

- **Not a replacement for a hardened VM/microVM (Firecracker/gVisor) against kernel 0-days:** `--backend docker` relies on standard Linux container namespaces/cgroups/seccomp. For actively hostile malware analysis, run VulnBox inside a dedicated VM or Kata/gVisor runtime.
- **Not a full-application black-box DAST crawler:** Active probing targets specific confirmed or declarative endpoints on `127.0.0.1` (Targeted DAST) rather than spidering arbitrary unauthenticated production URLs.
- **No automatic production repo mutation:** VulnBox never commits or applies patches directly to the user's working tree; human-in-the-loop review (`git apply`) is mandatory.
