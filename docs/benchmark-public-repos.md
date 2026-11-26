# Public Repository Benchmark Analysis

To evaluate `vulnbox` on real-world open-source codebases (measuring both **false-positive precision** on production templates and **SAST recall** on intentionally vulnerable benchmarks), we ran `vulnbox profile` and `vulnbox scan` inside the scrubbed sandbox against two popular public repositories:

1. **[`fastapi/full-stack-fastapi-template`](https://github.com/fastapi/full-stack-fastapi-template)** (30k+ stars — mixed Python FastAPI + React/Vite + Docker monorepo)
2. **[`OWASP/NodeGoat`](https://github.com/OWASP/NodeGoat)** (OWASP Node.js/Express security benchmark)

---

## 1. `fastapi/full-stack-fastapi-template` (Production Monorepo Precision)

### Profile Result
```json
{
  "ecosystem": "mixed",
  "manifests": [
    "backend/pyproject.toml",
    "pyproject.toml",
    "uv.lock",
    "bun.lock",
    "frontend/package.json",
    "package.json",
    "packages/react-email/package.json"
  ],
  "dockerfiles": ["backend/Dockerfile", "frontend/Dockerfile.playwright"],
  "frameworks": ["fastapi", "react", "vite"],
  "start_command": "fastapi run backend/app/main.py --port $PORT",
  "env_files": [".env", "frontend/.env"]
}
```

### Findings & Triage (`5` findings, `0` SAST false positives)

`vulnbox` scrubbed `2` env files (`13` redactions) before sandbox execution and reported `0` noisy SAST alerts across all Python and TypeScript files (the template properly uses parameterized SQLModel queries, allowlisted CORS, and `pwdlib[argon2,bcrypt]`):

| Finding ID | Rule / CWE | Severity | Location | Verdict | Analysis |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `CFG-DOCKER-001-2ed5f3e7` | `CFG-DOCKER-001` (`CWE-250`) | **HIGH** | `backend/Dockerfile:65` | **True Positive** | Production image (`FROM python:3.14` → `CMD ["fastapi", "run", "--workers", "4"]`) never switches to a non-root `USER`. |
| `CFG-DOCKER-005-8e9195f8` | `CFG-DOCKER-005` (`CWE-494`) | **HIGH** | `frontend/Dockerfile.playwright:8` | **True Positive** | Executes `RUN curl -fsSL https://bun.sh/install \| bash` without checksum verification during build. |
| `CFG-DOCKER-001-520493b3` | `CFG-DOCKER-001` (`CWE-250`) | **HIGH** | `frontend/Dockerfile.playwright:19` | **True Positive (Test Image)** | Playwright E2E container runs as `root` (lower priority since non-production). |
| `CFG-SECRET-001-d6512cd1` | `CFG-SECRET-001` (`CWE-798`) | **MEDIUM** | `.env:1` | **Contextual True Positive** | Smart `.env` triage classified this as `template_placeholder` (`changethis` values). Although `backend/app/core/config.py` guards against `"changethis"` outside `development`, shipping `.env` instead of `.env.example` risks accidental secret commits downstream. |
| `CFG-SECRET-001-d91d9431` | `CFG-SECRET-001` (`CWE-798`) | **LOW** | `frontend/.env:1` | **Informational** | Smart `.env` triage classified this as `public_only` (`VITE_API_URL`, `MAILPIT_HOST`), avoiding a noisy `HIGH` false positive. |

---

## 2. `OWASP/NodeGoat` (SAST Recall & Secret/Dependency Detection)

### Profile Result
```json
{
  "ecosystem": "node",
  "manifests": ["package-lock.json", "package.json"],
  "dockerfiles": ["Dockerfile"],
  "frameworks": ["express"],
  "test_commands": {"node": "npm test"},
  "start_command": "node server.js"
}
```

### Findings & Triage (`5` findings after comment-line filtering)

| Finding ID | Rule / CWE | Severity | Location | Verdict | Analysis |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `JS-EVAL-001-d039f81a` | `JS-EVAL-001` (`CWE-95`) | **HIGH** | `app/routes/contributions.js:32` | **True Positive** | `const preTax = eval(req.body.preTax);` — direct arbitrary JavaScript code execution from untrusted POST input. |
| `JS-EVAL-001-b8577dfc` | `JS-EVAL-001` (`CWE-95`) | **HIGH** | `app/routes/contributions.js:33` | **True Positive** | `const afterTax = eval(req.body.afterTax);` — direct arbitrary code execution. |
| `JS-EVAL-001-5f42f34b` | `JS-EVAL-001` (`CWE-95`) | **HIGH** | `app/routes/contributions.js:34` | **True Positive** | `const roth = eval(req.body.roth);` — direct arbitrary code execution. |
| `CFG-SECRET-001-8dbc969a` | `CFG-SECRET-001` (`CWE-798`) | **HIGH** | `artifacts/cert/server.key:1` | **True Positive** | Committed TLS private key file; automatically scrubbed before sandbox execution. |
| `DEP-CVE-2024-29041-23228b36` | `DEP-CVE-2024-29041` (`CWE-601`) | **MEDIUM** | `package.json:13` | **True Positive (Caveat)** | Accurately flagged `express ^4.13.4` (`< 4.19.2`). Note: per-file import reachability marked it `not_reachable` because route handlers invoke `res.redirect()` via Express middleware injection without directly calling `require("express")` in the route file—highlighting cross-file framework call-graph analysis as a next-phase enhancement. |

---

## Key Engineering Takeaways & Next Roadmap Items

Running against real public repositories drove four immediate upgrades shipped in this release (`monorepo nested manifests/uv.lock`, `CFG-DOCKER-005` for `curl | bash`, smart `.env` severity triage, and JS comment-line filtering) and identified clear next-phase enhancements:
- **Live OSV / `osv-scanner` integration** for full transitive lockfile CVE coverage beyond the built-in catalog.
- **Cross-file Express/FastAPI framework taint & middleware reachability** (e.g., tracking `res.redirect()` in routes that don't directly import `express`, and NoSQL/template-injection rules like MongoDB `$where` and `swig`/EJS unescaped sinks in NodeGoat).
- **Docker Compose multi-service sandbox orchestration** for full-stack apps that require Postgres/MongoDB sidecars during live `curl` verification.
