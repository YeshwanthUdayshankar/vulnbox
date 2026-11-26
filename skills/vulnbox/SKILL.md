---
name: vulnbox
description: >-
  Tests local Python and Node.js repositories inside a secret-scrubbed isolated sandbox
  using static analysis, dependency CVE reachability, config hygiene, and active before/after
  loopback curl probes, then generates and dual-verifies remediation patches, regression tests,
  Markdown reports, and SARIF 2.1.0 output. Use when asked to test a repo for vulnerabilities
  in a sandbox, confirm exploitability/reproducibility with active curl checks, or verify
  security fixes without mutating the working tree.
---

# VulnBox: Sandboxed Vulnerability Verification & Remediation

Test repositories in an isolated, secret-scrubbed sandbox, **actively confirm vulnerabilities at runtime** using loopback `curl` probes before patching, and re-run the **exact same probe + test suite** after patching to prove the fix works with zero regressions.

## Workflow

1. **Check environment & profile the target repository (read-only):**
   ```bash
   ./scripts/run_vulnbox.sh doctor
   ./scripts/run_vulnbox.sh profile <repo-path> --json
   ```
   Confirm detected ecosystem (`python`, `node`, `mixed`), test commands, and runnable `start_command`.

2. **Run end-to-end sandboxed scan, active pre/post `curl` probing, and dual-verified remediation:**
   ```bash
   ./scripts/run_vulnbox.sh remediate <repo-path> \
     --backend auto \
     --out <output-dir>
   ```
   - Pass `--start-cmd "<cmd>"` and `--health-path "/health"` if the app uses a custom server entrypoint.
   - Pass `--advisories <advisories.json>` to check specific dependency CVEs and reachability.
   - Pass `--probe <probe.json>` to run custom loopback `curl` probes against specific endpoints.

3. **Author & verify custom patches for complex or custom-endpoint findings:**
   If a finding requires a custom multi-file fix or a custom endpoint probe:
   - Write a declarative loopback probe JSON matching `DynamicProbeSpec` (see [remediation_patterns.md](./references/remediation_patterns.md)).
   - Run `probe` first to prove the vulnerability reproduces live on `127.0.0.1`:
     ```bash
     ./scripts/run_vulnbox.sh probe <repo-path> --probe <probe.json> --start-cmd "<cmd>"
     ```
   - Draft a minimal unified diff (`candidate.patch`) and defensive regression test, then dual-verify inside the sandbox:
     ```bash
     ./scripts/run_vulnbox.sh verify-patch <repo-path> \
       --patch candidate.patch \
       --finding-id <finding-id> \
       --probe <probe.json> \
       --test-file <regression_test> \
       --json
     ```
   - Only treat a patch as verified if `verify-patch` exits `0` (`verified == true`).

4. **Inspect the generated bundle (`<output-dir>`):**
   - `report.md`: Executive summary, before/after `curl` commands and responses, unified diffs, and HITL checklist.
   - `findings.sarif.json`: Schema-validated SARIF 2.1.0 report.
   - `patches/*.patch` and `regression_tests/*`: Ready-to-review diffs and permanent security tests.

5. **Mandatory Human-in-the-Loop (HITL) Gate:**
   Present the confirmed findings, before/after `curl` proof, verified `.patch` diffs, and regression test results to the user for explicit approval **before** applying any patch to their real working tree (`git apply`).

## Security & Anti-Hallucination Guardrails

- **Zero Host Mutation:** Never modify the target repository during testing; all scans, probes, and patch tests must run inside the scrubbed ephemeral sandbox.
- **Active Proof Honesty:** Never claim a vulnerability was actively confirmed unless `dynamic_probe_before.matched_vulnerable == true`, and never claim a fix is dynamically verified unless the **same** probe returned `dynamic_probe_after.matched_fixed == true` and `matched_vulnerable == false`.
- **Loopback Only:** Active probes are strictly confined to `127.0.0.1` / `localhost` inside the sandbox. Never target external URLs or remote systems.
- **Secret Hygiene:** Always rely on VulnBox's pre-sandbox secret scrubber so real `.env` files and credentials are never mounted into test sandboxes.
