"""Dual-verification orchestrator: active before/after curl probing + static + test suite."""

from __future__ import annotations

import shlex
import sys
from pathlib import Path
from typing import Any

from vulnbox.analyzers import run_all_analyzers
from vulnbox.models import (
    DynamicProbeResult,
    DynamicProbeSpec,
    Finding,
    MemoryLeakProbeResult,
    MemoryLeakProbeSpec,
    PatchCandidate,
    RepoProfile,
    VerificationResult,
)
from vulnbox.registry import PluginRegistry
from vulnbox.remediation.diff_utils import apply_unified_diff
from vulnbox.remediation.dynamic_probe import infer_probe_for_finding, run_dynamic_probe
from vulnbox.remediation.memory_probe import (
    infer_memory_probe_for_finding,
    run_memory_leak_probe,
)
from vulnbox.sandbox.base import SandboxBackend, SandboxPolicy
from vulnbox.scrubber import ScrubbedWorkspace


def run_existing_tests(
    workspace_dir: Path,
    profile: RepoProfile,
    backend: SandboxBackend,
    policy: SandboxPolicy,
) -> tuple[bool, str]:
    if not profile.test_commands:
        return True, "No existing test commands detected."
    logs: list[str] = []
    for eco, cmd in profile.test_commands.items():
        res = backend.run(workspace_dir, cmd, policy=policy)
        logs.append(f"[{eco}] $ {cmd} (rc={res.exit_code})\n{res.stdout}\n{res.stderr}".strip())
        if res.exit_code != 0:
            return False, "\n\n".join(logs)
    return True, "\n\n".join(logs)


_run_existing_tests = run_existing_tests


def _run_regression_test(
    workspace_dir: Path,
    test_rel_path: str,
    backend: SandboxBackend,
    policy: SandboxPolicy,
) -> tuple[bool, str]:
    if test_rel_path.endswith((".mjs", ".js", ".cjs")):
        cmd = f"node --test {shlex.quote(test_rel_path)}"
    else:
        py_exe = "python3" if backend.name == "docker" else sys.executable
        cmd = f"{shlex.quote(py_exe)} -m pytest -q {shlex.quote(test_rel_path)}"
    res = backend.run(workspace_dir, cmd, policy=policy)
    return res.exit_code == 0, f"$ {cmd} (rc={res.exit_code})\n{res.stdout}\n{res.stderr}".strip()


def verify_patch(
    repo_path: Path,
    profile: RepoProfile,
    patch: PatchCandidate,
    backend: SandboxBackend,
    finding: Finding | None = None,
    probe_spec: DynamicProbeSpec | None = None,
    memory_probe_spec: MemoryLeakProbeSpec | None = None,
    check_leaks: bool = False,
    call_graph: Any | None = None,
    start_cmd: str | None = None,
    health_path: str | None = None,
    advisories_path: Path | None = None,
    policy: SandboxPolicy | None = None,
    registry: PluginRegistry | None = None,
    baseline_tests_override: tuple[bool, str] | None = None,
) -> VerificationResult:
    """Verify a patch candidate in a fresh scrubbed sandbox before and after patching."""
    pol = policy or SandboxPolicy()
    logs: dict[str, str] = {}
    effective_start = start_cmd or profile.start_command
    effective_health = health_path or profile.health_path

    with ScrubbedWorkspace(repo_path) as sws:
        ws = sws.path
        # 1. Baseline findings & existing tests
        baseline_findings = run_all_analyzers(
            ws,
            scrub_summary=None,
            advisories_path=advisories_path,
            profile=profile,
            registry=registry,
            call_graph=call_graph,
        )
        baseline_ids = {f.finding_id for f in baseline_findings}

        if baseline_tests_override is not None:
            baseline_tests_ok, baseline_test_log = baseline_tests_override
        else:
            baseline_tests_ok, baseline_test_log = run_existing_tests(ws, profile, backend, pol)
        logs["baseline_tests"] = baseline_test_log

        # 2. Active pre-patch curl/HTTP probe (if app is runnable & probe exists)
        active_probe = probe_spec or patch.probe_spec
        if active_probe is None and finding is not None:
            active_probe = infer_probe_for_finding(finding, ws, registry=registry)

        probe_before: DynamicProbeResult | None = None
        if active_probe is not None and effective_start:
            probe_before = run_dynamic_probe(
                ws,
                backend=backend,
                start_cmd=effective_start,
                spec=active_probe,
                health_path=effective_health,
                policy=pol,
            )
            logs["dynamic_probe_before"] = (
                f"{probe_before.curl_command}\n"
                f"status={probe_before.status_code} matched_vulnerable={probe_before.matched_vulnerable} "
                f"error={probe_before.error}\n{probe_before.response_body_excerpt}"
            )

        # 2b. Active pre-patch memory & FD leak stress probe (opt-in via check_leaks)
        active_mem_probe = memory_probe_spec or patch.memory_probe_spec
        if active_mem_probe is None and check_leaks and finding is not None:
            active_mem_probe = infer_memory_probe_for_finding(
                finding, ws, call_graph=call_graph, registry=registry
            )

        mem_before: MemoryLeakProbeResult | None = None
        if check_leaks and active_mem_probe is not None and effective_start:
            mem_before = run_memory_leak_probe(
                ws,
                backend=backend,
                start_cmd=effective_start,
                spec=active_mem_probe,
                health_path=effective_health,
                policy=pol,
            )
            logs["memory_probe_before"] = (
                f"endpoint={mem_before.endpoint} slope={mem_before.bytes_per_request_slope}B/req "
                f"r2={mem_before.r_squared} fd_delta={mem_before.fd_delta} "
                f"leak_detected={mem_before.leak_detected} error={mem_before.error}"
            )

        # 3. Pre-patch regression test (should fail before patch)
        reg_failed_before: bool | None = None
        reg_file_abs: Path | None = None
        if patch.regression_test_path and patch.regression_test_code:
            reg_file_abs = ws / patch.regression_test_path
            reg_file_abs.parent.mkdir(parents=True, exist_ok=True)
            reg_file_abs.write_text(patch.regression_test_code, encoding="utf-8")
            passed_before, reg_pre_log = _run_regression_test(
                ws, patch.regression_test_path, backend, pol
            )
            reg_failed_before = not passed_before
            logs["regression_test_before"] = reg_pre_log
            reg_file_abs.unlink(missing_ok=True)

        # 4. Apply unified diff inside the ephemeral sandbox copy
        try:
            apply_unified_diff(ws, patch.unified_diff)
            patch_applied = True
        except Exception as exc:
            logs["patch_error"] = str(exc)
            return VerificationResult(
                patch_id=patch.patch_id,
                finding_id=patch.finding_id,
                sandbox_backend=backend.name,
                baseline_tests_passed=baseline_tests_ok,
                patch_applied=False,
                finding_resolved=False,
                no_new_findings=False,
                dynamic_probe_before=probe_before,
                dynamic_probe_after=None,
                dynamic_confirmed_and_fixed=False if probe_before else None,
                regression_test_failed_before=reg_failed_before,
                regression_test_passed_after=None,
                existing_tests_passed_after=False,
                verified=False,
                summary=f"Patch failed to apply: {exc}",
                logs=logs,
            )

        # 5. Post-patch static analysis check
        post_findings = run_all_analyzers(
            ws,
            scrub_summary=None,
            advisories_path=advisories_path,
            profile=profile,
            registry=registry,
            call_graph=call_graph,
        )
        post_ids = {f.finding_id for f in post_findings}
        target_rule = finding.rule_id if finding else patch.rule_id
        target_file = finding.file_path if finding else None

        # Finding is resolved if original ID is gone AND no matching rule remains on same file
        if target_file:
            same_rule_on_file = any(
                f.rule_id == target_rule and f.file_path == target_file for f in post_findings
            )
            finding_resolved = (patch.finding_id not in post_ids) and not same_rule_on_file
        else:
            finding_resolved = patch.finding_id not in post_ids

        new_findings = [f for f in post_findings if f.finding_id not in baseline_ids]
        # Exclude shifted line-number copies of untouched findings in modified files
        no_new_findings = len(new_findings) == 0 or all(
            f.rule_id in {bf.rule_id for bf in baseline_findings} for f in new_findings
        )

        # 6. Active post-patch curl/HTTP probe (exact same probe!)
        probe_after: DynamicProbeResult | None = None
        dynamic_ok: bool | None = None
        if active_probe is not None and effective_start:
            probe_after = run_dynamic_probe(
                ws,
                backend=backend,
                start_cmd=effective_start,
                spec=active_probe,
                health_path=effective_health,
                policy=pol,
            )
            logs["dynamic_probe_after"] = (
                f"{probe_after.curl_command}\n"
                f"status={probe_after.status_code} matched_fixed={probe_after.matched_fixed} "
                f"error={probe_after.error}\n{probe_after.response_body_excerpt}"
            )
            dynamic_ok = bool(
                probe_before
                and probe_before.matched_vulnerable
                and probe_after.matched_fixed
                and not probe_after.matched_vulnerable
            )

        # 6b. Active post-patch memory & FD leak stress probe
        mem_after: MemoryLeakProbeResult | None = None
        mem_ok: bool | None = None
        if check_leaks and active_mem_probe is not None and effective_start:
            mem_after = run_memory_leak_probe(
                ws,
                backend=backend,
                start_cmd=effective_start,
                spec=active_mem_probe,
                health_path=effective_health,
                policy=pol,
            )
            logs["memory_probe_after"] = (
                f"endpoint={mem_after.endpoint} slope={mem_after.bytes_per_request_slope}B/req "
                f"r2={mem_after.r_squared} fd_delta={mem_after.fd_delta} "
                f"leak_detected={mem_after.leak_detected} error={mem_after.error}"
            )
            mem_ok = bool(
                mem_before
                and mem_before.error is None
                and mem_after.error is None
                and mem_before.leak_detected
                and not mem_after.leak_detected
            )

        # 7. Post-patch regression test (must PASS)
        reg_passed_after: bool | None = None
        if patch.regression_test_path and patch.regression_test_code:
            reg_file_abs = ws / patch.regression_test_path
            reg_file_abs.parent.mkdir(parents=True, exist_ok=True)
            reg_file_abs.write_text(patch.regression_test_code, encoding="utf-8")
            reg_passed_after, reg_post_log = _run_regression_test(
                ws, patch.regression_test_path, backend, pol
            )
            logs["regression_test_after"] = reg_post_log
            reg_file_abs.unlink(missing_ok=True)

        # 8. Post-patch existing test suite (zero regressions)
        post_tests_ok, post_test_log = _run_existing_tests(ws, profile, backend, pol)
        logs["post_patch_tests"] = post_test_log

        verified = (
            patch_applied
            and finding_resolved
            and no_new_findings
            and post_tests_ok
            and (reg_passed_after is not False)
            and (reg_failed_before is not False)
            and (dynamic_ok is not False)
            and (mem_ok is not False)
        )

        status_parts = [
            f"finding_resolved={finding_resolved}",
            f"tests_after={post_tests_ok}",
        ]
        if reg_passed_after is not None:
            status_parts.append(f"reg_test={reg_failed_before}->pass:{reg_passed_after}")
        if dynamic_ok is not None:
            status_parts.append(f"active_curl_probe={dynamic_ok}")
        if mem_ok is not None:
            status_parts.append(f"memory_leak_probe={mem_ok}")

        return VerificationResult(
            patch_id=patch.patch_id,
            finding_id=patch.finding_id,
            sandbox_backend=backend.name,
            baseline_tests_passed=baseline_tests_ok,
            patch_applied=patch_applied,
            finding_resolved=finding_resolved,
            no_new_findings=no_new_findings,
            dynamic_probe_before=probe_before,
            dynamic_probe_after=probe_after,
            dynamic_confirmed_and_fixed=dynamic_ok,
            memory_probe_before=mem_before,
            memory_probe_after=mem_after,
            memory_leak_confirmed_and_fixed=mem_ok,
            regression_test_failed_before=reg_failed_before,
            regression_test_passed_after=reg_passed_after,
            existing_tests_passed_after=post_tests_ok,
            verified=verified,
            summary=", ".join(status_parts),
            logs=logs,
        )
