"""Core programmatic orchestration engine decoupled from the CLI presentation layer."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime
from pathlib import Path

from vulnbox._version import __version__ as TOOL_VERSION
from vulnbox.analyzers import run_all_analyzers
from vulnbox.callgraph import build_hybrid_call_graph
from vulnbox.llm import (
    GuardrailPolicy,
    LLMConfig,
    OpenAICompatLLMClient,
    synthesize_and_verify_patch,
)
from vulnbox.models import (
    AuditReport,
    DynamicProbeResult,
    DynamicProbeSpec,
    GuardrailEvent,
    MemoryLeakProbeResult,
    PatchCandidate,
    RepoProfile,
    VerificationResult,
)
from vulnbox.profiler import profile_repo
from vulnbox.registry import PluginRegistry, default_registry
from vulnbox.remediation import (
    generate_patch_for_finding,
    generate_regression_test,
    infer_memory_probe_for_finding,
    infer_probe_for_finding,
    run_dynamic_probe,
    run_memory_leak_probe,
    verify_patch,
)
from vulnbox.remediation.verifier import run_existing_tests
from vulnbox.reporting import write_report_bundle
from vulnbox.sandbox import SandboxBackend, SandboxPolicy, select_backend
from vulnbox.scrubber import ScrubbedWorkspace


def _utc_now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


class VulnBoxEngine:
    """High-level SDK/service facade orchestrating profiling, scanning, probing, and remediation."""

    def __init__(
        self,
        backend: SandboxBackend | str = "auto",
        registry: PluginRegistry | None = None,
        sandbox_policy: SandboxPolicy | None = None,
    ) -> None:
        self.backend: SandboxBackend = (
            select_backend(backend) if isinstance(backend, str) else backend
        )
        self.registry: PluginRegistry = registry or default_registry
        self.sandbox_policy: SandboxPolicy = sandbox_policy or SandboxPolicy()

    def profile(self, repo_path: str | Path) -> RepoProfile:
        return profile_repo(repo_path)

    def scan(
        self,
        repo_path: str | Path,
        advisories_path: Path | None = None,
        deep: bool = False,
        check_leaks: bool = False,
        start_cmd: str | None = None,
        health_path: str | None = None,
        out_dir: Path | None = None,
    ) -> tuple[AuditReport, dict[str, Path]]:
        repo = Path(repo_path).resolve()
        prof = profile_repo(repo)
        effective_check_leaks = check_leaks or deep
        effective_start = start_cmd or prof.start_command
        effective_health = health_path or prof.health_path
        memory_probes: list[MemoryLeakProbeResult] = []

        with ScrubbedWorkspace(repo) as sws:
            cg = build_hybrid_call_graph(
                sws.path,
                profile=prof,
                backend=self.backend,
                policy=self.sandbox_policy,
                include_runtime=deep,
            )
            findings = run_all_analyzers(
                sws.path,
                scrub_summary=sws.summary,
                advisories_path=advisories_path,
                profile=prof,
                registry=self.registry,
                call_graph=cg,
            )
            if effective_check_leaks and effective_start:
                for f in findings:
                    if f.category not in ("memory_leak", "resource_leak"):
                        continue
                    mspec = infer_memory_probe_for_finding(
                        f, sws.path, call_graph=cg, registry=self.registry
                    )
                    if mspec is not None:
                        mres = run_memory_leak_probe(
                            sws.path,
                            backend=self.backend,
                            start_cmd=effective_start,
                            spec=mspec,
                            health_path=effective_health,
                            policy=self.sandbox_policy,
                        )
                        memory_probes.append(mres)

            report = AuditReport(
                tool_version=TOOL_VERSION,
                timestamp=_utc_now(),
                sandbox_backend=self.backend.name,
                profile=prof,
                scrub_summary=sws.summary,
                findings=findings,
                call_graph_summary=cg.to_summary(),
                memory_probes=memory_probes,
            )
            written = (
                write_report_bundle(report, out_dir, registry=self.registry)
                if out_dir is not None
                else {}
            )
        return report, written

    def probe(
        self,
        repo_path: str | Path,
        specs: list[DynamicProbeSpec],
        start_cmd: str | None = None,
        health_path: str | None = None,
    ) -> list[DynamicProbeResult]:
        repo = Path(repo_path).resolve()
        prof = profile_repo(repo)
        effective_start = start_cmd or prof.start_command
        if not effective_start:
            raise ValueError("No runnable server start command detected. Supply start_cmd.")
        effective_health = health_path or prof.health_path

        results: list[DynamicProbeResult] = []
        with ScrubbedWorkspace(repo) as sws:
            for spec in specs:
                results.append(
                    run_dynamic_probe(
                        sws.path,
                        backend=self.backend,
                        start_cmd=effective_start,
                        spec=spec,
                        health_path=effective_health,
                        policy=self.sandbox_policy,
                    )
                )
        return results

    def remediate(
        self,
        repo_path: str | Path,
        start_cmd: str | None = None,
        health_path: str | None = None,
        custom_probes: list[DynamicProbeSpec] | None = None,
        advisories_path: Path | None = None,
        deep: bool = False,
        check_leaks: bool = False,
        llm_config: LLMConfig | None = None,
        llm_client: OpenAICompatLLMClient | None = None,
        guardrail_policy: GuardrailPolicy | None = None,
        max_workers: int = 4,
        out_dir: Path | None = None,
    ) -> tuple[AuditReport, dict[str, Path]]:
        repo = Path(repo_path).resolve()
        prof = profile_repo(repo)
        probes = custom_probes or []
        effective_check_leaks = check_leaks or deep

        active_client = llm_client or (OpenAICompatLLMClient(llm_config) if llm_config else None)
        llm_enabled = active_client is not None
        llm_model = (
            llm_config.resolved_model()
            if llm_config
            else (active_client.config.resolved_model() if active_client else None)
        )
        g_policy = guardrail_policy or GuardrailPolicy()
        guardrail_events: list[GuardrailEvent] = []
        patches: list[PatchCandidate] = []
        verifications: list[VerificationResult] = []
        unpatched_findings = []
        baseline_tests_cache: tuple[bool, str] | None = None

        with ScrubbedWorkspace(repo) as sws:
            scrub = sws.summary
            cg = build_hybrid_call_graph(
                sws.path,
                profile=prof,
                backend=self.backend,
                policy=self.sandbox_policy,
                include_runtime=deep,
            )
            findings = run_all_analyzers(
                sws.path,
                scrub_summary=scrub,
                advisories_path=advisories_path,
                profile=prof,
                registry=self.registry,
                call_graph=cg,
            )
            if findings:
                baseline_tests_cache = run_existing_tests(
                    sws.path, prof, self.backend, self.sandbox_policy
                )

            for f in findings:
                patch = generate_patch_for_finding(f, sws.path, registry=self.registry)
                if patch is None:
                    if f.category != "secret":
                        unpatched_findings.append(f)
                    continue
                reg = generate_regression_test(f, registry=self.registry)
                if reg:
                    patch.regression_test_path, patch.regression_test_code = reg

                matched_probe = next(
                    (p for p in probes if p.finding_id == f.finding_id or p.rule_id == f.rule_id),
                    None,
                )
                if matched_probe is None:
                    matched_probe = infer_probe_for_finding(f, sws.path, registry=self.registry)
                patch.probe_spec = matched_probe

                if effective_check_leaks and f.category in ("memory_leak", "resource_leak"):
                    patch.memory_probe_spec = infer_memory_probe_for_finding(
                        f, sws.path, call_graph=cg, registry=self.registry
                    )
                patches.append(patch)

            if active_client is not None and unpatched_findings:
                for f in unpatched_findings:
                    matched_probe = next(
                        (p for p in probes if p.finding_id == f.finding_id or p.rule_id == f.rule_id),
                        None,
                    )
                    cand, ver, evs = synthesize_and_verify_patch(
                        repo_path=repo,
                        workspace_dir=sws.path,
                        profile=prof,
                        finding=f,
                        backend=self.backend,
                        client=active_client,
                        policy=g_policy,
                        probe_spec=matched_probe,
                        start_cmd=start_cmd,
                        health_path=health_path,
                        advisories_path=advisories_path,
                        sandbox_policy=self.sandbox_policy,
                        registry=self.registry,
                        baseline_tests_override=baseline_tests_cache,
                    )
                    guardrail_events.extend(evs)
                    if cand is not None:
                        patches.append(cand)
                    if ver is not None:
                        verifications.append(ver)

        finding_map = {f.finding_id: f for f in findings}
        already_verified_ids = {v.finding_id for v in verifications}
        pending_patches = [p for p in patches if p.finding_id not in already_verified_ids]

        def _verify_one(p: PatchCandidate) -> VerificationResult:
            return verify_patch(
                repo_path=repo,
                profile=prof,
                patch=p,
                backend=self.backend,
                finding=finding_map.get(p.finding_id),
                probe_spec=p.probe_spec,
                memory_probe_spec=p.memory_probe_spec,
                check_leaks=effective_check_leaks,
                call_graph=cg,
                start_cmd=start_cmd,
                health_path=health_path,
                advisories_path=advisories_path,
                policy=self.sandbox_policy,
                registry=self.registry,
                baseline_tests_override=baseline_tests_cache,
            )

        workers = max(1, min(max_workers, len(pending_patches) or 1))
        if workers == 1 or len(pending_patches) <= 1:
            verifications.extend(_verify_one(p) for p in pending_patches)
        else:
            with ThreadPoolExecutor(max_workers=workers) as pool:
                verifications.extend(pool.map(_verify_one, pending_patches))

        mem_probe_results = [
            v.memory_probe_before for v in verifications if v.memory_probe_before is not None
        ]

        report = AuditReport(
            tool_version=TOOL_VERSION,
            timestamp=_utc_now(),
            sandbox_backend=self.backend.name,
            profile=prof,
            scrub_summary=scrub,
            findings=findings,
            patches=patches,
            verifications=verifications,
            call_graph_summary=cg.to_summary(),
            memory_probes=mem_probe_results,
            llm_enabled=llm_enabled,
            llm_model=llm_model,
            guardrail_events=guardrail_events,
        )
        written = (
            write_report_bundle(report, out_dir, registry=self.registry)
            if out_dir is not None
            else {}
        )
        return report, written

    def verify_external_patch(
        self,
        repo_path: str | Path,
        unified_diff: str,
        finding_id: str = "CUSTOM-001",
        rule_id: str = "CUSTOM",
        regression_test_path: str | None = None,
        regression_test_code: str | None = None,
        probe_spec: DynamicProbeSpec | None = None,
        start_cmd: str | None = None,
        health_path: str | None = None,
        description: str = "External patch",
    ) -> VerificationResult:
        repo = Path(repo_path).resolve()
        prof = profile_repo(repo)
        candidate = PatchCandidate(
            patch_id=f"patch-{finding_id}",
            finding_id=finding_id,
            rule_id=rule_id,
            strategy="agent_supplied",
            description=description,
            unified_diff=unified_diff,
            regression_test_path=regression_test_path,
            regression_test_code=regression_test_code,
            probe_spec=probe_spec,
        )
        return verify_patch(
            repo_path=repo,
            profile=prof,
            patch=candidate,
            backend=self.backend,
            probe_spec=probe_spec,
            start_cmd=start_cmd,
            health_path=health_path,
            policy=self.sandbox_policy,
            registry=self.registry,
        )
