"""Core programmatic orchestration engine decoupled from the CLI presentation layer."""

from __future__ import annotations

from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

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
    MockRule,
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
    resolve_auth_headers,
    run_dynamic_probe,
    run_memory_leak_probe,
    verify_patch,
)
from vulnbox.remediation.verifier import run_existing_tests
from vulnbox.reporting import resolve_repo_output_dir, write_report_bundle
from vulnbox.sandbox import (
    AirGappedSidecars,
    DockerSandboxBackend,
    LocalSandboxBackend,
    SandboxBackend,
    SandboxPolicy,
    ensure_dependency_image,
    select_backend,
)
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
        image: str = "vulnbox-sandbox:latest",
    ) -> None:
        self.backend: SandboxBackend = (
            select_backend(backend, image=image) if isinstance(backend, str) else backend
        )
        self.registry: PluginRegistry = registry or default_registry
        self.sandbox_policy: SandboxPolicy = sandbox_policy or SandboxPolicy(image=image)

    @contextmanager
    def _execution_context(
        self,
        repo: Path,
        build_deps: bool = False,
        image: str | None = None,
        services: list[str] | None = None,
    ) -> Iterator[tuple[SandboxBackend, SandboxPolicy, dict[str, str]]]:
        """Prepare repo-aware backend (target .venv / dep layer / air-gapped sidecars)."""
        base_backend = self.backend
        pol = self.sandbox_policy

        if base_backend.name == "local":
            if isinstance(base_backend, LocalSandboxBackend) and base_backend.target_repo_path is None:
                yield LocalSandboxBackend(target_repo_path=repo), pol, {}
            else:
                yield base_backend, pol, {}
            return

        effective_image = image or (
            base_backend.default_image
            if isinstance(base_backend, DockerSandboxBackend)
            else pol.image
        )
        if build_deps and not image:
            effective_image = ensure_dependency_image(repo, base_image=effective_image)

        with AirGappedSidecars(services=services) as (net_name, svc_env):
            effective_pol = pol.model_copy(update={"image": effective_image})
            if isinstance(base_backend, DockerSandboxBackend):
                effective_backend: SandboxBackend = DockerSandboxBackend(
                    image=effective_image,
                    network_override=net_name,
                )
            else:
                effective_backend = base_backend
            yield effective_backend, effective_pol, svc_env

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
        build_deps: bool = False,
        image: str | None = None,
    ) -> tuple[AuditReport, dict[str, Path]]:
        repo = Path(repo_path).resolve()
        prof = profile_repo(repo)
        effective_check_leaks = check_leaks or deep
        effective_start = start_cmd or prof.start_command
        effective_health = health_path or prof.health_path
        memory_probes: list[MemoryLeakProbeResult] = []

        with self._execution_context(repo, build_deps=build_deps, image=image) as (
            exec_backend,
            exec_policy,
            _svc_env,
        ):
            with ScrubbedWorkspace(repo) as sws:
                cg = build_hybrid_call_graph(
                    sws.path,
                    profile=prof,
                    backend=exec_backend,
                    policy=exec_policy,
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
                                backend=exec_backend,
                                start_cmd=effective_start,
                                spec=mspec,
                                health_path=effective_health,
                                policy=exec_policy,
                                registry=self.registry,
                            )
                            memory_probes.append(mres)

                report = AuditReport(
                    tool_version=TOOL_VERSION,
                    timestamp=_utc_now(),
                    sandbox_backend=exec_backend.name,
                    profile=prof,
                    scrub_summary=sws.summary,
                    findings=findings,
                    call_graph_summary=cg.to_summary(),
                    memory_probes=memory_probes,
                )
                written = (
                    write_report_bundle(
                        report,
                        resolve_repo_output_dir(out_dir, repo),
                        registry=self.registry,
                    )
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
        build_deps: bool = False,
        image: str | None = None,
        mock_integrations: bool = True,
        mock_rules: list[MockRule] | None = None,
        mocks_strict: bool = False,
        services: list[str] | None = None,
        auth_header: str | None = None,
        auth_jwt_claims: str | dict[str, Any] | None = None,
    ) -> list[DynamicProbeResult]:
        repo = Path(repo_path).resolve()
        prof = profile_repo(repo)
        effective_start = start_cmd or prof.start_command
        effective_health = health_path or prof.health_path

        results: list[DynamicProbeResult] = []
        with self._execution_context(
            repo, build_deps=build_deps, image=image, services=services
        ) as (exec_backend, exec_policy, svc_env):
            with ScrubbedWorkspace(repo) as sws:
                auth_headers = resolve_auth_headers(
                    auth_header=auth_header,
                    auth_jwt_claims=auth_jwt_claims,
                    workspace_dir=sws.path,
                )
                for spec in specs:
                    results.append(
                        run_dynamic_probe(
                            sws.path,
                            backend=exec_backend,
                            start_cmd=effective_start,
                            spec=spec,
                            health_path=effective_health,
                            policy=exec_policy,
                            mock_integrations=mock_integrations,
                            mock_rules=mock_rules,
                            mocks_strict=mocks_strict,
                            extra_env=svc_env,
                            auth_headers=auth_headers,
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
        build_deps: bool = False,
        image: str | None = None,
        mock_integrations: bool = True,
        mock_rules: list[MockRule] | None = None,
        mocks_strict: bool = False,
        services: list[str] | None = None,
        auth_header: str | None = None,
        auth_jwt_claims: str | dict[str, Any] | None = None,
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

        with self._execution_context(
            repo, build_deps=build_deps, image=image, services=services
        ) as (exec_backend, exec_policy, svc_env):
            with ScrubbedWorkspace(repo) as sws:
                scrub = sws.summary
                cg = build_hybrid_call_graph(
                    sws.path,
                    profile=prof,
                    backend=exec_backend,
                    policy=exec_policy,
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
                        sws.path, prof, exec_backend, exec_policy
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
                            backend=exec_backend,
                            client=active_client,
                            policy=g_policy,
                            probe_spec=matched_probe,
                            start_cmd=start_cmd,
                            health_path=health_path,
                            advisories_path=advisories_path,
                            sandbox_policy=exec_policy,
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
                    backend=exec_backend,
                    finding=finding_map.get(p.finding_id),
                    probe_spec=p.probe_spec,
                    memory_probe_spec=p.memory_probe_spec,
                    check_leaks=effective_check_leaks,
                    call_graph=cg,
                    start_cmd=start_cmd,
                    health_path=health_path,
                    advisories_path=advisories_path,
                    policy=exec_policy,
                    registry=self.registry,
                    baseline_tests_override=baseline_tests_cache,
                    mock_integrations=mock_integrations,
                    mock_rules=mock_rules,
                    mocks_strict=mocks_strict,
                    extra_env=svc_env,
                    auth_header=auth_header,
                    auth_jwt_claims=auth_jwt_claims,
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
            write_report_bundle(
                report,
                resolve_repo_output_dir(out_dir, repo),
                registry=self.registry,
            )
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
        build_deps: bool = False,
        image: str | None = None,
        mock_integrations: bool = True,
        mock_rules: list[MockRule] | None = None,
        mocks_strict: bool = False,
        services: list[str] | None = None,
        auth_header: str | None = None,
        auth_jwt_claims: str | dict[str, Any] | None = None,
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
        with self._execution_context(
            repo, build_deps=build_deps, image=image, services=services
        ) as (exec_backend, exec_policy, svc_env):
            return verify_patch(
                repo_path=repo,
                profile=prof,
                patch=candidate,
                backend=exec_backend,
                probe_spec=probe_spec,
                start_cmd=start_cmd,
                health_path=health_path,
                policy=exec_policy,
                registry=self.registry,
                mock_integrations=mock_integrations,
                mock_rules=mock_rules,
                mocks_strict=mocks_strict,
                extra_env=svc_env,
                auth_header=auth_header,
                auth_jwt_claims=auth_jwt_claims,
            )
