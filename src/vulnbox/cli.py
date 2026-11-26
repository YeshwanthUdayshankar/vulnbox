"""Typer CLI for VulnBox."""

from __future__ import annotations

import json
import shutil
import sys
from datetime import UTC, datetime
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from vulnbox import __version__
from vulnbox.analyzers import run_all_analyzers
from vulnbox.llm import (
    GuardrailPolicy,
    LLMConfig,
    OpenAICompatLLMClient,
    synthesize_and_verify_patch,
)
from vulnbox.models import AuditReport, GuardrailEvent, PatchCandidate
from vulnbox.profiler import profile_repo
from vulnbox.remediation import (
    generate_patch_for_finding,
    generate_regression_test,
    infer_probe_for_finding,
    load_probe_specs,
    run_dynamic_probe,
    verify_patch,
)
from vulnbox.reporting import write_report_bundle
from vulnbox.sandbox import DockerSandboxBackend, LocalSandboxBackend, select_backend
from vulnbox.scrubber import cleanup_workspace, create_scrubbed_workspace

app = typer.Typer(
    name="vulnbox",
    help="Sandboxed security testing, active loopback verification, and dual-verified patching.",
    no_args_is_help=True,
)
console = Console()


def _utc_now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


@app.command()
def doctor() -> None:
    """Check local toolchains, curl, and Docker/local sandbox readiness."""
    docker_be = DockerSandboxBackend()
    docker_ok = docker_be.is_available()
    local_ok = LocalSandboxBackend().is_available()

    table = Table(title=f"VulnBox v{__version__} Environment Check")
    table.add_column("Component", style="bold")
    table.add_column("Status")
    table.add_column("Details")

    table.add_row("Python", "OK", sys.version.split()[0])
    table.add_row("Node.js", "OK" if shutil.which("node") else "MISSING", shutil.which("node") or "not found")
    table.add_row("curl", "OK" if shutil.which("curl") else "FALLBACK", shutil.which("curl") or "urllib fallback")
    table.add_row(
        "Docker Sandbox",
        "READY" if docker_ok else "UNAVAILABLE",
        "Docker daemon reachable" if docker_ok else "Daemon unavailable (use --backend local or start Docker)",
    )
    table.add_row("Local Isolated Sandbox", "READY" if local_ok else "ERROR", "Stripped env + rlimits + temp copy")
    console.print(table)


@app.command()
def profile(
    repo: Path = typer.Argument(..., exists=True, file_okay=False, resolve_path=True),
    as_json: bool = typer.Option(False, "--json", help="Print JSON output"),
) -> None:
    """Profile a repository (ecosystem, manifests, test commands, runnable start command)."""
    prof = profile_repo(repo)
    if as_json:
        typer.echo(prof.model_dump_json(indent=2))
        return

    table = Table(title="Repository Profile")
    table.add_column("Field", style="bold")
    table.add_column("Value")
    table.add_row("Path", prof.repo_path)
    table.add_row("Ecosystem", prof.ecosystem)
    table.add_row("Manifests", ", ".join(prof.manifests) or "-")
    table.add_row("Frameworks", ", ".join(prof.frameworks) or "-")
    table.add_row("Dockerfiles", ", ".join(prof.dockerfiles) or "-")
    table.add_row("Env Files", ", ".join(prof.env_files) or "-")
    table.add_row("Test Commands", json.dumps(prof.test_commands) if prof.test_commands else "-")
    table.add_row("Inferred Start Command", prof.start_command or "-")
    table.add_row("Health Path", prof.health_path)
    console.print(table)


@app.command()
def scan(
    repo: Path = typer.Argument(..., exists=True, file_okay=False, resolve_path=True),
    backend: str = typer.Option("auto", "--backend", help="Sandbox backend: auto, docker, local"),
    advisories: Path | None = typer.Option(None, "--advisories", help="Optional JSON advisory file"),
    out: Path = typer.Option(Path("vulnbox-out"), "--out", help="Output directory for report bundle"),
) -> None:
    """Scrub a repository and run SAST, config hygiene, and dependency reachability analysis."""
    be = select_backend(backend)
    prof = profile_repo(repo)
    scrub = create_scrubbed_workspace(repo)
    ws = Path(scrub.sandbox_dir)
    try:
        findings = run_all_analyzers(ws, scrub_summary=scrub, advisories_path=advisories)
        report = AuditReport(
            tool_version=__version__,
            timestamp=_utc_now(),
            sandbox_backend=be.name,
            profile=prof,
            scrub_summary=scrub,
            findings=findings,
        )
        written = write_report_bundle(report, out)
    finally:
        cleanup_workspace(ws)

    console.print(f"[bold]Scan complete[/bold]: {len(findings)} findings found.")
    console.print(f"Markdown report: {written['markdown']}")
    console.print(f"SARIF 2.1.0:     {written['sarif']}")


@app.command()
def probe(
    repo: Path = typer.Argument(..., exists=True, file_okay=False, resolve_path=True),
    probe_file: Path = typer.Option(..., "--probe", exists=True, help="JSON file with DynamicProbeSpec"),
    start_cmd: str | None = typer.Option(None, "--start-cmd", help="Override server start command"),
    health_path: str | None = typer.Option(None, "--health-path", help="Override healthcheck path"),
    backend: str = typer.Option("auto", "--backend", help="Sandbox backend: auto, docker, local"),
) -> None:
    """Start the repo inside a scrubbed sandbox on 127.0.0.1 and run active curl probes."""
    be = select_backend(backend)
    prof = profile_repo(repo)
    effective_start = start_cmd or prof.start_command
    if not effective_start:
        console.print("[red]No runnable server start command detected. Pass --start-cmd.[/red]")
        raise typer.Exit(code=2)

    specs = load_probe_specs(probe_file)
    scrub = create_scrubbed_workspace(repo)
    ws = Path(scrub.sandbox_dir)
    any_error = False
    try:
        for spec in specs:
            res = run_dynamic_probe(
                ws,
                backend=be,
                start_cmd=effective_start,
                spec=spec,
                health_path=health_path or prof.health_path,
            )
            console.print(f"[bold]Probe:[/bold] {res.probe_id}")
            console.print(f"  curl: {res.curl_command}")
            console.print(
                f"  HTTP {res.status_code} | matched_vulnerable={res.matched_vulnerable} | matched_fixed={res.matched_fixed}"
            )
            if res.error:
                console.print(f"  [red]error: {res.error}[/red]")
                any_error = True
    finally:
        cleanup_workspace(ws)

    if any_error:
        raise typer.Exit(code=1)


@app.command()
def remediate(
    repo: Path = typer.Argument(..., exists=True, file_okay=False, resolve_path=True),
    backend: str = typer.Option("auto", "--backend", help="Sandbox backend: auto, docker, local"),
    start_cmd: str | None = typer.Option(None, "--start-cmd", help="Override server start command"),
    health_path: str | None = typer.Option(None, "--health-path", help="Override healthcheck path"),
    probe_file: Path | None = typer.Option(None, "--probe", help="Optional custom JSON probe spec(s)"),
    advisories: Path | None = typer.Option(None, "--advisories", help="Optional JSON advisory file"),
    llm: bool = typer.Option(False, "--llm", help="Enable guarded LLM synthesis for findings without deterministic patches"),
    llm_provider: str = typer.Option("ollama", "--llm-provider", help="LLM provider: ollama, openai, gemini, custom"),
    llm_model: str | None = typer.Option(None, "--llm-model", help="Override LLM model name"),
    llm_base_url: str | None = typer.Option(None, "--llm-base-url", help="Override OpenAI-compatible API base URL"),
    llm_max_retries: int = typer.Option(2, "--llm-max-retries", min=0, max=5, help="Max guarded LLM retry attempts per finding"),
    out: Path = typer.Option(Path("vulnbox-out"), "--out", help="Output directory for report bundle"),
) -> None:
    """Run full end-to-end sandbox scan, active pre/post curl probing, patching, and dual verification."""
    be = select_backend(backend)
    prof = profile_repo(repo)
    custom_probes = load_probe_specs(probe_file) if probe_file else []

    llm_cfg = LLMConfig(provider=llm_provider, model=llm_model, base_url=llm_base_url) if llm else None
    llm_client = OpenAICompatLLMClient(llm_cfg) if llm_cfg else None
    guardrail_policy = GuardrailPolicy(max_retries=llm_max_retries)
    guardrail_events: list[GuardrailEvent] = []

    scrub = create_scrubbed_workspace(repo)
    ws = Path(scrub.sandbox_dir)
    patches: list[PatchCandidate] = []
    verifications = []
    unpatched_findings = []

    try:
        findings = run_all_analyzers(ws, scrub_summary=scrub, advisories_path=advisories)
        for f in findings:
            patch = generate_patch_for_finding(f, ws)
            if patch is None:
                if f.category != "secret":
                    unpatched_findings.append(f)
                continue
            reg = generate_regression_test(f)
            if reg:
                patch.regression_test_path, patch.regression_test_code = reg

            matched_probe = next(
                (p for p in custom_probes if p.finding_id == f.finding_id or p.rule_id == f.rule_id),
                None,
            )
            if matched_probe is None:
                matched_probe = infer_probe_for_finding(f, ws)
            patch.probe_spec = matched_probe
            patches.append(patch)

        # Optional guarded LLM synthesis for findings without deterministic auto-patches
        if llm_client is not None and unpatched_findings:
            for f in unpatched_findings:
                matched_probe = next(
                    (p for p in custom_probes if p.finding_id == f.finding_id or p.rule_id == f.rule_id),
                    None,
                )
                cand, ver, evs = synthesize_and_verify_patch(
                    repo_path=repo,
                    workspace_dir=ws,
                    profile=prof,
                    finding=f,
                    backend=be,
                    client=llm_client,
                    policy=guardrail_policy,
                    probe_spec=matched_probe,
                    start_cmd=start_cmd,
                    health_path=health_path,
                    advisories_path=advisories,
                )
                guardrail_events.extend(evs)
                if cand is not None:
                    patches.append(cand)
                if ver is not None:
                    verifications.append(ver)
    finally:
        cleanup_workspace(ws)

    finding_map = {f.finding_id: f for f in findings}
    already_verified_ids = {v.finding_id for v in verifications}
    for patch in patches:
        if patch.finding_id in already_verified_ids:
            continue
        ver = verify_patch(
            repo_path=repo,
            profile=prof,
            patch=patch,
            backend=be,
            finding=finding_map.get(patch.finding_id),
            probe_spec=patch.probe_spec,
            start_cmd=start_cmd,
            health_path=health_path,
            advisories_path=advisories,
        )
        verifications.append(ver)

    report = AuditReport(
        tool_version=__version__,
        timestamp=_utc_now(),
        sandbox_backend=be.name,
        profile=prof,
        scrub_summary=scrub,
        findings=findings,
        patches=patches,
        verifications=verifications,
        llm_enabled=llm,
        llm_model=llm_cfg.resolved_model() if llm_cfg else None,
        guardrail_events=guardrail_events,
    )
    written = write_report_bundle(report, out)

    verified_count = sum(1 for v in verifications if v.verified)
    active_count = sum(1 for v in verifications if v.dynamic_confirmed_and_fixed is True)
    blocked_count = sum(1 for g in guardrail_events if g.decision == "block")
    console.print(
        f"[bold green]Remediation bundle complete[/bold green]: "
        f"{len(findings)} findings, {verified_count}/{len(patches)} verified patches, "
        f"{active_count} actively confirmed & fixed via live curl probe"
        + (f", {blocked_count} guardrail blocks." if llm else ".")
    )
    console.print(f"Report:  {written['markdown']}")
    console.print(f"SARIF:   {written['sarif']}")
    console.print(f"Patches: {out.resolve() / 'patches'}")


@app.command("verify-patch")
def verify_patch_cmd(
    repo: Path = typer.Argument(..., exists=True, file_okay=False, resolve_path=True),
    patch_file: Path = typer.Option(..., "--patch", exists=True, help="Path to unified diff .patch file"),
    finding_id: str = typer.Option("CUSTOM-001", "--finding-id", help="Finding ID being fixed"),
    rule_id: str = typer.Option("CUSTOM", "--rule-id", help="Rule ID being fixed"),
    test_file: Path | None = typer.Option(None, "--test-file", exists=True, help="Optional regression test file"),
    probe_file: Path | None = typer.Option(None, "--probe", exists=True, help="Optional JSON probe spec"),
    start_cmd: str | None = typer.Option(None, "--start-cmd", help="Override server start command"),
    health_path: str | None = typer.Option(None, "--health-path", help="Override healthcheck path"),
    backend: str = typer.Option("auto", "--backend", help="Sandbox backend: auto, docker, local"),
    as_json: bool = typer.Option(False, "--json", help="Emit JSON result"),
) -> None:
    """Verify an external or agent-authored patch inside a scrubbed sandbox (exit 0 iff verified)."""
    be = select_backend(backend)
    prof = profile_repo(repo)
    diff_text = patch_file.read_text(encoding="utf-8")

    reg_path: str | None = None
    reg_code: str | None = None
    if test_file:
        reg_path = f"tests/{test_file.name}"
        reg_code = test_file.read_text(encoding="utf-8")

    probe_spec = load_probe_specs(probe_file)[0] if probe_file else None
    candidate = PatchCandidate(
        patch_id=f"patch-{finding_id}",
        finding_id=finding_id,
        rule_id=rule_id,
        strategy="agent_supplied",
        description=f"External patch from {patch_file.name}",
        unified_diff=diff_text,
        regression_test_path=reg_path,
        regression_test_code=reg_code,
        probe_spec=probe_spec,
    )

    result = verify_patch(
        repo_path=repo,
        profile=prof,
        patch=candidate,
        backend=be,
        probe_spec=probe_spec,
        start_cmd=start_cmd,
        health_path=health_path,
    )

    if as_json:
        typer.echo(result.model_dump_json(indent=2))
    else:
        status = "[bold green]VERIFIED[/bold green]" if result.verified else "[bold red]UNVERIFIED[/bold red]"
        console.print(f"Patch {result.patch_id}: {status} ({result.summary})")
        if result.dynamic_probe_before:
            console.print(f"  Active curl: {result.dynamic_probe_before.curl_command}")
            console.print(
                f"  Pre-patch:  HTTP {result.dynamic_probe_before.status_code} (vulnerable={result.dynamic_probe_before.matched_vulnerable})"
            )
        if result.dynamic_probe_after:
            console.print(
                f"  Post-patch: HTTP {result.dynamic_probe_after.status_code} (fixed={result.dynamic_probe_after.matched_fixed})"
            )

    if not result.verified:
        raise typer.Exit(code=1)


if __name__ == "__main__":
    app()
