"""Thin Typer CLI presentation layer delegating orchestration to VulnBoxEngine."""

from __future__ import annotations

import json
import shutil
import sys
import webbrowser
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from vulnbox import __version__
from vulnbox.analyzers.advisory_feed import sync_advisory_cache
from vulnbox.engine import VulnBoxEngine
from vulnbox.llm import GuardrailPolicy, LLMConfig
from vulnbox.mcp_server import serve_mcp_stdio
from vulnbox.remediation import load_mock_rules, load_probe_specs
from vulnbox.sandbox import (
    DockerSandboxBackend,
    LocalSandboxBackend,
    prune_dependency_images,
)
from vulnbox.suppressions import should_fail_ci
from vulnbox.ui import create_ui_server


def _parse_services_opt(services: str | None) -> list[str]:
    if not services:
        return []
    return [s.strip().lower() for s in services.split(",") if s.strip()]

app = typer.Typer(
    name="vulnbox",
    help="Sandboxed security testing, active loopback verification, and dual-verified patching.",
    no_args_is_help=True,
)
console = Console()


@app.command()
def doctor() -> None:
    """Check local toolchains, curl, and Docker/local sandbox readiness."""
    docker_ok = DockerSandboxBackend().is_available()
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
    prof = VulnBoxEngine(backend="local").profile(repo)
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
    deep: bool = typer.Option(
        False,
        "--deep",
        help="Enable sandbox runtime call-graph tracing (sys.monitoring / V8 Inspector) and dynamic memory/FD leak probing",
    ),
    check_leaks: bool = typer.Option(
        False,
        "--check-leaks",
        help="Run active loopback memory & file-descriptor stress probes for detected leak findings",
    ),
    build_deps: bool = typer.Option(
        False,
        "--build-deps",
        help="Build & cache a manifest-only Docker dependency layer (vulnbox-deps:<hash>)",
    ),
    image: str | None = typer.Option(
        None, "--image", help="Custom pre-built Docker image tag for sandbox execution"
    ),
    advisory_cache: Path | None = typer.Option(
        None, "--advisory-cache", help="Offline advisory cache directory (OSV/KEV/EPSS)"
    ),
    baseline: Path | None = typer.Option(
        None, "--baseline", exists=True, help="Baseline JSON file of accepted finding fingerprints"
    ),
    write_baseline_path: Path | None = typer.Option(
        None, "--write-baseline", help="Write current finding fingerprints to a baseline JSON file"
    ),
    fail_on: str | None = typer.Option(
        None,
        "--fail-on",
        help="Exit non-zero if any finding meets or exceeds severity (low, medium, high, critical)",
    ),
    out: Path = typer.Option(Path("vulnbox-out"), "--out", help="Output directory for report bundle"),
) -> None:
    """Scrub a repository and run SAST, config hygiene, memory leak, and call-graph reachability analysis."""
    engine = VulnBoxEngine(backend=backend, image=image or "vulnbox-sandbox:latest")
    report, written = engine.scan(
        repo,
        advisories_path=advisories,
        deep=deep,
        check_leaks=check_leaks,
        out_dir=out,
        build_deps=build_deps,
        image=image,
        advisory_cache_dir=advisory_cache,
        baseline_path=baseline,
        write_baseline_path=write_baseline_path,
    )

    console.print(f"[bold]Scan complete[/bold]: {len(report.findings)} findings found.")
    if report.call_graph_summary is not None:
        cg = report.call_graph_summary
        console.print(
            f"Call graph:      {cg.total_nodes} nodes, {cg.total_edges} edges "
            f"(runtime_resolved={cg.runtime_resolved_count}, unresolved={len(cg.unresolved_sites)})"
        )
    if report.memory_probes:
        leaked = sum(1 for m in report.memory_probes if m.leak_detected)
        console.print(f"Memory probes:   {leaked}/{len(report.memory_probes)} confirmed active leaks")
    console.print(f"Markdown report: {written['markdown']}")
    console.print(f"SARIF 2.1.0:     {written['sarif']}")
    if "openvex" in written:
        console.print(f"OpenVEX v0.2.0:  {written['openvex']}")
    if "cyclonedx_vex" in written:
        console.print(f"CycloneDX VEX:   {written['cyclonedx_vex']}")

    if should_fail_ci(report.findings, fail_on):
        console.print(f"[bold red]CI Gate failed[/bold red]: finding(s) >= {fail_on} severity.")
        raise typer.Exit(code=1)


@app.command()
def probe(
    repo: Path = typer.Argument(..., exists=True, file_okay=False, resolve_path=True),
    probe_file: Path = typer.Option(..., "--probe", exists=True, help="JSON file with DynamicProbeSpec"),
    start_cmd: str | None = typer.Option(None, "--start-cmd", help="Override server start command"),
    health_path: str | None = typer.Option(None, "--health-path", help="Override healthcheck path"),
    backend: str = typer.Option("auto", "--backend", help="Sandbox backend: auto, docker, local"),
    build_deps: bool = typer.Option(
        False,
        "--build-deps",
        help="Build & cache a manifest-only Docker dependency layer (vulnbox-deps:<hash>)",
    ),
    image: str | None = typer.Option(
        None, "--image", help="Custom pre-built Docker image tag for sandbox execution"
    ),
    mocks: Path | None = typer.Option(
        None, "--mocks", exists=True, help="Optional JSON file with explicit MockRule overrides"
    ),
    mocks_strict: bool = typer.Option(
        False, "--mocks-strict", help="Return HTTP 502 for unmocked outbound calls instead of inferred 200"
    ),
    mock_integrations: bool = typer.Option(
        True,
        "--mock-integrations/--no-mock-integrations",
        help="Auto-mock outbound HTTP/HTTPS integrations with expected-shape 200 responses + Redis/SMTP shims",
    ),
    services: str | None = typer.Option(
        None, "--services", help="Comma-separated air-gapped Docker sidecars (e.g. postgres,redis)"
    ),
    auth_header: str | None = typer.Option(
        None, "--auth-header", help="Optional auth header for probed routes (e.g. 'Authorization: Bearer ...')"
    ),
    auth_jwt_claims: str | None = typer.Option(
        None,
        "--auth-jwt-claims",
        help="JSON claims object to mint an HS256 test JWT signed with the sandbox dummy secret",
    ),
) -> None:
    """Start the repo inside a scrubbed sandbox on 127.0.0.1 and run active curl probes."""
    engine = VulnBoxEngine(backend=backend, image=image or "vulnbox-sandbox:latest")
    specs = load_probe_specs(probe_file)
    mock_rules = load_mock_rules(mocks) if mocks else None
    try:
        results = engine.probe(
            repo,
            specs=specs,
            start_cmd=start_cmd,
            health_path=health_path,
            build_deps=build_deps,
            image=image,
            mock_integrations=mock_integrations,
            mock_rules=mock_rules,
            mocks_strict=mocks_strict,
            services=_parse_services_opt(services),
            auth_header=auth_header,
            auth_jwt_claims=auth_jwt_claims,
        )
    except ValueError as exc:
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(code=2) from exc

    any_error = False
    for res in results:
        console.print(f"[bold]Probe:[/bold] {res.probe_id} (mode={res.probe_mode})")
        console.print(f"  curl: {res.curl_command}")
        if res.skipped:
            console.print(f"  [yellow]SKIPPED: {res.skip_reason}[/yellow]")
        else:
            console.print(
                f"  HTTP {res.status_code} | matched_vulnerable={res.matched_vulnerable} | matched_fixed={res.matched_fixed}"
            )
        if res.outbound_calls:
            hosts = ", ".join(sorted({c.host for c in res.outbound_calls}))
            console.print(
                f"  [cyan]Intercepted outbound calls ({len(res.outbound_calls)}): {hosts}[/cyan]"
            )
        if res.error and not res.skipped:
            console.print(f"  [red]error: {res.error}[/red]")
            any_error = True

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
    deep: bool = typer.Option(
        False,
        "--deep",
        help="Enable sandbox runtime call-graph tracing and active before/after memory & FD leak verification",
    ),
    check_leaks: bool = typer.Option(
        False,
        "--check-leaks",
        help="Enable active before/after heap slope and file-descriptor leak verification",
    ),
    build_deps: bool = typer.Option(
        False,
        "--build-deps",
        help="Build & cache a manifest-only Docker dependency layer (vulnbox-deps:<hash>)",
    ),
    image: str | None = typer.Option(
        None, "--image", help="Custom pre-built Docker image tag for sandbox execution"
    ),
    mocks: Path | None = typer.Option(
        None, "--mocks", exists=True, help="Optional JSON file with explicit MockRule overrides"
    ),
    mocks_strict: bool = typer.Option(
        False, "--mocks-strict", help="Return HTTP 502 for unmocked outbound calls instead of inferred 200"
    ),
    mock_integrations: bool = typer.Option(
        True,
        "--mock-integrations/--no-mock-integrations",
        help="Auto-mock outbound HTTP/HTTPS integrations with expected-shape 200 responses + Redis/SMTP shims",
    ),
    services: str | None = typer.Option(
        None, "--services", help="Comma-separated air-gapped Docker sidecars (e.g. postgres,redis)"
    ),
    auth_header: str | None = typer.Option(
        None, "--auth-header", help="Optional auth header for probed routes"
    ),
    auth_jwt_claims: str | None = typer.Option(
        None,
        "--auth-jwt-claims",
        help="JSON claims object to mint an HS256 test JWT signed with the sandbox dummy secret",
    ),
    llm: bool = typer.Option(False, "--llm", help="Enable guarded LLM synthesis for findings without deterministic patches"),
    llm_provider: str = typer.Option("ollama", "--llm-provider", help="LLM provider: ollama, openai, gemini, custom"),
    llm_model: str | None = typer.Option(None, "--llm-model", help="Override LLM model name"),
    llm_base_url: str | None = typer.Option(None, "--llm-base-url", help="Override OpenAI-compatible API base URL"),
    llm_max_retries: int = typer.Option(2, "--llm-max-retries", min=0, max=5, help="Max guarded LLM retry attempts per finding"),
    jobs: int = typer.Option(4, "--jobs", "-j", min=1, max=16, help="Max parallel sandbox patch verification workers"),
    out: Path = typer.Option(Path("vulnbox-out"), "--out", help="Output directory for report bundle"),
) -> None:
    """Run full end-to-end sandbox scan, active pre/post curl probing, patching, and dual verification."""
    engine = VulnBoxEngine(backend=backend, image=image or "vulnbox-sandbox:latest")
    custom_probes = load_probe_specs(probe_file) if probe_file else []
    mock_rules = load_mock_rules(mocks) if mocks else None
    llm_cfg = LLMConfig(provider=llm_provider, model=llm_model, base_url=llm_base_url) if llm else None

    report, written = engine.remediate(
        repo_path=repo,
        start_cmd=start_cmd,
        health_path=health_path,
        custom_probes=custom_probes,
        advisories_path=advisories,
        deep=deep,
        check_leaks=check_leaks,
        llm_config=llm_cfg,
        guardrail_policy=GuardrailPolicy(max_retries=llm_max_retries),
        max_workers=jobs,
        out_dir=out,
        build_deps=build_deps,
        image=image,
        mock_integrations=mock_integrations,
        mock_rules=mock_rules,
        mocks_strict=mocks_strict,
        services=_parse_services_opt(services),
        auth_header=auth_header,
        auth_jwt_claims=auth_jwt_claims,
    )

    verified_count = sum(1 for v in report.verifications if v.verified)
    active_count = sum(1 for v in report.verifications if v.dynamic_confirmed_and_fixed is True)
    mem_fixed = sum(1 for v in report.verifications if v.memory_leak_confirmed_and_fixed is True)
    blocked_count = sum(1 for g in report.guardrail_events if g.decision == "block")
    extra_parts: list[str] = []
    if mem_fixed:
        extra_parts.append(f"{mem_fixed} memory/FD leaks confirmed & fixed")
    if llm:
        extra_parts.append(f"{blocked_count} guardrail blocks")
    suffix = f", {', '.join(extra_parts)}." if extra_parts else "."
    console.print(
        f"[bold green]Remediation bundle complete[/bold green]: "
        f"{len(report.findings)} findings, {verified_count}/{len(report.patches)} verified patches, "
        f"{active_count} actively confirmed & fixed via live curl probe{suffix}"
    )
    console.print(f"Report:  {written['markdown']}")
    console.print(f"SARIF:   {written['sarif']}")
    console.print(f"Patches: {written['markdown'].parent / 'patches'}")


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
    build_deps: bool = typer.Option(
        False,
        "--build-deps",
        help="Build & cache a manifest-only Docker dependency layer (vulnbox-deps:<hash>)",
    ),
    image: str | None = typer.Option(
        None, "--image", help="Custom pre-built Docker image tag for sandbox execution"
    ),
    mocks: Path | None = typer.Option(
        None, "--mocks", exists=True, help="Optional JSON file with explicit MockRule overrides"
    ),
    mocks_strict: bool = typer.Option(
        False, "--mocks-strict", help="Return HTTP 502 for unmocked outbound calls instead of inferred 200"
    ),
    mock_integrations: bool = typer.Option(
        True,
        "--mock-integrations/--no-mock-integrations",
        help="Auto-mock outbound HTTP/HTTPS integrations with expected-shape 200 responses + Redis/SMTP shims",
    ),
    services: str | None = typer.Option(
        None, "--services", help="Comma-separated air-gapped Docker sidecars (e.g. postgres,redis)"
    ),
    auth_header: str | None = typer.Option(
        None, "--auth-header", help="Optional auth header for probed routes"
    ),
    auth_jwt_claims: str | None = typer.Option(
        None,
        "--auth-jwt-claims",
        help="JSON claims object to mint an HS256 test JWT signed with the sandbox dummy secret",
    ),
    as_json: bool = typer.Option(False, "--json", help="Emit JSON result"),
) -> None:
    """Verify an external or agent-authored patch inside a scrubbed sandbox (exit 0 iff verified)."""
    engine = VulnBoxEngine(backend=backend, image=image or "vulnbox-sandbox:latest")
    diff_text = patch_file.read_text(encoding="utf-8")
    reg_path = f"tests/{test_file.name}" if test_file else None
    reg_code = test_file.read_text(encoding="utf-8") if test_file else None
    probe_spec = load_probe_specs(probe_file)[0] if probe_file else None
    mock_rules = load_mock_rules(mocks) if mocks else None

    result = engine.verify_external_patch(
        repo_path=repo,
        unified_diff=diff_text,
        finding_id=finding_id,
        rule_id=rule_id,
        regression_test_path=reg_path,
        regression_test_code=reg_code,
        probe_spec=probe_spec,
        start_cmd=start_cmd,
        health_path=health_path,
        description=f"External patch from {patch_file.name}",
        build_deps=build_deps,
        image=image,
        mock_integrations=mock_integrations,
        mock_rules=mock_rules,
        mocks_strict=mocks_strict,
        services=_parse_services_opt(services),
        auth_header=auth_header,
        auth_jwt_claims=auth_jwt_claims,
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


@app.command("sync-advisories")
def sync_advisories_cmd(
    repo: Path | None = typer.Argument(
        None,
        exists=True,
        file_okay=False,
        resolve_path=True,
        help="Optional repository whose lockfile dependencies will be queried against OSV.dev",
    ),
    cache_dir: Path | None = typer.Option(
        None, "--cache-dir", help="Directory to store offline OSV/KEV/EPSS JSON caches"
    ),
    no_kev: bool = typer.Option(False, "--no-kev", help="Skip syncing CISA KEV catalog"),
    no_epss: bool = typer.Option(False, "--no-epss", help="Skip syncing FIRST EPSS scores"),
) -> None:
    """Sync OSV.dev, CISA KEV, and FIRST EPSS feeds to a local offline cache for air-gapped scans."""
    summary = sync_advisory_cache(
        repo_path=repo,
        cache_dir=cache_dir,
        include_kev=not no_kev,
        include_epss=not no_epss,
    )
    console.print(
        f"[bold green]Offline advisory cache updated[/bold green] at {summary['cache_dir']}: "
        f"{summary['osv_advisories_cached']} OSV advisories, "
        f"{summary['kev_cves_cached']} CISA KEV CVEs, "
        f"{summary['epss_scores_cached']} EPSS scores."
    )


@app.command("clean-cache")
def clean_cache() -> None:
    """Remove locally cached VulnBox Docker dependency images (vulnbox-deps:*)."""
    removed = prune_dependency_images()
    if removed:
        console.print(f"[green]Removed {len(removed)} cached dependency image(s):[/green] {', '.join(removed)}")
    else:
        console.print("No cached vulnbox-deps:* Docker images found.")


@app.command("mcp")
def mcp_cmd() -> None:
    """Start the stdio MCP (Model Context Protocol) server exposing scan, probe, and verify-patch tools."""
    serve_mcp_stdio()


@app.command()
def ui(
    host: str = typer.Option("127.0.0.1", "--host", help="Bind host (loopback 127.0.0.1 recommended)"),
    port: int = typer.Option(8787, "--port", min=0, max=65535, help="Port to serve the local Web UI"),
    no_browser: bool = typer.Option(False, "--no-browser", help="Do not open a browser automatically"),
) -> None:
    """Launch the local CSRF-protected Web UI for all VulnBox workflows."""
    server = create_ui_server(host=host, port=port)
    bound_host, bound_port = server.server_address[:2]
    host_str = bound_host.decode("utf-8") if isinstance(bound_host, bytes) else str(bound_host)
    url = f"http://{host_str}:{bound_port}"
    console.print(f"[bold green]VulnBox Web UI running[/bold green] at [bold]{url}[/bold]")
    console.print("Press Ctrl+C to stop.")
    if not no_browser:
        webbrowser.open(url)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        console.print("\nShutting down VulnBox Web UI.")
    finally:
        server.server_close()


if __name__ == "__main__":
    app()
