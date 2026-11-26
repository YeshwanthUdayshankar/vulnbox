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
from vulnbox.engine import VulnBoxEngine
from vulnbox.llm import GuardrailPolicy, LLMConfig
from vulnbox.remediation import load_probe_specs
from vulnbox.sandbox import DockerSandboxBackend, LocalSandboxBackend
from vulnbox.ui import create_ui_server

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
    out: Path = typer.Option(Path("vulnbox-out"), "--out", help="Output directory for report bundle"),
) -> None:
    """Scrub a repository and run SAST, config hygiene, memory leak, and call-graph reachability analysis."""
    engine = VulnBoxEngine(backend=backend)
    report, written = engine.scan(
        repo,
        advisories_path=advisories,
        deep=deep,
        check_leaks=check_leaks,
        out_dir=out,
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


@app.command()
def probe(
    repo: Path = typer.Argument(..., exists=True, file_okay=False, resolve_path=True),
    probe_file: Path = typer.Option(..., "--probe", exists=True, help="JSON file with DynamicProbeSpec"),
    start_cmd: str | None = typer.Option(None, "--start-cmd", help="Override server start command"),
    health_path: str | None = typer.Option(None, "--health-path", help="Override healthcheck path"),
    backend: str = typer.Option("auto", "--backend", help="Sandbox backend: auto, docker, local"),
) -> None:
    """Start the repo inside a scrubbed sandbox on 127.0.0.1 and run active curl probes."""
    engine = VulnBoxEngine(backend=backend)
    specs = load_probe_specs(probe_file)
    try:
        results = engine.probe(repo, specs=specs, start_cmd=start_cmd, health_path=health_path)
    except ValueError as exc:
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(code=2) from exc

    any_error = False
    for res in results:
        console.print(f"[bold]Probe:[/bold] {res.probe_id}")
        console.print(f"  curl: {res.curl_command}")
        console.print(
            f"  HTTP {res.status_code} | matched_vulnerable={res.matched_vulnerable} | matched_fixed={res.matched_fixed}"
        )
        if res.error:
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
    llm: bool = typer.Option(False, "--llm", help="Enable guarded LLM synthesis for findings without deterministic patches"),
    llm_provider: str = typer.Option("ollama", "--llm-provider", help="LLM provider: ollama, openai, gemini, custom"),
    llm_model: str | None = typer.Option(None, "--llm-model", help="Override LLM model name"),
    llm_base_url: str | None = typer.Option(None, "--llm-base-url", help="Override OpenAI-compatible API base URL"),
    llm_max_retries: int = typer.Option(2, "--llm-max-retries", min=0, max=5, help="Max guarded LLM retry attempts per finding"),
    jobs: int = typer.Option(4, "--jobs", "-j", min=1, max=16, help="Max parallel sandbox patch verification workers"),
    out: Path = typer.Option(Path("vulnbox-out"), "--out", help="Output directory for report bundle"),
) -> None:
    """Run full end-to-end sandbox scan, active pre/post curl probing, patching, and dual verification."""
    engine = VulnBoxEngine(backend=backend)
    custom_probes = load_probe_specs(probe_file) if probe_file else []
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
    engine = VulnBoxEngine(backend=backend)
    diff_text = patch_file.read_text(encoding="utf-8")
    reg_path = f"tests/{test_file.name}" if test_file else None
    reg_code = test_file.read_text(encoding="utf-8") if test_file else None
    probe_spec = load_probe_specs(probe_file)[0] if probe_file else None

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


@app.command()
def ui(
    host: str = typer.Option("127.0.0.1", "--host", help="Bind host (loopback 127.0.0.1 recommended)"),
    port: int = typer.Option(8787, "--port", min=0, max=65535, help="Port to serve the local Web UI"),
    no_browser: bool = typer.Option(False, "--no-browser", help="Do not open a browser automatically"),
) -> None:
    """Launch the local CSRF-protected Web UI for all VulnBox workflows."""
    server = create_ui_server(host=host, port=port)
    bound_host, bound_port = server.server_address[:2]
    url = f"http://{bound_host}:{bound_port}"
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
