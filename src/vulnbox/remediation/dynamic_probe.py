"""Active loopback dynamic probe runner for live before/after sandbox verification."""

from __future__ import annotations

import json
import shlex
import shutil
import socket
import sys
from pathlib import Path
from typing import Any, Literal
from urllib.parse import urlparse

from vulnbox.models import (
    DynamicProbeResult,
    DynamicProbeSpec,
    Finding,
    MockRule,
    ProbeExpectation,
)
from vulnbox.registry import PluginRegistry, default_registry
from vulnbox.remediation.mock_inferrer import infer_mock_rules
from vulnbox.sandbox.base import SandboxBackend, SandboxPolicy

ALLOWED_LOOPBACK_HOSTS = {"127.0.0.1", "localhost", "::1"}
_REMEDIATION_DIR = Path(__file__).resolve().parent
_PROBE_WORKER_PATH = _REMEDIATION_DIR / "_probe_worker.py"
_INPROCESS_WORKER_PATH = _REMEDIATION_DIR / "_inprocess_probe_worker.py"
_MOCK_SERVER_PATH = _REMEDIATION_DIR / "_mock_server.py"
_SERVICE_SHIMS_PATH = _REMEDIATION_DIR / "_service_shims.py"
_PY_HTTP_PRELOAD_PATH = _REMEDIATION_DIR / "_py_http_mock_preload.py"
_NODE_HTTP_PRELOAD_PATH = _REMEDIATION_DIR / "_node_http_mock_preload.mjs"

_BOOT_SKIP_SIGNATURES: tuple[tuple[str, str], ...] = (
    ("ModuleNotFoundError", "missing Python dependency (run with --build-deps or --image)"),
    ("ImportError", "Python import error during boot (run with --build-deps or --image)"),
    ("ERR_MODULE_NOT_FOUND", "missing Node.js module (run with --build-deps or --image)"),
    ("Cannot find module", "missing Node.js dependency (run with --build-deps or --image)"),
    ("ECONNREFUSED", "external service connection refused (try --services or --mocks)"),
    ("ConnectionRefusedError", "external service connection refused (try --services or --mocks)"),
    ("OperationalError", "database connection unavailable during boot (try --services postgres)"),
    ("could not connect to server", "database server unreachable (try --services postgres)"),
    ("Temporary failure in name resolution", "external DNS unavailable inside air-gapped sandbox"),
    ("Name or service not known", "external hostname unavailable inside air-gapped sandbox"),
    ("getaddrinfo ENOTFOUND", "external hostname unavailable inside air-gapped sandbox"),
)


def classify_boot_skip_error(error_text: str | None) -> str | None:
    """Return a human-readable skip reason if server boot failed due to missing deps/services."""
    if not error_text:
        return None
    for marker, reason in _BOOT_SKIP_SIGNATURES:
        if marker in error_text:
            return f"Boot skipped: {reason} [{marker}]"
    return None


def validate_loopback_url(url: str) -> None:
    """Ensure a probe target URL strictly references loopback (127.0.0.1 / localhost)."""
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise ValueError(f"Unsupported URL scheme for sandbox probe: {parsed.scheme!r}")
    if parsed.hostname not in ALLOWED_LOOPBACK_HOSTS:
        raise ValueError(
            f"Refusing non-loopback probe target {parsed.hostname!r}. "
            "VulnBox active probes are strictly confined to localhost/127.0.0.1."
        )


def _pick_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def load_probe_specs(probe_path: Path) -> list[DynamicProbeSpec]:
    """Load one or more declarative DynamicProbeSpec definitions from JSON."""
    raw: Any = json.loads(probe_path.read_text(encoding="utf-8"))
    items = raw if isinstance(raw, list) else [raw]
    specs: list[DynamicProbeSpec] = []
    for item in items:
        spec = DynamicProbeSpec.model_validate(item)
        if not spec.path.startswith("/"):
            raise ValueError(f"Probe path must start with '/': {spec.path!r}")
        specs.append(spec)
    return specs


def _read_finding_source(finding: Finding, workspace_dir: Path) -> str | None:
    target_file = workspace_dir / finding.file_path
    if not target_file.is_file():
        return None
    return target_file.read_text(encoding="utf-8", errors="ignore")


@default_registry.register_probe("PY-YAML-001")
def _probe_py_yaml(finding: Finding, workspace_dir: Path) -> DynamicProbeSpec | None:
    source = _read_finding_source(finding, workspace_dir)
    if not source or "/parse" not in source:
        return None
    return DynamicProbeSpec(
        probe_id=f"probe-{finding.finding_id}",
        finding_id=finding.finding_id,
        rule_id=finding.rule_id,
        description=(
            "Send benign Python-tagged YAML ('!!python/tuple [1, 2]') to POST /parse "
            "to prove non-safe YAML loader acceptance pre-patch and rejection (HTTP 400) post-patch."
        ),
        method="POST",
        path="/parse",
        headers={"Content-Type": "text/plain"},
        body="!!python/tuple [1, 2]",
        vulnerable_expectation=ProbeExpectation(status_codes=[200]),
        fixed_expectation=ProbeExpectation(status_codes=[400, 422]),
    )


@default_registry.register_probe("PY-PATH-001", "JS-PATH-001")
def _probe_path_confinement(finding: Finding, workspace_dir: Path) -> DynamicProbeSpec | None:
    source = _read_finding_source(finding, workspace_dir)
    if not source or "/files" not in source:
        return None
    marker_name = "vulnbox_boundary_marker.txt"
    marker_val = "VULNBOX_BOUNDARY_MARKER_9F3A"
    return DynamicProbeSpec(
        probe_id=f"probe-{finding.finding_id}",
        finding_id=finding.finding_id,
        rule_id=finding.rule_id,
        description=(
            "Request a synthetic sibling boundary marker outside the configured public directory "
            "via GET /files?name=../vulnbox_boundary_marker.txt to verify path confinement."
        ),
        method="GET",
        path=f"/files?name=../{marker_name}",
        setup_marker_file=marker_name,
        setup_marker_content=marker_val,
        vulnerable_expectation=ProbeExpectation(status_codes=[200], body_contains=[marker_val]),
        fixed_expectation=ProbeExpectation(
            status_codes=[400, 403, 404], body_not_contains=[marker_val]
        ),
    )


@default_registry.register_probe("JS-CORS-001")
def _probe_js_cors(finding: Finding, workspace_dir: Path) -> DynamicProbeSpec | None:
    source = _read_finding_source(finding, workspace_dir)
    if not source or ("/api/data" not in source and "/health" not in source):
        return None
    route = "/api/data" if "/api/data" in source else "/health"
    return DynamicProbeSpec(
        probe_id=f"probe-{finding.finding_id}",
        finding_id=finding.finding_id,
        rule_id=finding.rule_id,
        description=(
            f"Send GET {route} with untrusted Origin header to verify permissive "
            "Access-Control-Allow-Origin + Access-Control-Allow-Credentials reflection."
        ),
        method="GET",
        path=route,
        headers={"Origin": "https://untrusted.example"},
        vulnerable_expectation=ProbeExpectation(
            status_codes=[200],
            headers_contain={"access-control-allow-credentials": "true"},
        ),
        fixed_expectation=ProbeExpectation(
            status_codes=[200],
            headers_not_contain={"access-control-allow-origin": "https://untrusted.example"},
        ),
    )


def infer_probe_for_finding(
    finding: Finding,
    workspace_dir: Path,
    registry: PluginRegistry | None = None,
) -> DynamicProbeSpec | None:
    """Dispatch loopback active probe inference via the plugin registry."""
    reg = registry or default_registry
    inferrer = reg.get_probe_inferrer(finding)
    if inferrer is None:
        return None
    return inferrer(finding, workspace_dir)


def _matches_cors_vulnerable(spec: DynamicProbeSpec, res_headers: dict[str, str]) -> bool:
    if spec.rule_id != "JS-CORS-001":
        return True
    acao = res_headers.get("access-control-allow-origin", "")
    acac = res_headers.get("access-control-allow-credentials", "").lower()
    untrusted = spec.headers.get("Origin", "https://untrusted.example")
    return acac == "true" and acao in ("*", untrusted)


def _matches_cors_fixed(spec: DynamicProbeSpec, res_headers: dict[str, str]) -> bool:
    if spec.rule_id != "JS-CORS-001":
        return True
    acao = res_headers.get("access-control-allow-origin", "")
    untrusted = spec.headers.get("Origin", "https://untrusted.example")
    return acao not in ("*", untrusted)


def _stage_mock_helpers(workspace_dir: Path) -> list[Path]:
    """Copy stdlib mock server, service shims, and HTTP preload hooks into workspace."""
    staged: list[Path] = []
    mock_srv_dst = workspace_dir / ".vulnbox_mock_server.py"
    mock_srv_dst.write_text(_MOCK_SERVER_PATH.read_text(encoding="utf-8"), encoding="utf-8")
    staged.append(mock_srv_dst)

    shims_dst = workspace_dir / ".vulnbox_service_shims.py"
    shims_dst.write_text(_SERVICE_SHIMS_PATH.read_text(encoding="utf-8"), encoding="utf-8")
    staged.append(shims_dst)

    py_preload_dir = workspace_dir / ".vulnbox_http_preload"
    py_preload_dir.mkdir(parents=True, exist_ok=True)
    site_dst = py_preload_dir / "sitecustomize.py"
    site_dst.write_text(_PY_HTTP_PRELOAD_PATH.read_text(encoding="utf-8"), encoding="utf-8")
    staged.append(py_preload_dir)

    node_preload_dst = workspace_dir / ".vulnbox_http_mock_preload.mjs"
    node_preload_dst.write_text(_NODE_HTTP_PRELOAD_PATH.read_text(encoding="utf-8"), encoding="utf-8")
    staged.append(node_preload_dst)
    return staged


def _cleanup_paths(paths: list[Path]) -> None:
    for p in paths:
        if not p.exists():
            continue
        try:
            if p.is_dir():
                shutil.rmtree(p, ignore_errors=True)
            else:
                p.unlink()
        except OSError:
            pass


def _build_probe_result(
    spec: DynamicProbeSpec,
    curl_command: str,
    exec_stdout: str,
    exec_stderr: str,
    exit_code: int,
    default_mode: Literal["http_server", "in_process"] = "http_server",
) -> DynamicProbeResult:
    if exit_code != 0 and not exec_stdout.strip():
        err_msg = f"Probe runner failed (rc={exit_code}): {exec_stderr.strip()}"
        skip_reason = classify_boot_skip_error(err_msg)
        return DynamicProbeResult(
            probe_id=spec.probe_id,
            curl_command=curl_command,
            skipped=skip_reason is not None,
            skip_reason=skip_reason,
            probe_mode=default_mode,
            error=err_msg,
        )

    try:
        json_line = [ln for ln in exec_stdout.splitlines() if ln.strip()][-1]
        data = json.loads(json_line)
    except (IndexError, json.JSONDecodeError) as exc:
        err_msg = f"Failed to parse probe JSON output: {exc}; raw={exec_stdout[:300]}"
        return DynamicProbeResult(
            probe_id=spec.probe_id,
            curl_command=curl_command,
            probe_mode=default_mode,
            error=err_msg,
        )

    status_code = data.get("status_code")
    res_headers: dict[str, str] = data.get("response_headers") or {}
    body_excerpt: str = data.get("response_body_excerpt") or ""
    err = data.get("error")
    skip_reason = classify_boot_skip_error(err) if status_code is None else None
    outbound_raw = data.get("outbound_calls") or []
    outbound_hosts = [str(c.get("host", "")) for c in outbound_raw if isinstance(c, dict)]

    matched_vuln = False
    matched_fixed = False
    if err is None:
        matched_vuln = spec.vulnerable_expectation.matches(
            status_code, res_headers, body_excerpt, outbound_hosts=outbound_hosts
        ) and _matches_cors_vulnerable(spec, res_headers)
        matched_fixed = spec.fixed_expectation.matches(
            status_code, res_headers, body_excerpt, outbound_hosts=outbound_hosts
        ) and _matches_cors_fixed(spec, res_headers)

    raw_mode = str(data.get("probe_mode") or default_mode)
    probe_mode: Literal["http_server", "in_process"] = (
        "in_process" if raw_mode == "in_process" else "http_server"
    )
    return DynamicProbeResult(
        probe_id=spec.probe_id,
        curl_command=curl_command,
        status_code=status_code,
        response_headers=res_headers,
        response_body_excerpt=body_excerpt,
        matched_vulnerable=matched_vuln,
        matched_fixed=matched_fixed,
        skipped=skip_reason is not None,
        skip_reason=skip_reason,
        outbound_calls=outbound_raw,
        probe_mode=probe_mode,
        error=err,
    )


def run_inprocess_probe(
    workspace_dir: Path,
    backend: SandboxBackend,
    spec: DynamicProbeSpec,
    policy: SandboxPolicy | None = None,
    mock_integrations: bool = True,
    mock_rules: list[MockRule] | None = None,
    mocks_strict: bool = False,
    extra_env: dict[str, str] | None = None,
    auth_headers: dict[str, str] | None = None,
) -> DynamicProbeResult:
    """Execute a probe directly in-process against a FastAPI/Starlette/Flask app."""
    if not spec.path.startswith("/"):
        raise ValueError(f"Probe path must start with '/': {spec.path!r}")

    curl_command = spec.to_curl("http://127.0.0.1:$PORT")
    effective_headers = {**(auth_headers or {}), **spec.headers}

    merged_rules: list[dict[str, Any]] = []
    if mock_integrations:
        user_rules = list(mock_rules or [])
        inferred = infer_mock_rules(workspace_dir)
        merged_rules = [r.model_dump() for r in (user_rules + inferred)]

    runner_script = workspace_dir / ".vulnbox_inprocess_runner.py"
    cfg_file = workspace_dir / ".vulnbox_inprocess_cfg.json"
    staged: list[Path] = [runner_script, cfg_file]
    cfg_payload = {
        "method": spec.method,
        "path": spec.path,
        "headers": effective_headers,
        "body": spec.body,
        "setup_marker_file": spec.setup_marker_file,
        "setup_marker_content": spec.setup_marker_content,
        "mock_integrations": mock_integrations,
        "mock_rules": merged_rules,
        "mocks_strict": mocks_strict,
    }

    py_exe = "python3" if backend.name == "docker" else sys.executable
    try:
        if mock_integrations:
            staged.extend(_stage_mock_helpers(workspace_dir))
        runner_script.write_text(_INPROCESS_WORKER_PATH.read_text(encoding="utf-8"), encoding="utf-8")
        cfg_file.write_text(json.dumps(cfg_payload), encoding="utf-8")
        cmd = f"{shlex.quote(py_exe)} .vulnbox_inprocess_runner.py .vulnbox_inprocess_cfg.json"
        exec_res = backend.run(
            workspace_dir,
            cmd,
            env=extra_env,
            policy=policy or SandboxPolicy(timeout_sec=30),
        )
    finally:
        _cleanup_paths(staged)

    return _build_probe_result(
        spec=spec,
        curl_command=curl_command,
        exec_stdout=exec_res.stdout,
        exec_stderr=exec_res.stderr,
        exit_code=exec_res.exit_code,
        default_mode="in_process",
    )


def run_dynamic_probe(
    workspace_dir: Path,
    backend: SandboxBackend,
    start_cmd: str | None,
    spec: DynamicProbeSpec,
    health_path: str = "/health",
    policy: SandboxPolicy | None = None,
    mock_integrations: bool = True,
    mock_rules: list[MockRule] | None = None,
    mocks_strict: bool = False,
    extra_env: dict[str, str] | None = None,
    auth_headers: dict[str, str] | None = None,
    allow_inprocess_fallback: bool = True,
) -> DynamicProbeResult:
    """Start the repo's app inside the sandbox on loopback and run the active curl probe.

    When `mock_integrations=True` (default), launches an in-sandbox expected-shape HTTP
    mock server + Python/Node outbound preload hooks + lightweight Redis/SMTP shims and
    records all outbound requests as an SSRF canary log.
    """
    if not spec.path.startswith("/"):
        raise ValueError(f"Probe path must start with '/': {spec.path!r}")

    if not start_cmd:
        if allow_inprocess_fallback:
            return run_inprocess_probe(
                workspace_dir=workspace_dir,
                backend=backend,
                spec=spec,
                policy=policy,
                mock_integrations=mock_integrations,
                mock_rules=mock_rules,
                mocks_strict=mocks_strict,
                extra_env=extra_env,
                auth_headers=auth_headers,
            )
        return DynamicProbeResult(
            probe_id=spec.probe_id,
            curl_command=spec.to_curl("http://127.0.0.1:$PORT"),
            skipped=True,
            skip_reason="No start command detected for active server probing",
            error="No start command configured",
        )

    port = _pick_free_port()
    base_url = f"http://127.0.0.1:{port}"
    validate_loopback_url(f"{base_url}{spec.path}")
    curl_command = spec.to_curl("http://127.0.0.1:$PORT")
    effective_headers = {**(auth_headers or {}), **spec.headers}

    merged_rules: list[dict[str, Any]] = []
    if mock_integrations:
        user_rules = list(mock_rules or [])
        inferred = infer_mock_rules(workspace_dir)
        merged_rules = [r.model_dump() for r in (user_rules + inferred)]

    runner_script = workspace_dir / ".vulnbox_probe_runner.py"
    cfg_file = workspace_dir / ".vulnbox_probe_cfg.json"
    staged: list[Path] = [runner_script, cfg_file]
    cfg_payload = {
        "start_cmd": start_cmd,
        "port": port,
        "health_path": health_path,
        "method": spec.method,
        "path": spec.path,
        "headers": effective_headers,
        "body": spec.body,
        "setup_marker_file": spec.setup_marker_file,
        "setup_marker_content": spec.setup_marker_content,
        "mock_integrations": mock_integrations,
        "mock_rules": merged_rules,
        "mocks_strict": mocks_strict,
        "extra_env": extra_env or {},
    }

    worker_source = _PROBE_WORKER_PATH.read_text(encoding="utf-8")
    py_exe = "python3" if backend.name == "docker" else sys.executable
    try:
        if mock_integrations:
            staged.extend(_stage_mock_helpers(workspace_dir))
        runner_script.write_text(worker_source, encoding="utf-8")
        cfg_file.write_text(json.dumps(cfg_payload), encoding="utf-8")
        cmd = f"{shlex.quote(py_exe)} .vulnbox_probe_runner.py .vulnbox_probe_cfg.json"
        exec_res = backend.run(
            workspace_dir,
            cmd,
            env=extra_env,
            policy=policy or SandboxPolicy(timeout_sec=30),
        )
    finally:
        _cleanup_paths(staged)

    result = _build_probe_result(
        spec=spec,
        curl_command=curl_command,
        exec_stdout=exec_res.stdout,
        exec_stderr=exec_res.stderr,
        exit_code=exec_res.exit_code,
        default_mode="http_server",
    )

    if (
        allow_inprocess_fallback
        and result.status_code is None
        and result.error
        and not result.skipped
    ):
        fallback = run_inprocess_probe(
            workspace_dir=workspace_dir,
            backend=backend,
            spec=spec,
            policy=policy,
            mock_integrations=mock_integrations,
            mock_rules=mock_rules,
            mocks_strict=mocks_strict,
            extra_env=extra_env,
            auth_headers=auth_headers,
        )
        if fallback.status_code is not None:
            return fallback

    return result
