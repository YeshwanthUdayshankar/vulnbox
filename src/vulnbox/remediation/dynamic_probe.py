"""Active loopback dynamic probe runner for live before/after sandbox verification."""

from __future__ import annotations

import json
import shlex
import socket
import sys
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from vulnbox.models import (
    DynamicProbeResult,
    DynamicProbeSpec,
    Finding,
    ProbeExpectation,
)
from vulnbox.registry import PluginRegistry, default_registry
from vulnbox.sandbox.base import SandboxBackend, SandboxPolicy

ALLOWED_LOOPBACK_HOSTS = {"127.0.0.1", "localhost", "::1"}

# Standalone script executed INSIDE the isolated sandbox so both Docker (--network=none)
# and local sandboxes start the server, wait for healthcheck, run curl/HTTP against
# 127.0.0.1, and tear down the server process group cleanly.
_SANDBOX_PROBE_RUNNER = r'''
import json
import os
import signal
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

cfg = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
start_cmd = cfg["start_cmd"]
port = int(cfg["port"])
health_path = cfg["health_path"]
method = cfg["method"]
path = cfg["path"]
headers = cfg.get("headers") or {}
body = cfg.get("body")
marker_file = cfg.get("setup_marker_file")
marker_content = cfg.get("setup_marker_content") or ""

base_url = f"http://127.0.0.1:{port}"
created_marker = None
if marker_file:
    mp = Path(marker_file)
    if not mp.is_absolute():
        mp = Path.cwd() / mp
    mp.parent.mkdir(parents=True, exist_ok=True)
    mp.write_text(marker_content, encoding="utf-8")
    created_marker = mp

env = os.environ.copy()
env["HOST"] = "127.0.0.1"
env["PORT"] = str(port)

proc = subprocess.Popen(
    ["/bin/sh", "-c", start_cmd],
    env=env,
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
    text=True,
    start_new_session=True,
)

result = {
    "status_code": None,
    "response_headers": {},
    "response_body_excerpt": "",
    "error": None,
}


def parse_curl_http_output(raw: str):
    parts = raw.replace("\r\n", "\n").split("\n\n")
    # Handle 100-continue or multiple header blocks by taking the last HTTP/ header block
    header_idx = 0
    for idx, block in enumerate(parts):
        if block.startswith("HTTP/"):
            header_idx = idx
    header_block = parts[header_idx] if parts else ""
    body_text = "\n\n".join(parts[header_idx + 1 :]) if len(parts) > header_idx + 1 else ""
    lines = header_block.splitlines()
    status_code = None
    if lines:
        tokens = lines[0].split()
        if len(tokens) >= 2 and tokens[1].isdigit():
            status_code = int(tokens[1])
    hdrs = {}
    for line in lines[1:]:
        if ":" in line:
            k, v = line.split(":", 1)
            hdrs[k.strip().lower()] = v.strip()
    return status_code, hdrs, body_text


try:
    ready = False
    deadline = time.monotonic() + 10.0
    health_url = f"{base_url}{health_path}"
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            out, err = proc.communicate(timeout=1)
            result["error"] = f"Server exited early (rc={proc.returncode}): {err or out}"
            break
        try:
            with urllib.request.urlopen(health_url, timeout=0.5) as resp:
                if resp.status < 500:
                    ready = True
                    break
        except urllib.error.HTTPError as he:
            if he.code < 500:
                ready = True
                break
        except Exception:
            time.sleep(0.1)

    if not ready and not result["error"]:
        result["error"] = f"Server did not become ready on {health_url} within 10s"

    if ready:
        target_url = f"{base_url}{path}"
        curl_bin = shutil.which("curl")
        if curl_bin:
            cmd = [curl_bin, "-sS", "-i", "--max-time", "8", "-X", method]
            for hk, hv in headers.items():
                cmd.extend(["-H", f"{hk}: {hv}"])
            if body is not None:
                cmd.extend(["--data", body])
            cmd.append(target_url)
            cp = subprocess.run(cmd, capture_output=True, text=True, timeout=10, check=False)
            if cp.returncode != 0:
                result["error"] = f"curl failed (rc={cp.returncode}): {cp.stderr.strip()}"
            else:
                sc, hdrs, btxt = parse_curl_http_output(cp.stdout)
                result["status_code"] = sc
                result["response_headers"] = hdrs
                result["response_body_excerpt"] = btxt[:1000]
        else:
            req = urllib.request.Request(
                target_url,
                data=body.encode("utf-8") if body is not None else None,
                headers=headers,
                method=method,
            )
            try:
                with urllib.request.urlopen(req, timeout=8) as resp:
                    result["status_code"] = resp.status
                    result["response_headers"] = {k.lower(): v for k, v in resp.headers.items()}
                    result["response_body_excerpt"] = resp.read(1000).decode("utf-8", errors="ignore")
            except urllib.error.HTTPError as he:
                result["status_code"] = he.code
                result["response_headers"] = {k.lower(): v for k, v in he.headers.items()}
                result["response_body_excerpt"] = he.read(1000).decode("utf-8", errors="ignore")
finally:
    if proc.poll() is None:
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
            proc.wait(timeout=2)
        except Exception:
            try:
                os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
            except Exception:
                pass
    if created_marker and created_marker.exists():
        try:
            created_marker.unlink()
        except OSError:
            pass

print(json.dumps(result))
'''


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


def run_dynamic_probe(
    workspace_dir: Path,
    backend: SandboxBackend,
    start_cmd: str,
    spec: DynamicProbeSpec,
    health_path: str = "/health",
    policy: SandboxPolicy | None = None,
) -> DynamicProbeResult:
    """Start the repo's app inside the sandbox on loopback and run the active curl probe."""
    if not spec.path.startswith("/"):
        raise ValueError(f"Probe path must start with '/': {spec.path!r}")

    port = _pick_free_port()
    base_url = f"http://127.0.0.1:{port}"
    validate_loopback_url(f"{base_url}{spec.path}")
    curl_command = spec.to_curl("http://127.0.0.1:$PORT")

    runner_script = workspace_dir / ".vulnbox_probe_runner.py"
    cfg_file = workspace_dir / ".vulnbox_probe_cfg.json"
    cfg_payload = {
        "start_cmd": start_cmd,
        "port": port,
        "health_path": health_path,
        "method": spec.method,
        "path": spec.path,
        "headers": spec.headers,
        "body": spec.body,
        "setup_marker_file": spec.setup_marker_file,
        "setup_marker_content": spec.setup_marker_content,
    }

    py_exe = "python3" if backend.name == "docker" else sys.executable
    try:
        runner_script.write_text(_SANDBOX_PROBE_RUNNER, encoding="utf-8")
        cfg_file.write_text(json.dumps(cfg_payload), encoding="utf-8")
        cmd = f"{shlex.quote(py_exe)} .vulnbox_probe_runner.py .vulnbox_probe_cfg.json"
        exec_res = backend.run(
            workspace_dir,
            cmd,
            policy=policy or SandboxPolicy(timeout_sec=30),
        )
    finally:
        for tmp in (runner_script, cfg_file):
            if tmp.exists():
                try:
                    tmp.unlink()
                except OSError:
                    pass

    if exec_res.exit_code != 0 and not exec_res.stdout.strip():
        return DynamicProbeResult(
            probe_id=spec.probe_id,
            curl_command=curl_command,
            error=f"Probe runner failed (rc={exec_res.exit_code}): {exec_res.stderr.strip()}",
        )

    try:
        # Take the last JSON line in case the app printed anything earlier
        json_line = [ln for ln in exec_res.stdout.splitlines() if ln.strip()][-1]
        data = json.loads(json_line)
    except Exception as exc:
        return DynamicProbeResult(
            probe_id=spec.probe_id,
            curl_command=curl_command,
            error=f"Failed to parse probe JSON output: {exc}; raw={exec_res.stdout[:300]}",
        )

    status_code = data.get("status_code")
    res_headers: dict[str, str] = data.get("response_headers") or {}
    body_excerpt: str = data.get("response_body_excerpt") or ""
    err = data.get("error")

    matched_vuln = False
    matched_fixed = False
    if err is None:
        matched_vuln = spec.vulnerable_expectation.matches(
            status_code, res_headers, body_excerpt
        ) and _matches_cors_vulnerable(spec, res_headers)
        matched_fixed = spec.fixed_expectation.matches(
            status_code, res_headers, body_excerpt
        ) and _matches_cors_fixed(spec, res_headers)

    return DynamicProbeResult(
        probe_id=spec.probe_id,
        curl_command=curl_command,
        status_code=status_code,
        response_headers=res_headers,
        response_body_excerpt=body_excerpt,
        matched_vulnerable=matched_vuln,
        matched_fixed=matched_fixed,
        error=err,
    )
