"""Zero-dependency, CSRF-protected local Web UI server backed by VulnBoxEngine."""

from __future__ import annotations

import json
import secrets
import shutil
import sys
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from vulnbox._version import __version__
from vulnbox.callgraph.ts_utils import available_tree_sitter_languages
from vulnbox.engine import VulnBoxEngine
from vulnbox.llm import GuardrailPolicy, LLMConfig
from vulnbox.models import DynamicProbeSpec, MockRule
from vulnbox.registry import default_registry
from vulnbox.reporting.markdown import render_markdown_report
from vulnbox.reporting.sarif import build_sarif, validate_sarif
from vulnbox.sandbox import (
    SUPPORTED_SIDECARS,
    DockerSandboxBackend,
    LocalSandboxBackend,
    prune_dependency_images,
)

STATIC_DIR = Path(__file__).resolve().parent / "static"
STATIC_ASSETS: dict[str, tuple[str, str]] = {
    "/static/styles.css": ("styles.css", "text/css; charset=utf-8"),
    "/static/app.js": ("app.js", "application/javascript; charset=utf-8"),
}
MAX_BODY_BYTES = 2 * 1024 * 1024  # 2 MiB max request body
ALLOWED_HOSTS = {"127.0.0.1", "localhost", "::1"}

SECURITY_HEADERS: dict[str, str] = {
    "Content-Security-Policy": (
        "default-src 'self'; "
        "script-src 'self'; "
        "style-src 'self'; "
        "img-src 'self' data:; "
        "connect-src 'self'; "
        "frame-ancestors 'none'; "
        "base-uri 'self'"
    ),
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Cache-Control": "no-store",
}


def _discover_sample_fixtures() -> list[dict[str, str]]:
    """Return bundled sample fixture paths when running from the vulnbox source checkout."""
    repo_root = Path(__file__).resolve().parents[3]
    fixtures_dir = repo_root / "tests" / "fixtures"
    samples: list[dict[str, str]] = []
    if not fixtures_dir.is_dir():
        return samples
    for name, label in (
        ("py_sample_app", "Python Sample App"),
        ("node_sample_app", "Node.js Sample App"),
        ("llm_sql_app", "LLM SQL Sample App"),
        ("py_leaky_app", "Python Deep/Leaky App"),
        ("node_leaky_app", "Node.js Deep/Leaky App"),
        ("py_integrated_app", "Python Integrated/Mocked App"),
    ):
        cand = fixtures_dir / name
        if cand.is_dir():
            item: dict[str, str] = {"name": name, "label": label, "path": str(cand)}
            probe_file = cand / "probe_sql.json"
            if probe_file.is_file():
                item["probe_json"] = probe_file.read_text(encoding="utf-8")
            samples.append(item)
    return samples


def _doctor_status() -> dict[str, Any]:
    docker_ok = DockerSandboxBackend().is_available()
    local_ok = LocalSandboxBackend().is_available()
    return {
        "version": __version__,
        "python": sys.version.split()[0],
        "node": shutil.which("node"),
        "curl": shutil.which("curl"),
        "docker_ready": docker_ok,
        "local_ready": local_ok,
        "default_backend": "docker" if docker_ok else "local",
        "tree_sitter_languages": available_tree_sitter_languages(),
        "memory_profilers": [p.name for p in default_registry.list_memory_profilers()],
        "integration_mocking": True,
        "supported_sidecars": sorted(SUPPORTED_SIDECARS),
        "samples": _discover_sample_fixtures(),
    }


def _parse_probe_specs_payload(raw_probe: Any) -> list[DynamicProbeSpec]:
    if not raw_probe:
        return []
    if isinstance(raw_probe, str):
        text = raw_probe.strip()
        if not text:
            return []
        parsed = json.loads(text)
    else:
        parsed = raw_probe
    items = parsed if isinstance(parsed, list) else [parsed]
    specs: list[DynamicProbeSpec] = []
    for item in items:
        spec = DynamicProbeSpec.model_validate(item)
        if not spec.path.startswith("/"):
            raise ValueError(f"Probe path must start with '/': {spec.path!r}")
        specs.append(spec)
    return specs


def _parse_mock_rules_payload(raw_mocks: Any) -> list[MockRule] | None:
    if not raw_mocks:
        return None
    if isinstance(raw_mocks, str):
        text = raw_mocks.strip()
        if not text:
            return None
        parsed = json.loads(text)
    else:
        parsed = raw_mocks
    if isinstance(parsed, dict) and "rules" in parsed:
        items = parsed["rules"]
    elif isinstance(parsed, list):
        items = parsed
    else:
        items = [parsed]
    rules: list[MockRule] = []
    for item in items:
        rule = MockRule.model_validate(item)
        rule.source = "user"
        rules.append(rule)
    return rules


def _parse_services_payload(raw_services: Any) -> list[str]:
    if not raw_services:
        return []
    if isinstance(raw_services, list):
        return [str(s).strip().lower() for s in raw_services if str(s).strip()]
    return [s.strip().lower() for s in str(raw_services).split(",") if s.strip()]


def _require_repo_dir(raw_path: Any) -> Path:
    if not isinstance(raw_path, str) or not raw_path.strip():
        raise ValueError("Repository path is required.")
    repo = Path(raw_path.strip()).expanduser().resolve()
    if not repo.is_dir():
        raise ValueError(f"Repository directory does not exist: {repo}")
    return repo


class VulnBoxUIServer(ThreadingHTTPServer):
    """HTTP server holding the per-session CSRF token and bundle export cache."""

    allow_reuse_address = True

    def __init__(
        self,
        server_address: tuple[str, int],
        csrf_token: str | None = None,
    ) -> None:
        self.csrf_token: str = csrf_token or secrets.token_urlsafe(24)
        self.artifacts_lock = threading.Lock()
        self.latest_artifacts: dict[str, dict[str, str]] = {}
        super().__init__(server_address, VulnBoxUIHandler)


class VulnBoxUIHandler(BaseHTTPRequestHandler):
    server: VulnBoxUIServer

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
        return

    def _apply_security_headers(self) -> None:
        for k, v in SECURITY_HEADERS.items():
            self.send_header(k, v)

    def _send_bytes(self, status: int, content_type: str, body: bytes) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self._apply_security_headers()
        self.end_headers()
        self.wfile.write(body)

    def _send_json(self, status: int, payload: Any) -> None:
        body = json.dumps(payload, indent=2).encode("utf-8")
        self._send_bytes(status, "application/json; charset=utf-8", body)

    def _validate_host_and_csrf(self, require_csrf: bool) -> bool:
        host_header = (self.headers.get("Host") or "").split(":", 1)[0].strip("[]").lower()
        if host_header and host_header not in ALLOWED_HOSTS:
            self._send_json(403, {"error": f"Disallowed Host header: {host_header}"})
            return False

        origin = self.headers.get("Origin")
        if origin:
            parsed_origin = urlparse(origin)
            if (parsed_origin.hostname or "").lower() not in ALLOWED_HOSTS:
                self._send_json(403, {"error": f"Disallowed cross-origin request: {origin}"})
                return False

        if require_csrf:
            token = self.headers.get("X-VulnBox-Token") or ""
            if not secrets.compare_digest(token, self.server.csrf_token):
                self._send_json(403, {"error": "Missing or invalid X-VulnBox-Token CSRF header."})
                return False
        return True

    def _read_json_body(self) -> dict[str, Any]:
        length = int(self.headers.get("Content-Length") or "0")
        if length < 0 or length > MAX_BODY_BYTES:
            raise ValueError(f"Request body exceeds limit ({MAX_BODY_BYTES} bytes).")
        raw = self.rfile.read(length).decode("utf-8") if length else "{}"
        data = json.loads(raw or "{}")
        if not isinstance(data, dict):
            raise ValueError("JSON body must be an object.")
        return data

    def do_GET(self) -> None:  # noqa: N802
        if not self._validate_host_and_csrf(require_csrf=False):
            return
        parsed = urlparse(self.path)

        if parsed.path in ("/", "/index.html"):
            html = (STATIC_DIR / "index.html").read_text(encoding="utf-8")
            html = html.replace("__VULNBOX_CSRF_TOKEN__", self.server.csrf_token)
            html = html.replace("__VULNBOX_VERSION__", __version__)
            self._send_bytes(200, "text/html; charset=utf-8", html.encode("utf-8"))
            return

        if parsed.path in STATIC_ASSETS:
            fname, ctype = STATIC_ASSETS[parsed.path]
            asset_bytes = (STATIC_DIR / fname).read_bytes()
            self._send_bytes(200, ctype, asset_bytes)
            return

        if parsed.path == "/api/doctor":
            self._send_json(200, _doctor_status())
            return

        if parsed.path.startswith("/api/artifact/"):
            parts = parsed.path.removeprefix("/api/artifact/").split("/", 1)
            if len(parts) == 2:
                run_id, kind = parts
                with self.server.artifacts_lock:
                    bundle = self.server.latest_artifacts.get(run_id)
                    content = bundle.get(kind) if bundle else None
                if content is not None:
                    ctype = (
                        "text/markdown; charset=utf-8"
                        if kind == "report.md"
                        else "application/json; charset=utf-8"
                    )
                    self._send_bytes(200, ctype, content.encode("utf-8"))
                    return
            self._send_json(404, {"error": "Artifact not found."})
            return

        self._send_json(404, {"error": "Not found."})

    def do_POST(self) -> None:  # noqa: N802
        if not self._validate_host_and_csrf(require_csrf=True):
            return
        parsed = urlparse(self.path)
        try:
            body = self._read_json_body()
            if parsed.path == "/api/profile":
                self._handle_profile(body)
            elif parsed.path == "/api/scan":
                self._handle_scan(body)
            elif parsed.path == "/api/remediate":
                self._handle_remediate(body)
            elif parsed.path == "/api/probe":
                self._handle_probe(body)
            elif parsed.path == "/api/verify-patch":
                self._handle_verify_patch(body)
            elif parsed.path == "/api/clean-cache":
                removed = prune_dependency_images()
                self._send_json(200, {"removed": removed, "count": len(removed)})
            else:
                self._send_json(404, {"error": "Unknown API endpoint."})
        except (ValueError, json.JSONDecodeError) as exc:
            self._send_json(400, {"error": str(exc)})
        except RuntimeError as exc:
            self._send_json(500, {"error": str(exc)})
        except Exception as exc:
            self._send_json(500, {"error": f"Unexpected server error: {exc}"})

    def _store_report_artifacts(self, report: Any) -> tuple[str, str, dict[str, Any]]:
        run_id = secrets.token_hex(8)
        md_text = render_markdown_report(report)
        sarif_doc = build_sarif(report)
        validate_sarif(sarif_doc)
        sarif_text = json.dumps(sarif_doc, indent=2) + "\n"
        manifest_text = report.model_dump_json(indent=2) + "\n"
        with self.server.artifacts_lock:
            if len(self.server.latest_artifacts) >= 10:
                oldest = next(iter(self.server.latest_artifacts))
                self.server.latest_artifacts.pop(oldest, None)
            self.server.latest_artifacts[run_id] = {
                "report.md": md_text,
                "findings.sarif.json": sarif_text,
                "manifest.json": manifest_text,
            }
        return run_id, md_text, sarif_doc

    def _handle_profile(self, body: dict[str, Any]) -> None:
        repo = _require_repo_dir(body.get("repo_path"))
        prof = VulnBoxEngine(backend="local").profile(repo)
        self._send_json(200, {"profile": prof.model_dump()})

    def _handle_scan(self, body: dict[str, Any]) -> None:
        repo = _require_repo_dir(body.get("repo_path"))
        backend = str(body.get("backend") or "auto")
        adv_raw = (body.get("advisories_path") or "").strip()
        adv_path = Path(adv_raw).expanduser().resolve() if adv_raw else None
        if adv_path is not None and not adv_path.is_file():
            raise ValueError(f"Advisories file not found: {adv_path}")

        out_raw = (body.get("out_dir") or "").strip()
        out_path = Path(out_raw).expanduser().resolve() if out_raw else None
        deep = bool(body.get("deep"))
        check_leaks = bool(body.get("check_leaks"))
        start_cmd = (body.get("start_cmd") or "").strip() or None
        health_path = (body.get("health_path") or "").strip() or None

        engine = VulnBoxEngine(backend=backend)
        report, written = engine.scan(
            repo,
            advisories_path=adv_path,
            deep=deep,
            check_leaks=check_leaks,
            start_cmd=start_cmd,
            health_path=health_path,
            out_dir=out_path,
        )
        run_id, md_text, sarif_doc = self._store_report_artifacts(report)
        self._send_json(
            200,
            {
                "run_id": run_id,
                "report": report.model_dump(),
                "markdown": md_text,
                "sarif": sarif_doc,
                "written": {k: str(v) for k, v in written.items()},
            },
        )

    def _handle_remediate(self, body: dict[str, Any]) -> None:
        repo = _require_repo_dir(body.get("repo_path"))
        backend = str(body.get("backend") or "auto")
        start_cmd = (body.get("start_cmd") or "").strip() or None
        health_path = (body.get("health_path") or "").strip() or None
        probes = _parse_probe_specs_payload(body.get("probe_json"))

        adv_raw = (body.get("advisories_path") or "").strip()
        adv_path = Path(adv_raw).expanduser().resolve() if adv_raw else None
        if adv_path is not None and not adv_path.is_file():
            raise ValueError(f"Advisories file not found: {adv_path}")

        llm_enabled = bool(body.get("llm_enabled"))
        llm_cfg: LLMConfig | None = None
        if llm_enabled:
            llm_cfg = LLMConfig(
                provider=str(body.get("llm_provider") or "ollama"),
                model=(body.get("llm_model") or "").strip() or None,
                base_url=(body.get("llm_base_url") or "").strip() or None,
            )
        max_retries = int(body.get("llm_max_retries") if body.get("llm_max_retries") is not None else 2)
        max_retries = max(0, min(5, max_retries))

        out_raw = (body.get("out_dir") or "").strip()
        out_path = Path(out_raw).expanduser().resolve() if out_raw else None
        deep = bool(body.get("deep"))
        check_leaks = bool(body.get("check_leaks"))
        max_workers = int(body.get("max_workers") if body.get("max_workers") is not None else 4)
        max_workers = max(1, min(16, max_workers))
        build_deps = bool(body.get("build_deps"))
        image = (body.get("image") or "").strip() or None
        mock_integrations = (
            bool(body.get("mock_integrations")) if "mock_integrations" in body else True
        )
        mock_rules = _parse_mock_rules_payload(body.get("mocks_json"))
        mocks_strict = bool(body.get("mocks_strict"))
        services = _parse_services_payload(body.get("services"))
        auth_header = (body.get("auth_header") or "").strip() or None
        auth_jwt_claims = (body.get("auth_jwt_claims") or "").strip() or None

        engine = VulnBoxEngine(backend=backend, image=image or "vulnbox-sandbox:latest")
        report, written = engine.remediate(
            repo_path=repo,
            start_cmd=start_cmd,
            health_path=health_path,
            custom_probes=probes,
            advisories_path=adv_path,
            deep=deep,
            check_leaks=check_leaks,
            llm_config=llm_cfg,
            guardrail_policy=GuardrailPolicy(max_retries=max_retries),
            max_workers=max_workers,
            out_dir=out_path,
            build_deps=build_deps,
            image=image,
            mock_integrations=mock_integrations,
            mock_rules=mock_rules,
            mocks_strict=mocks_strict,
            services=services,
            auth_header=auth_header,
            auth_jwt_claims=auth_jwt_claims,
        )
        run_id, md_text, sarif_doc = self._store_report_artifacts(report)
        self._send_json(
            200,
            {
                "run_id": run_id,
                "report": report.model_dump(),
                "markdown": md_text,
                "sarif": sarif_doc,
                "written": {k: str(v) for k, v in written.items()},
            },
        )

    def _handle_probe(self, body: dict[str, Any]) -> None:
        repo = _require_repo_dir(body.get("repo_path"))
        backend = str(body.get("backend") or "auto")
        start_cmd = (body.get("start_cmd") or "").strip() or None
        health_path = (body.get("health_path") or "").strip() or None
        specs = _parse_probe_specs_payload(body.get("probe_json"))
        if not specs:
            raise ValueError("Provide a valid DynamicProbeSpec JSON object or array.")
        build_deps = bool(body.get("build_deps"))
        image = (body.get("image") or "").strip() or None
        mock_integrations = (
            bool(body.get("mock_integrations")) if "mock_integrations" in body else True
        )
        mock_rules = _parse_mock_rules_payload(body.get("mocks_json"))
        mocks_strict = bool(body.get("mocks_strict"))
        services = _parse_services_payload(body.get("services"))
        auth_header = (body.get("auth_header") or "").strip() or None
        auth_jwt_claims = (body.get("auth_jwt_claims") or "").strip() or None

        engine = VulnBoxEngine(backend=backend, image=image or "vulnbox-sandbox:latest")
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
            services=services,
            auth_header=auth_header,
            auth_jwt_claims=auth_jwt_claims,
        )
        self._send_json(200, {"results": [r.model_dump() for r in results]})

    def _handle_verify_patch(self, body: dict[str, Any]) -> None:
        repo = _require_repo_dir(body.get("repo_path"))
        backend = str(body.get("backend") or "auto")
        unified_diff = str(body.get("unified_diff") or "")
        if not unified_diff.strip():
            raise ValueError("Unified diff (.patch content) is required.")

        finding_id = str(body.get("finding_id") or "CUSTOM-001").strip()
        rule_id = str(body.get("rule_id") or "CUSTOM").strip()
        start_cmd = (body.get("start_cmd") or "").strip() or None
        health_path = (body.get("health_path") or "").strip() or None

        reg_path = (body.get("regression_test_path") or "").strip() or None
        reg_code = (body.get("regression_test_code") or "").strip() or None
        if reg_code and not reg_path:
            reg_path = "tests/test_security_custom.py"

        probes = _parse_probe_specs_payload(body.get("probe_json"))
        probe_spec = probes[0] if probes else None
        build_deps = bool(body.get("build_deps"))
        image = (body.get("image") or "").strip() or None
        mock_integrations = (
            bool(body.get("mock_integrations")) if "mock_integrations" in body else True
        )
        mock_rules = _parse_mock_rules_payload(body.get("mocks_json"))
        mocks_strict = bool(body.get("mocks_strict"))
        services = _parse_services_payload(body.get("services"))
        auth_header = (body.get("auth_header") or "").strip() or None
        auth_jwt_claims = (body.get("auth_jwt_claims") or "").strip() or None

        engine = VulnBoxEngine(backend=backend, image=image or "vulnbox-sandbox:latest")
        result = engine.verify_external_patch(
            repo_path=repo,
            unified_diff=unified_diff,
            finding_id=finding_id,
            rule_id=rule_id,
            regression_test_path=reg_path,
            regression_test_code=reg_code,
            probe_spec=probe_spec,
            start_cmd=start_cmd,
            health_path=health_path,
            description="Patch submitted via VulnBox Web UI",
            build_deps=build_deps,
            image=image,
            mock_integrations=mock_integrations,
            mock_rules=mock_rules,
            mocks_strict=mocks_strict,
            services=services,
            auth_header=auth_header,
            auth_jwt_claims=auth_jwt_claims,
        )
        self._send_json(200, {"verification": result.model_dump()})


def create_ui_server(
    host: str = "127.0.0.1",
    port: int = 8787,
    allow_remote: bool = False,
) -> VulnBoxUIServer:
    """Create a hardened local VulnBoxUIServer bound strictly to loopback by default."""
    if not allow_remote and host not in ALLOWED_HOSTS:
        raise ValueError(
            f"Refusing non-loopback bind host {host!r}. Pass allow_remote=True only if intended."
        )
    # Touch temp dir check cleanly
    _ = tempfile.gettempdir()
    return VulnBoxUIServer((host, port))
