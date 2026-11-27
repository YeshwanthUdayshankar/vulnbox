"""Zero-dependency stdio MCP (Model Context Protocol) server exposing VulnBox as an agent truth oracle.

Exposes 4 sandboxed tools over JSON-RPC 2.0 stdio (supporting both newline-delimited JSON
and LSP-style Content-Length framing):
  - `vulnbox_profile`
  - `vulnbox_scan`
  - `vulnbox_probe`
  - `vulnbox_verify_patch`
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any, TextIO

from vulnbox._version import __version__
from vulnbox.engine import VulnBoxEngine
from vulnbox.llm.guardrails import (
    GuardrailPolicy,
    validate_llm_diff,
    validate_llm_probe,
    validate_llm_regression_test,
    validate_start_command,
)
from vulnbox.models import DynamicProbeSpec, Finding, MockRule
from vulnbox.reporting.vex import build_cyclonedx_vex, build_openvex
from vulnbox.suppressions import should_fail_ci

MCP_PROTOCOL_VERSION = "2024-11-05"

TOOL_DEFINITIONS: list[dict[str, Any]] = [
    {
        "name": "vulnbox_profile",
        "description": "Read-only profiling of a local repository (ecosystem, manifests, frameworks, test commands, start command).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "repo_path": {"type": "string", "description": "Absolute path to local repository"},
            },
            "required": ["repo_path"],
        },
    },
    {
        "name": "vulnbox_scan",
        "description": "Run air-gapped SAST (taint-tracked), lockfile CVE reachability (with OpenVEX/CycloneDX VEX & EPSS/KEV), config hygiene, and memory leak analysis without mutating the repo. Defaults to Docker containment.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "repo_path": {"type": "string", "description": "Absolute path to local repository"},
                "backend": {"type": "string", "enum": ["docker", "local"], "default": "docker"},
                "deep": {"type": "boolean", "default": False},
                "check_leaks": {"type": "boolean", "default": False},
                "fail_on": {"type": "string", "enum": ["low", "medium", "high", "critical"]},
                "include_vex": {"type": "boolean", "default": True},
            },
            "required": ["repo_path"],
        },
    },
    {
        "name": "vulnbox_probe",
        "description": "Boot a scrubbed copy of a local repo on 127.0.0.1 inside a Docker air-gapped sandbox (with expected-shape HTTP 200 mocks, SSRF canary, Redis/SMTP shims, and optional HS256 test-JWT) and execute guardrail-validated active probes.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "repo_path": {"type": "string"},
                "probes": {
                    "type": "array",
                    "items": {"type": "object"},
                    "description": "List of DynamicProbeSpec objects",
                },
                "start_cmd": {"type": "string"},
                "backend": {"type": "string", "enum": ["docker", "local"], "default": "docker"},
                "mock_integrations": {"type": "boolean", "default": True},
                "mocks": {"type": "array", "items": {"type": "object"}},
                "auth_jwt_claims": {"type": "object"},
            },
            "required": ["repo_path", "probes"],
        },
    },
    {
        "name": "vulnbox_verify_patch",
        "description": "Dual-verify a guardrail-validated candidate unified diff patch (plus optional regression test and active loopback probe) inside a fresh secret-scrubbed Docker sandbox without mutating the target repo.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "repo_path": {"type": "string"},
                "unified_diff": {"type": "string"},
                "finding_id": {"type": "string", "default": "CUSTOM-001"},
                "rule_id": {"type": "string", "default": "CUSTOM"},
                "regression_test_path": {"type": "string"},
                "regression_test_code": {"type": "string"},
                "probe_spec": {"type": "object"},
                "start_cmd": {"type": "string"},
                "backend": {"type": "string", "enum": ["docker", "local"], "default": "docker"},
                "mock_integrations": {"type": "boolean", "default": True},
                "auth_jwt_claims": {"type": "object"},
            },
            "required": ["repo_path", "unified_diff"],
        },
    },
]


def _resolve_mcp_backend(
    requested: str | None,
    *,
    allow_local: bool,
    executes_repo_code: bool,
) -> str:
    """Enforce Docker containment by default for MCP tool calls.

    Refuses `local` (and never silently falls back from `auto` to `local`) unless the MCP
    server was explicitly started with `--allow-local`. Purely static `vulnbox_scan`
    (deep=False, check_leaks=False) does not execute repository code; if `backend` is omitted
    and Docker is unavailable, it still refuses `local` when `executes_repo_code=True`.
    """
    pref = str(requested or "docker").strip().lower()
    if pref == "auto":
        # Never allow silent fallback to host-local execution under MCP
        pref = "docker"
    if pref == "local":
        if not allow_local:
            raise PermissionError(
                "MCP server refuses '--backend local' host execution by default because local "
                "mode is not a kernel/filesystem containment boundary. Use backend='docker' "
                "or restart the MCP server explicitly with `vulnbox mcp --allow-local`."
            )
        return "local"
    if pref == "docker":
        return "docker"
    raise ValueError(f"Unsupported MCP backend {requested!r}. Allowed: 'docker' (or 'local' with --allow-local).")


def _enforce_guardrail(ev_decision: str, gate: str, reason: str) -> None:
    if ev_decision == "block":
        raise PermissionError(f"MCP guardrail blocked input ({gate}): {reason}")


def _execute_tool(name: str, args: dict[str, Any], *, allow_local: bool = False) -> dict[str, Any]:
    policy = GuardrailPolicy()

    if name == "vulnbox_profile":
        repo = Path(str(args["repo_path"])).expanduser().resolve()
        prof = VulnBoxEngine(backend="local").profile(repo)
        return {"profile": prof.model_dump()}

    if name == "vulnbox_scan":
        repo = Path(str(args["repo_path"])).expanduser().resolve()
        deep = bool(args.get("deep"))
        check_leaks = bool(args.get("check_leaks"))
        executes_code = deep or check_leaks
        backend = _resolve_mcp_backend(
            args.get("backend"),
            allow_local=allow_local,
            executes_repo_code=executes_code,
        )
        # Pure static scan never runs untrusted repo code, so if Docker isn't running we can still
        # use the non-executing static pipeline only when backend='local' was permitted or explicitly allowed.
        engine = VulnBoxEngine(backend=backend)
        report, _ = engine.scan(
            repo,
            deep=deep,
            check_leaks=check_leaks,
        )
        payload: dict[str, Any] = {
            "findings_count": len(report.findings),
            "suppressed_count": len(report.suppressed_findings),
            "ci_gate_failed": should_fail_ci(report.findings, args.get("fail_on")),
            "findings": [f.model_dump() for f in report.findings],
            "call_graph_summary": report.call_graph_summary.model_dump()
            if report.call_graph_summary
            else None,
            "memory_probes": [m.model_dump() for m in report.memory_probes],
        }
        if args.get("include_vex", True):
            payload["openvex"] = build_openvex(report)
            payload["cyclonedx_vex"] = build_cyclonedx_vex(report)
        return payload

    if name == "vulnbox_probe":
        repo = Path(str(args["repo_path"])).expanduser().resolve()
        backend = _resolve_mcp_backend(
            args.get("backend"),
            allow_local=allow_local,
            executes_repo_code=True,
        )
        start_cmd = args.get("start_cmd")
        if start_cmd is not None:
            sc_ev = validate_start_command(str(start_cmd))
            _enforce_guardrail(sc_ev.decision, sc_ev.gate, sc_ev.reason)

        specs = [DynamicProbeSpec.model_validate(item) for item in (args.get("probes") or [])]
        for spec in specs:
            pr_ev = validate_llm_probe(spec, policy)
            _enforce_guardrail(pr_ev.decision, pr_ev.gate, pr_ev.reason)

        raw_mocks = args.get("mocks")
        mock_rules = (
            [MockRule.model_validate(m) for m in raw_mocks] if isinstance(raw_mocks, list) else None
        )
        engine = VulnBoxEngine(backend=backend)
        results = engine.probe(
            repo,
            specs=specs,
            start_cmd=str(start_cmd) if start_cmd is not None else None,
            mock_integrations=bool(args.get("mock_integrations", True)),
            mock_rules=mock_rules,
            auth_jwt_claims=args.get("auth_jwt_claims"),
        )
        return {"results": [r.model_dump() for r in results]}

    if name == "vulnbox_verify_patch":
        repo = Path(str(args["repo_path"])).expanduser().resolve()
        backend = _resolve_mcp_backend(
            args.get("backend"),
            allow_local=allow_local,
            executes_repo_code=True,
        )
        finding_id = str(args.get("finding_id") or "CUSTOM-001")
        rule_id = str(args.get("rule_id") or "CUSTOM")
        unified_diff = str(args["unified_diff"])

        # Validate agent-supplied diff, start_cmd, probe_spec, and regression test via deterministic guardrails
        dummy_finding = Finding(
            finding_id=finding_id,
            rule_id=rule_id,
            cwe_id="CWE-000",
            title="MCP external patch verification",
            category="sast",
            severity="medium",
            file_path=".",
            message="MCP patch verification",
            recommended_fix="",
        )
        diff_ev = validate_llm_diff(unified_diff, dummy_finding, repo, policy)
        _enforce_guardrail(diff_ev.decision, diff_ev.gate, diff_ev.reason)

        start_cmd = args.get("start_cmd")
        if start_cmd is not None:
            sc_ev = validate_start_command(str(start_cmd), finding_id=finding_id)
            _enforce_guardrail(sc_ev.decision, sc_ev.gate, sc_ev.reason)

        raw_probe = args.get("probe_spec")
        probe_spec = DynamicProbeSpec.model_validate(raw_probe) if raw_probe else None
        if probe_spec is not None:
            pr_ev = validate_llm_probe(probe_spec, policy, finding_id=finding_id)
            _enforce_guardrail(pr_ev.decision, pr_ev.gate, pr_ev.reason)

        reg_path = args.get("regression_test_path")
        reg_code = args.get("regression_test_code")
        if reg_path or reg_code:
            if not (reg_path and reg_code):
                raise PermissionError(
                    "MCP guardrail blocked input (regression_test_safety_gate): "
                    "Both regression_test_path and regression_test_code are required together."
                )
            rt_ev = validate_llm_regression_test(str(reg_path), str(reg_code), finding_id=finding_id)
            _enforce_guardrail(rt_ev.decision, rt_ev.gate, rt_ev.reason)

        engine = VulnBoxEngine(backend=backend)
        ver = engine.verify_external_patch(
            repo_path=repo,
            unified_diff=unified_diff,
            finding_id=finding_id,
            rule_id=rule_id,
            regression_test_path=str(reg_path) if reg_path else None,
            regression_test_code=str(reg_code) if reg_code else None,
            probe_spec=probe_spec,
            start_cmd=str(start_cmd) if start_cmd is not None else None,
            mock_integrations=bool(args.get("mock_integrations", True)),
            auth_jwt_claims=args.get("auth_jwt_claims"),
        )
        return {"verification": ver.model_dump()}

    raise ValueError(f"Unknown MCP tool: {name}")


def handle_mcp_request(
    msg: dict[str, Any],
    *,
    allow_local: bool = False,
) -> dict[str, Any] | None:
    """Handle one JSON-RPC 2.0 MCP message and return the response dict (or None for notifications)."""
    method = msg.get("method")
    req_id = msg.get("id")
    params = msg.get("params") or {}

    # Notifications have no `id` and expect no reply
    if method == "notifications/initialized" or (req_id is None and method != "initialize"):
        return None

    try:
        if method == "initialize":
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "protocolVersion": MCP_PROTOCOL_VERSION,
                    "capabilities": {"tools": {}},
                    "serverInfo": {"name": "vulnbox", "version": __version__},
                },
            }

        if method == "ping":
            return {"jsonrpc": "2.0", "id": req_id, "result": {}}

        if method == "tools/list":
            return {"jsonrpc": "2.0", "id": req_id, "result": {"tools": TOOL_DEFINITIONS}}

        if method == "tools/call":
            tool_name = str(params.get("name") or "")
            tool_args = params.get("arguments") or {}
            if not isinstance(tool_args, dict):
                raise ValueError("Tool arguments must be a JSON object.")
            output = _execute_tool(tool_name, tool_args, allow_local=allow_local)
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "content": [{"type": "text", "text": json.dumps(output, indent=2)}],
                    "isError": False,
                },
            }

        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "error": {"code": -32601, "message": f"Method not found: {method}"},
        }
    except Exception as exc:
        if method == "tools/call":
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "content": [{"type": "text", "text": json.dumps({"error": str(exc)})}],
                    "isError": True,
                },
            }
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "error": {"code": -32000, "message": str(exc)},
        }


def serve_mcp_stdio(
    stdin: TextIO | None = None,
    stdout: TextIO | None = None,
    *,
    allow_local: bool = False,
) -> None:
    """Run the JSON-RPC 2.0 MCP server loop over stdio (supports newline JSON & Content-Length)."""
    inp = stdin or sys.stdin
    out = stdout or sys.stdout

    while True:
        line = inp.readline()
        if not line:
            break
        stripped = line.strip()
        if not stripped:
            continue

        use_framing = False
        if stripped.lower().startswith("content-length:"):
            use_framing = True
            length = int(stripped.split(":", 1)[1].strip())
            # Consume remaining headers until blank line
            while True:
                hdr = inp.readline()
                if not hdr or hdr.strip() == "":
                    break
            raw_payload = inp.read(length)
        else:
            raw_payload = stripped

        try:
            msg = json.loads(raw_payload)
        except json.JSONDecodeError:
            continue

        if not isinstance(msg, dict):
            continue
        reply = handle_mcp_request(msg, allow_local=allow_local)
        if reply is None:
            continue

        encoded = json.dumps(reply)
        if use_framing:
            out.write(f"Content-Length: {len(encoded.encode('utf-8'))}\r\n\r\n{encoded}")
        else:
            out.write(encoded + "\n")
        out.flush()
