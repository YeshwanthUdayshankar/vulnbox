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
from vulnbox.models import DynamicProbeSpec, MockRule
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
        "description": "Run air-gapped SAST (taint-tracked), lockfile CVE reachability (with OpenVEX/CycloneDX VEX & EPSS/KEV), config hygiene, and memory leak analysis without mutating the repo.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "repo_path": {"type": "string", "description": "Absolute path to local repository"},
                "backend": {"type": "string", "enum": ["auto", "docker", "local"], "default": "auto"},
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
        "description": "Boot a scrubbed copy of a local repo on 127.0.0.1 inside an air-gapped sandbox (with expected-shape HTTP 200 mocks, SSRF canary, Redis/SMTP shims, and optional HS256 test-JWT) and execute declarative active probes.",
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
                "backend": {"type": "string", "enum": ["auto", "docker", "local"], "default": "auto"},
                "mock_integrations": {"type": "boolean", "default": True},
                "mocks": {"type": "array", "items": {"type": "object"}},
                "auth_jwt_claims": {"type": "object"},
            },
            "required": ["repo_path", "probes"],
        },
    },
    {
        "name": "vulnbox_verify_patch",
        "description": "Dual-verify a candidate unified diff patch (plus optional regression test and active loopback probe) inside a fresh secret-scrubbed sandbox without mutating the target repo.",
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
                "backend": {"type": "string", "enum": ["auto", "docker", "local"], "default": "auto"},
                "mock_integrations": {"type": "boolean", "default": True},
                "auth_jwt_claims": {"type": "object"},
            },
            "required": ["repo_path", "unified_diff"],
        },
    },
]


def _execute_tool(name: str, args: dict[str, Any]) -> dict[str, Any]:
    if name == "vulnbox_profile":
        repo = Path(str(args["repo_path"])).expanduser().resolve()
        prof = VulnBoxEngine(backend="local").profile(repo)
        return {"profile": prof.model_dump()}

    if name == "vulnbox_scan":
        repo = Path(str(args["repo_path"])).expanduser().resolve()
        backend = str(args.get("backend") or "auto")
        engine = VulnBoxEngine(backend=backend)
        report, _ = engine.scan(
            repo,
            deep=bool(args.get("deep")),
            check_leaks=bool(args.get("check_leaks")),
        )
        payload: dict[str, Any] = {
            "findings_count": len(report.findings),
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
        backend = str(args.get("backend") or "auto")
        specs = [DynamicProbeSpec.model_validate(item) for item in (args.get("probes") or [])]
        raw_mocks = args.get("mocks")
        mock_rules = (
            [MockRule.model_validate(m) for m in raw_mocks] if isinstance(raw_mocks, list) else None
        )
        engine = VulnBoxEngine(backend=backend)
        results = engine.probe(
            repo,
            specs=specs,
            start_cmd=args.get("start_cmd"),
            mock_integrations=bool(args.get("mock_integrations", True)),
            mock_rules=mock_rules,
            auth_jwt_claims=args.get("auth_jwt_claims"),
        )
        return {"results": [r.model_dump() for r in results]}

    if name == "vulnbox_verify_patch":
        repo = Path(str(args["repo_path"])).expanduser().resolve()
        backend = str(args.get("backend") or "auto")
        raw_probe = args.get("probe_spec")
        probe_spec = DynamicProbeSpec.model_validate(raw_probe) if raw_probe else None
        engine = VulnBoxEngine(backend=backend)
        ver = engine.verify_external_patch(
            repo_path=repo,
            unified_diff=str(args["unified_diff"]),
            finding_id=str(args.get("finding_id") or "CUSTOM-001"),
            rule_id=str(args.get("rule_id") or "CUSTOM"),
            regression_test_path=args.get("regression_test_path"),
            regression_test_code=args.get("regression_test_code"),
            probe_spec=probe_spec,
            start_cmd=args.get("start_cmd"),
            mock_integrations=bool(args.get("mock_integrations", True)),
            auth_jwt_claims=args.get("auth_jwt_claims"),
        )
        return {"verification": ver.model_dump()}

    raise ValueError(f"Unknown MCP tool: {name}")


def handle_mcp_request(msg: dict[str, Any]) -> dict[str, Any] | None:
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
            output = _execute_tool(tool_name, tool_args)
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
        reply = handle_mcp_request(msg)
        if reply is None:
            continue

        encoded = json.dumps(reply)
        if use_framing:
            out.write(f"Content-Length: {len(encoded.encode('utf-8'))}\r\n\r\n{encoded}")
        else:
            out.write(encoded + "\n")
        out.flush()
