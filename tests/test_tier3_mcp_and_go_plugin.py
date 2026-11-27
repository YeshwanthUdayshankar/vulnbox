"""Tests for Tier 3: stdio MCP server mode, reference Go plugin pack, CI/release artifacts, and threat model."""

from __future__ import annotations

import io
import json
import sys
from pathlib import Path

import yaml

from vulnbox.analyzers import run_all_analyzers
from vulnbox.mcp_server import handle_mcp_request, serve_mcp_stdio
from vulnbox.registry import PluginRegistry

REPO_ROOT = Path(__file__).resolve().parents[1]
FIXTURES = Path(__file__).parent / "fixtures"


def test_mcp_server_initialize_list_and_tools_end_to_end():
    init = handle_mcp_request({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}})
    assert init is not None
    assert init["result"]["serverInfo"]["name"] == "vulnbox"

    listed = handle_mcp_request({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
    assert listed is not None
    tool_names = {t["name"] for t in listed["result"]["tools"]}
    assert tool_names == {"vulnbox_profile", "vulnbox_scan", "vulnbox_probe", "vulnbox_verify_patch"}

    # Call vulnbox_profile
    prof_reply = handle_mcp_request(
        {
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {
                "name": "vulnbox_profile",
                "arguments": {"repo_path": str(FIXTURES / "py_sample_app")},
            },
        }
    )
    assert prof_reply is not None and prof_reply["result"]["isError"] is False
    prof_data = json.loads(prof_reply["result"]["content"][0]["text"])
    assert prof_data["profile"]["ecosystem"] == "python"

    # Call vulnbox_scan (includes OpenVEX & CycloneDX VEX)
    scan_reply = handle_mcp_request(
        {
            "jsonrpc": "2.0",
            "id": 4,
            "method": "tools/call",
            "params": {
                "name": "vulnbox_scan",
                "arguments": {
                    "repo_path": str(FIXTURES / "py_sample_app"),
                    "backend": "local",
                    "fail_on": "high",
                    "include_vex": True,
                },
            },
        }
    )
    assert scan_reply is not None and scan_reply["result"]["isError"] is False
    scan_data = json.loads(scan_reply["result"]["content"][0]["text"])
    assert scan_data["findings_count"] >= 6
    assert scan_data["ci_gate_failed"] is True
    assert scan_data["openvex"]["@context"] == "https://openvex.dev/ns/v0.2.0"
    assert scan_data["cyclonedx_vex"]["bomFormat"] == "CycloneDX"

    # Call vulnbox_probe on py_integrated_app via MCP
    probe_reply = handle_mcp_request(
        {
            "jsonrpc": "2.0",
            "id": 5,
            "method": "tools/call",
            "params": {
                "name": "vulnbox_probe",
                "arguments": {
                    "repo_path": str(FIXTURES / "py_integrated_app"),
                    "backend": "local",
                    "start_cmd": f"{sys.executable} app.py",
                    "probes": [
                        {
                            "probe_id": "mcp-stripe-probe",
                            "method": "POST",
                            "path": "/checkout",
                            "vulnerable_expectation": {
                                "status_codes": [200],
                                "body_contains": ["succeeded"],
                                "outbound_hosts_contain": ["api.stripe.com"],
                            },
                            "fixed_expectation": {"status_codes": [400]},
                        }
                    ],
                },
            },
        }
    )
    assert probe_reply is not None and probe_reply["result"]["isError"] is False
    probe_data = json.loads(probe_reply["result"]["content"][0]["text"])
    assert probe_data["results"][0]["matched_vulnerable"] is True

    # Test Content-Length stdio transport framing
    msg = json.dumps({"jsonrpc": "2.0", "id": 9, "method": "ping"})
    framed = f"Content-Length: {len(msg.encode('utf-8'))}\r\n\r\n{msg}"
    out_buf = io.StringIO()
    serve_mcp_stdio(stdin=io.StringIO(framed), stdout=out_buf)
    raw_out = out_buf.getvalue()
    assert raw_out.startswith("Content-Length:")
    body = raw_out.split("\r\n\r\n", 1)[1]
    assert json.loads(body)["id"] == 9


def test_reference_go_plugin_pack_registration_and_detection():
    go_plugin_src = REPO_ROOT / "plugins" / "vulnbox-go" / "src"
    sys.path.insert(0, str(go_plugin_src))
    try:
        import vulnbox_go  # type: ignore[import-not-found]

        reg = PluginRegistry()
        vulnbox_go.register(reg)

        findings = run_all_analyzers(FIXTURES / "go_sample_app", registry=reg)
        rules = {f.rule_id for f in findings}
        assert rules == {"GO-CMD-001", "GO-SQL-001", "GO-TLS-001", "GO-PATH-001", "GO-SSRF-001"}
    finally:
        sys.path.remove(str(go_plugin_src))


def test_distribution_and_ci_artifacts_are_valid():
    action = yaml.safe_load((REPO_ROOT / "action.yml").read_text(encoding="utf-8"))
    assert "runs" in action and action["runs"]["using"] == "composite"

    hooks = yaml.safe_load((REPO_ROOT / ".pre-commit-hooks.yaml").read_text(encoding="utf-8"))
    assert isinstance(hooks, list) and hooks[0]["id"] == "vulnbox-scan"

    release_wf = yaml.safe_load(
        (REPO_ROOT / ".github" / "workflows" / "release.yml").read_text(encoding="utf-8")
    )
    assert "build-and-publish" in release_wf["jobs"]

    threat_model = (REPO_ROOT / "docs" / "threat-model.md").read_text(encoding="utf-8")
    assert "Trust Boundaries" in threat_model and "--network=none" in threat_model
