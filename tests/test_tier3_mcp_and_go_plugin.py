"""Tests for Tier 3: hardened stdio MCP server, Go plugin (SAST + go.mod OSV reachability),
pinned/injection-safe CI & release workflows, and threat model."""

from __future__ import annotations

import io
import json
import re
import sys
from pathlib import Path

import yaml

from vulnbox.analyzers import run_all_analyzers
from vulnbox.mcp_server import handle_mcp_request, serve_mcp_stdio
from vulnbox.registry import PluginRegistry

REPO_ROOT = Path(__file__).resolve().parents[1]
FIXTURES = Path(__file__).parent / "fixtures"
SHA_PIN_RE = re.compile(r"@[0-9a-f]{40}$")


def test_mcp_server_defaults_to_docker_refuses_local_by_default_and_enforces_guardrails():
    init = handle_mcp_request({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}})
    assert init is not None
    assert init["result"]["serverInfo"]["name"] == "vulnbox"

    listed = handle_mcp_request({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
    assert listed is not None
    tools_by_name = {t["name"]: t for t in listed["result"]["tools"]}
    assert set(tools_by_name) == {"vulnbox_profile", "vulnbox_scan", "vulnbox_probe", "vulnbox_verify_patch"}
    # Schema defaults MUST be docker (never auto)
    for tname in ("vulnbox_scan", "vulnbox_probe", "vulnbox_verify_patch"):
        assert tools_by_name[tname]["inputSchema"]["properties"]["backend"]["default"] == "docker"

    # 1. Default MCP (allow_local=False) ALLOWS pure static vulnbox_scan (no repo code executed)
    #    even without Docker, but REFUSES executing calls (deep=True, vulnbox_probe, vulnbox_verify_patch) with backend="local"!
    static_ok = handle_mcp_request(
        {
            "jsonrpc": "2.0",
            "id": 99,
            "method": "tools/call",
            "params": {
                "name": "vulnbox_scan",
                "arguments": {"repo_path": str(FIXTURES / "py_sample_app"), "backend": "local"},
            },
        }
    )
    assert static_ok is not None and static_ok["result"]["isError"] is False

    refused_deep = handle_mcp_request(
        {
            "jsonrpc": "2.0",
            "id": 10,
            "method": "tools/call",
            "params": {
                "name": "vulnbox_scan",
                "arguments": {
                    "repo_path": str(FIXTURES / "py_sample_app"),
                    "backend": "local",
                    "deep": True,
                },
            },
        }
    )
    assert refused_deep is not None and refused_deep["result"]["isError"] is True
    assert "--allow-local" in refused_deep["result"]["content"][0]["text"]

    refused_probe = handle_mcp_request(
        {
            "jsonrpc": "2.0",
            "id": 101,
            "method": "tools/call",
            "params": {
                "name": "vulnbox_probe",
                "arguments": {
                    "repo_path": str(FIXTURES / "py_integrated_app"),
                    "backend": "local",
                    "probes": [
                        {
                            "probe_id": "p0",
                            "method": "GET",
                            "path": "/health",
                            "vulnerable_expectation": {"status_codes": [200]},
                            "fixed_expectation": {"status_codes": [200]},
                        }
                    ],
                },
            },
        }
    )
    assert refused_probe is not None and refused_probe["result"]["isError"] is True
    assert "--allow-local" in refused_probe["result"]["content"][0]["text"]

    # 2. Guardrails MUST block shell injection / inline eval in start_cmd even when allow_local=True
    for bad_cmd in ("python3 -c 'import os; os.system(\"id\")'", "uvicorn app:app; id", "bash -c whoami"):
        blocked = handle_mcp_request(
            {
                "jsonrpc": "2.0",
                "id": 11,
                "method": "tools/call",
                "params": {
                    "name": "vulnbox_probe",
                    "arguments": {
                        "repo_path": str(FIXTURES / "py_integrated_app"),
                        "backend": "local",
                        "start_cmd": bad_cmd,
                        "probes": [
                            {
                                "probe_id": "p1",
                                "method": "GET",
                                "path": "/health",
                                "vulnerable_expectation": {"status_codes": [200]},
                                "fixed_expectation": {"status_codes": [200]},
                            }
                        ],
                    },
                },
            },
            allow_local=True,
        )
        assert blocked is not None and blocked["result"]["isError"] is True
        assert "start_cmd_safety_gate" in blocked["result"]["content"][0]["text"]

    # 3. Guardrails MUST block protected-path diffs & malicious regression tests in vulnbox_verify_patch
    bad_patch = handle_mcp_request(
        {
            "jsonrpc": "2.0",
            "id": 12,
            "method": "tools/call",
            "params": {
                "name": "vulnbox_verify_patch",
                "arguments": {
                    "repo_path": str(FIXTURES / "py_sample_app"),
                    "backend": "local",
                    "unified_diff": "--- a/.env\n+++ b/.env\n@@ -1 +1 @@\n-A=1\n+A=2\n",
                },
            },
        },
        allow_local=True,
    )
    assert bad_patch is not None and bad_patch["result"]["isError"] is True
    assert "diff_safety_gate" in bad_patch["result"]["content"][0]["text"]

    # 4. With explicit allow_local=True and safe inputs, profile/scan/probe work end-to-end
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
    assert json.loads(prof_reply["result"]["content"][0]["text"])["profile"]["ecosystem"] == "python"

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
        },
        allow_local=True,
    )
    assert scan_reply is not None and scan_reply["result"]["isError"] is False
    scan_data = json.loads(scan_reply["result"]["content"][0]["text"])
    assert scan_data["findings_count"] >= 6
    assert scan_data["ci_gate_failed"] is True
    assert scan_data["openvex"]["@context"] == "https://openvex.dev/ns/v0.2.0"
    assert scan_data["cyclonedx_vex"]["bomFormat"] == "CycloneDX"

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
        },
        allow_local=True,
    )
    assert probe_reply is not None and probe_reply["result"]["isError"] is False
    assert json.loads(probe_reply["result"]["content"][0]["text"])["results"][0]["matched_vulnerable"] is True

    # Test Content-Length stdio transport framing
    msg = json.dumps({"jsonrpc": "2.0", "id": 9, "method": "ping"})
    framed = f"Content-Length: {len(msg.encode('utf-8'))}\r\n\r\n{msg}"
    out_buf = io.StringIO()
    serve_mcp_stdio(stdin=io.StringIO(framed), stdout=out_buf)
    raw_out = out_buf.getvalue()
    assert raw_out.startswith("Content-Length:")
    assert json.loads(raw_out.split("\r\n\r\n", 1)[1])["id"] == 9


def test_reference_go_plugin_pack_sast_reachability_and_gomod_osv_symbols(tmp_path: Path):
    go_plugin_src = REPO_ROOT / "plugins" / "vulnbox-go" / "src"
    sys.path.insert(0, str(go_plugin_src))
    try:
        import vulnbox_go  # type: ignore[import-not-found]

        reg = PluginRegistry()
        vulnbox_go.register(reg)

        # 1. Fixture SAST: HTTP handler findings -> reachable, non-handler helper -> under_investigation
        findings = run_all_analyzers(FIXTURES / "go_sample_app", registry=reg)
        by_rule = {f.rule_id: f for f in findings}
        assert set(by_rule) == {"GO-CMD-001", "GO-SQL-001", "GO-TLS-001", "GO-PATH-001", "GO-SSRF-001"}
        assert by_rule["GO-TLS-001"].reachability == "under_investigation"  # inside insecureClient()
        assert by_rule["GO-CMD-001"].reachability == "reachable"  # inside runHandler(w, r, db)

        # 2. go.mod + Go OSV symbol-level reachability (reachable vs safe-symbols-only vs unimported)
        go_reach = tmp_path / "go_reach"
        go_reach.mkdir()
        (go_reach / "go.mod").write_text(
            "module example.com/demo\n\ngo 1.22\n\nrequire (\n\tgolang.org/x/net v0.15.0\n)\n",
            encoding="utf-8",
        )
        (go_reach / "server.go").write_text(
            'package main\nimport (\n\t"net/http"\n\t"golang.org/x/net/http2"\n)\n'
            "func main() {\n\tvar s http.Server\n\t_ = http2.ConfigureServer(&s, nil)\n}\n",
            encoding="utf-8",
        )
        dep_reach = [
            f for f in run_all_analyzers(go_reach, registry=reg) if f.rule_id == "DEP-GO-2023-2102"
        ]
        assert len(dep_reach) == 1 and dep_reach[0].reachability == "reachable"

        # Imported golang.org/x/net/http2 calling an UNRELATED other.ConfigureServer() MUST NOT match!
        # Sole module in go.mod using only safe http2.Transport -> not_reachable
        go_safe = tmp_path / "go_safe"
        go_safe.mkdir()
        (go_safe / "go.mod").write_text(
            "module example.com/safe\n\ngo 1.22\n\nrequire golang.org/x/net v0.15.0\n",
            encoding="utf-8",
        )
        (go_safe / "client.go").write_text(
            'package main\nimport "golang.org/x/net/http2"\n'
            "func main() {\n\t_ = http2.Transport{}\n\tother.ConfigureServer()\n}\n",
            encoding="utf-8",
        )
        dep_safe = [
            f for f in run_all_analyzers(go_safe, registry=reg) if f.rule_id == "DEP-GO-2023-2102"
        ]
        assert len(dep_safe) == 1 and dep_safe[0].reachability == "not_reachable"
        assert dep_safe[0].metadata["reachability_basis"] == "imported_safe_symbols_no_dependents"

        # Multiple modules in go.mod -> other deps might call http2 transitively -> MUST stay under_investigation
        go_multi = tmp_path / "go_multi"
        go_multi.mkdir()
        (go_multi / "go.mod").write_text(
            "module example.com/multi\n\ngo 1.22\n\nrequire (\n"
            "\tgolang.org/x/net v0.15.0\n"
            "\tgithub.com/example/other v1.0.0\n)\n",
            encoding="utf-8",
        )
        (go_multi / "client.go").write_text(
            'package main\nimport "golang.org/x/net/http2"\nfunc main() { _ = http2.Transport{} }\n',
            encoding="utf-8",
        )
        dep_multi = [
            f for f in run_all_analyzers(go_multi, registry=reg) if f.rule_id == "DEP-GO-2023-2102"
        ]
        assert len(dep_multi) == 1 and dep_multi[0].reachability == "under_investigation"

        # Go stdlib CVE via `go 1.21.1` directive in go.mod (reachable via net/http.ListenAndServe)
        go_stdlib = tmp_path / "go_stdlib"
        go_stdlib.mkdir()
        (go_stdlib / "go.mod").write_text("module example.com/std\n\ngo 1.21.1\n", encoding="utf-8")
        (go_stdlib / "srv.go").write_text(
            'package main\nimport "net/http"\nfunc main() { _ = http.ListenAndServe(":8080", nil) }\n',
            encoding="utf-8",
        )
        stdlib_hits = [
            f for f in run_all_analyzers(go_stdlib, registry=reg) if f.rule_id == "DEP-GO-2023-2102-STDLIB"
        ]
        assert len(stdlib_hits) == 1 and stdlib_hits[0].reachability == "reachable"

        # Unimported in go.mod -> under_investigation (NEVER false not_affected)
        go_unimp = tmp_path / "go_unimp"
        go_unimp.mkdir()
        (go_unimp / "go.mod").write_text(
            "module example.com/unimp\n\ngo 1.22\n\nrequire golang.org/x/net v0.15.0\n",
            encoding="utf-8",
        )
        (go_unimp / "main.go").write_text('package main\nfunc main() {}\n', encoding="utf-8")
        dep_unimp = [
            f for f in run_all_analyzers(go_unimp, registry=reg) if f.rule_id == "DEP-GO-2023-2102"
        ]
        assert len(dep_unimp) == 1 and dep_unimp[0].reachability == "under_investigation"
    finally:
        sys.path.remove(str(go_plugin_src))


def test_distribution_and_ci_artifacts_are_hardened():
    action_raw = (REPO_ROOT / "action.yml").read_text(encoding="utf-8")
    action = yaml.safe_load(action_raw)
    assert "runs" in action and action["runs"]["using"] == "composite"
    for step in action["runs"]["steps"]:
        if "run" in step:
            assert "${{ inputs." not in step["run"], "Expression injection found in action.yml run:"
            assert "${{ github." not in step["run"], "Expression injection found in action.yml run:"
        if "uses" in step:
            assert SHA_PIN_RE.search(step["uses"]), f"Action not SHA-pinned: {step['uses']}"

    hooks = yaml.safe_load((REPO_ROOT / ".pre-commit-hooks.yaml").read_text(encoding="utf-8"))
    assert isinstance(hooks, list) and hooks[0]["id"] == "vulnbox-scan"

    for wf_path in (
        REPO_ROOT / ".github" / "workflows" / "release.yml",
        REPO_ROOT / ".github" / "workflows" / "ci.yml",
    ):
        wf = yaml.safe_load(wf_path.read_text(encoding="utf-8"))
        for job in wf["jobs"].values():
            for step in job["steps"]:
                if "uses" in step:
                    assert SHA_PIN_RE.search(step["uses"]), f"{wf_path.name} not SHA-pinned: {step['uses']}"

    release_wf = yaml.safe_load(
        (REPO_ROOT / ".github" / "workflows" / "release.yml").read_text(encoding="utf-8")
    )
    assert "verify" in release_wf["jobs"]
    assert release_wf["jobs"]["build-and-publish"]["needs"] == "verify"

    threat_model = (REPO_ROOT / "docs" / "threat-model.md").read_text(encoding="utf-8")
    assert "Trust Boundaries" in threat_model and "--network=none" in threat_model
    assert "pull_request_target" in threat_model and "--allow-local" in threat_model

    # SARIF subset schema: suppressions belongs on results[], NOT on tool.driver.rules[]
    sarif_schema = json.loads(
        (REPO_ROOT / "src" / "vulnbox" / "schemas" / "sarif_2_1_0.schema.json").read_text(encoding="utf-8")
    )
    run_props = sarif_schema["properties"]["runs"]["items"]["properties"]
    rule_props = run_props["tool"]["properties"]["driver"]["properties"]["rules"]["items"]["properties"]
    result_props = run_props["results"]["items"]["properties"]
    assert "suppressions" not in rule_props
    assert "suppressions" in result_props
