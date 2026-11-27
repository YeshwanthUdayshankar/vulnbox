"""Precision regression tests distilled from real-world popular open-source benchmarks."""

from __future__ import annotations

from pathlib import Path

from vulnbox.analyzers.memory_leaks import MemoryLeakAnalyzer
from vulnbox.analyzers.node_sast import NodeSASTAnalyzer
from vulnbox.analyzers.python_sast import PythonSASTAnalyzer


def test_node_sast_skips_minified_bundles_and_regexp_exec(tmp_path: Path):
    (tmp_path / "socket.io.min.js").write_text(
        'var n=/^test/;var a=n.exec(t||"");\n',
        encoding="utf-8",
    )
    (tmp_path / "parser.js").write_text(
        'const pattern = /^foo/;\nfunction run(t) { return pattern.exec(t + "bar"); }\n',
        encoding="utf-8",
    )
    findings = NodeSASTAnalyzer().analyze(tmp_path)
    assert [f for f in findings if f.rule_id == "JS-CMD-001"] == []


def test_memory_leaks_respects_open_followed_by_with_and_browser_ready_interval(tmp_path: Path):
    (tmp_path / "loader.py").write_text(
        "def load(p):\n"
        "    try:\n"
        "        f = open(p, 'rb')\n"
        "    except FileNotFoundError:\n"
        "        return None\n"
        "    with f:\n"
        "        return f.read()\n",
        encoding="utf-8",
    )
    static_dir = tmp_path / "app" / "static" / "js"
    static_dir.mkdir(parents=True)
    (static_dir / "clock.js").write_text(
        "$(document).ready(function () {\n"
        "  setInterval(() => { console.log('tick'); }, 1000);\n"
        "});\n",
        encoding="utf-8",
    )
    findings = MemoryLeakAnalyzer().analyze(tmp_path)
    assert [f for f in findings if f.rule_id in ("MEM-PY-003", "MEM-JS-003")] == []


def test_python_sast_skips_regex_guarded_path_join_and_setup_py_and_triages_checksum_md5(tmp_path: Path):
    (tmp_path / "setup.py").write_text(
        "import os\ndef read(name):\n    with open(os.path.join('.', name)) as f:\n        return f.read()\n",
        encoding="utf-8",
    )
    (tmp_path / "safe_cfg.py").write_text(
        "import os, re, hashlib\n"
        "CONFIG_FILE = 'settings.json'\n"
        "def load_cfg(base, name):\n"
        "    if re.fullmatch(r'[A-Za-z0-9_-]+', name):\n"
        "        with open(os.path.join(base, f'{name}.json')) as f:\n"
        "            return f.read()\n"
        "def load_const(base):\n"
        "    with open(os.path.join(base, CONFIG_FILE)) as f:\n"
        "        return f.read()\n"
        "def make_etag(body):\n"
        "    etag_hash = hashlib.md5(body).hexdigest()\n"
        "    return etag_hash\n",
        encoding="utf-8",
    )
    findings = PythonSASTAnalyzer().analyze(tmp_path)
    assert [f for f in findings if f.rule_id == "PY-PATH-001"] == []
    md5_findings = [f for f in findings if f.rule_id == "PY-HASH-001"]
    assert len(md5_findings) == 1
    assert md5_findings[0].severity == "low"


def test_python_path_severity_triage_and_reporting_phase1_to_4_parity(tmp_path: Path):
    from vulnbox.models import (
        AuditReport,
        DynamicProbeResult,
        Finding,
        OutboundCallRecord,
        RepoProfile,
        ScrubSummary,
        VerificationResult,
    )
    from vulnbox.reporting.markdown import render_markdown_report
    from vulnbox.reporting.sarif import build_sarif, validate_sarif

    (tmp_path / "paths.py").write_text(
        "import os\n"
        "def internal_helper(base, ts):\n"
        "    p = os.path.join(base, f'snapshot-{ts}.txt')\n"
        "    with open(p) as f:\n"
        "        return f.read()\n"
        "def read_user_file(base, filename):\n"
        "    p = os.path.join(base, filename)\n"
        "    with open(p) as f:\n"
        "        return f.read()\n",
        encoding="utf-8",
    )
    findings = PythonSASTAnalyzer().analyze(tmp_path)
    by_fn = {f.metadata["function"]: f for f in findings if f.rule_id == "PY-PATH-001"}
    assert by_fn["internal_helper"].severity == "low"
    assert by_fn["read_user_file"].severity == "high"

    # Verify Markdown & SARIF render skipped probe + outbound SSRF canary calls cleanly
    f_skip = Finding(
        finding_id="F-SKIP",
        rule_id="PY-YAML-001",
        cwe_id="CWE-502",
        title="YAML",
        category="sast",
        severity="high",
        file_path="app.py",
        message="msg",
        recommended_fix="fix",
    )
    f_ssrf = Finding(
        finding_id="F-SSRF",
        rule_id="PY-SSRF-001",
        cwe_id="CWE-918",
        title="SSRF",
        category="sast",
        severity="high",
        file_path="app.py",
        message="msg",
        recommended_fix="fix",
    )
    report = AuditReport(
        tool_version="0.1.0",
        timestamp="2026-11-26T00:00:00Z",
        sandbox_backend="local",
        profile=RepoProfile(repo_path=str(tmp_path), ecosystem="python"),
        scrub_summary=ScrubSummary(sandbox_dir=str(tmp_path)),
        findings=[f_skip, f_ssrf],
        verifications=[
            VerificationResult(
                patch_id="p1",
                finding_id="F-SKIP",
                sandbox_backend="local",
                baseline_tests_passed=True,
                patch_applied=True,
                finding_resolved=True,
                no_new_findings=True,
                dynamic_probe_before=DynamicProbeResult(
                    probe_id="pr1",
                    curl_command="curl http://127.0.0.1:$PORT/",
                    skipped=True,
                    skip_reason="Boot skipped: missing dep",
                    probe_mode="http_server",
                ),
                existing_tests_passed_after=True,
                verified=True,
                summary="ok",
            ),
            VerificationResult(
                patch_id="p2",
                finding_id="F-SSRF",
                sandbox_backend="local",
                baseline_tests_passed=True,
                patch_applied=True,
                finding_resolved=True,
                no_new_findings=True,
                dynamic_probe_before=DynamicProbeResult(
                    probe_id="pr2",
                    curl_command="curl http://127.0.0.1:$PORT/fetch",
                    status_code=200,
                    matched_vulnerable=True,
                    probe_mode="in_process",
                    outbound_calls=[
                        OutboundCallRecord(
                            host="169.254.169.254",
                            method="GET",
                            path="/latest/meta-data/",
                            status_code=200,
                        )
                    ],
                ),
                existing_tests_passed_after=True,
                verified=True,
                summary="ok",
            ),
        ],
    )
    md = render_markdown_report(report)
    assert "| SKIPPED |" in md
    assert "Boot skipped: missing dep" in md
    assert "Intercepted Outbound Calls (SSRF Canary)" in md
    assert "169.254.169.254" in md

    sarif = build_sarif(report)
    validate_sarif(sarif)
    res_props = {r["properties"]["findingId"]: r["properties"] for r in sarif["runs"][0]["results"]}
    assert res_props["F-SKIP"]["activeProbeSkipped"] is True
    assert res_props["F-SSRF"]["activeProbeMode"] == "in_process"
    assert res_props["F-SSRF"]["outboundCalls"][0]["host"] == "169.254.169.254"


def test_open_webui_precision_guards(tmp_path: Path):
    """Regression guards distilled from scanning open-webui/open-webui."""
    from vulnbox.analyzers.config_hygiene import ConfigHygieneAnalyzer
    from vulnbox.analyzers.dependency_reachability import DependencyReachabilityAnalyzer
    from vulnbox.analyzers.lockfiles import parse_python_dependencies
    from vulnbox.callgraph.graph import CallGraph
    from vulnbox.models import CallEdge, CallNode

    # 1. JS-SSRF-001 & JS-XSS-001: URLSearchParams query builder & DOMPurify variable tracking
    (tmp_path / "client.ts").write_text(
        "const API_BASE = '/api/v1';\n"
        "export async function listItems(q: string) {\n"
        "  const params = new URLSearchParams();\n"
        "  params.set('q', q);\n"
        "  return fetch(`${API_BASE}/items?${params.toString()}`);\n"
        "}\n"
        "export function renderNote(el: HTMLElement, raw: string) {\n"
        "  const html = DOMPurify.sanitize(raw);\n"
        "  el.innerHTML = html;\n"
        "}\n",
        encoding="utf-8",
    )
    (tmp_path / "real_ssrf.js").write_text(
        "async function handler(req, res) {\n"
        "  const target = req.query.url;\n"
        "  return fetch(`${target}/status`);\n"
        "}\n",
        encoding="utf-8",
    )
    js_findings = NodeSASTAnalyzer().analyze(tmp_path)
    assert [f for f in js_findings if f.file_path == "client.ts" and f.rule_id in ("JS-SSRF-001", "JS-XSS-001")] == []
    assert any(f.file_path == "real_ssrf.js" and f.rule_id == "JS-SSRF-001" for f in js_findings)

    # 2. PY-JWT-001 issuer peek before verified decode & PY-PATH-001 inline realpath().startswith()
    (tmp_path / "auth_and_audio.py").write_text(
        "import os, jwt\n"
        "def verify_logout(logout_token, key):\n"
        "    iss = jwt.decode(logout_token, options={'verify_signature': False}).get('iss')\n"
        "    return jwt.decode(logout_token, key, algorithms=['RS256'], issuer=iss)\n"
        "def save_upload(file_dir, filename):\n"
        "    file_path = os.path.join(file_dir, filename)\n"
        "    if not os.path.realpath(file_path).startswith(os.path.realpath(file_dir)):\n"
        "        raise ValueError('bad path')\n"
        "    with open(file_path, 'wb') as f:\n"
        "        f.write(b'ok')\n",
        encoding="utf-8",
    )
    py_findings = PythonSASTAnalyzer().analyze(tmp_path)
    assert [f for f in py_findings if f.rule_id in ("PY-JWT-001", "PY-PATH-001")] == []

    # 3. MEM-PY-001 add_done_callback(tasks.discard) & MEM-JS-002 -bundle.js skip
    (tmp_path / "tasks.py").write_text(
        "import asyncio\n"
        "_ssh_tasks = set()\n"
        "def start(coro):\n"
        "    t = asyncio.create_task(coro)\n"
        "    _ssh_tasks.add(t)\n"
        "    t.add_done_callback(_ssh_tasks.discard)\n",
        encoding="utf-8",
    )
    (tmp_path / "swagger-ui-bundle.js").write_text(
        "for (var i = 0; i < 10; i++) { s.on('x', fn); }\n",
        encoding="utf-8",
    )
    mem_findings = MemoryLeakAnalyzer().analyze(tmp_path)
    assert [f for f in mem_findings if f.rule_id in ("MEM-PY-001", "MEM-JS-002")] == []

    # 4. CFG-DOCKER-002 --platform flag & CFG-DOCKER-003 TIKTOKEN + empty ENV
    (tmp_path / "Dockerfile").write_text(
        "FROM --platform=$BUILDPLATFORM node:22-alpine3.20 AS build\n"
        'ARG USE_TIKTOKEN_ENCODING_NAME="cl100k_base"\n'
        'ENV OPENAI_API_KEY="" \\\n'
        '    TIKTOKEN_ENCODING_NAME="cl100k_base"\n'
        "USER appuser\n",
        encoding="utf-8",
    )
    cfg_findings = ConfigHygieneAnalyzer().analyze(tmp_path)
    assert [f for f in cfg_findings if f.rule_id in ("CFG-DOCKER-002", "CFG-DOCKER-003")] == []

    # 5. Lockfile dedup (root uv.lock vs backend/requirements.txt) & cross-ecosystem CG guard
    (tmp_path / "uv.lock").write_text(
        '[[package]]\nname = "black"\nversion = "26.5.1"\n',
        encoding="utf-8",
    )
    backend = tmp_path / "backend"
    backend.mkdir()
    (backend / "requirements.txt").write_text("black==26.5.1\n", encoding="utf-8")
    py_deps = parse_python_dependencies(tmp_path)
    assert len([d for d in py_deps if d.name == "black"]) == 1

    # Node uuid package must NOT match Python external::uuid.uuid4 in call graph
    (tmp_path / "package-lock.json").write_text(
        '{"lockfileVersion": 3, "packages": {"node_modules/uuid": {"version": "8.3.2"}}}',
        encoding="utf-8",
    )
    adv_file = tmp_path / "adv.json"
    adv_file.write_text(
        '[{"advisory_id":"CVE-2099-0001","ecosystem":"node","package":"uuid",'
        '"affected_below":"9.0.0","fixed_version":"9.0.0","severity":"medium",'
        '"cwe_id":"CWE-330","title":"Test uuid","imports":["uuid"],"vulnerable_symbols":[]}]',
        encoding="utf-8",
    )
    cg = CallGraph()
    cg.add_node(CallNode(node_id="backend/app.py::handler", symbol="handler", file_path="backend/app.py", line=1, is_entrypoint=True))
    cg.add_node(CallNode(node_id="external::uuid.uuid4", symbol="uuid4", file_path="<external>", line=0))
    cg.add_edge(CallEdge(caller="backend/app.py::handler", callee="external::uuid.uuid4", file_path="backend/app.py", line=2, provenance="static_exact"))
    dep_findings = DependencyReachabilityAnalyzer(adv_file).analyze(tmp_path, call_graph=cg)
    assert len(dep_findings) == 1
    assert dep_findings[0].reachability == "not_reachable"
    assert "call_path" not in dep_findings[0].metadata
