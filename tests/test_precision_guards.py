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
