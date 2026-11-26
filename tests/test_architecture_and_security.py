"""Tests for Phase 1 security hardening and Phase 2 plugin/engine extensibility."""

from __future__ import annotations

import subprocess
from pathlib import Path
from unittest.mock import patch

import pytest

from vulnbox import AnalysisContext, PluginRegistry, ScrubbedWorkspace, VulnBoxEngine
from vulnbox.llm.client import validate_llm_base_url
from vulnbox.models import AuditReport, Finding, PatchCandidate
from vulnbox.remediation.diff_utils import make_unified_diff
from vulnbox.sandbox.base import SandboxPolicy
from vulnbox.sandbox.docker_backend import DockerSandboxBackend
from vulnbox.sandbox.local_backend import LocalSandboxBackend


def test_docker_hardening_env_validation_and_timeout_cleanup(tmp_path: Path):
    be = DockerSandboxBackend()
    cmd = be.build_command(tmp_path, "echo hi", container_name="vulnbox-test123")
    assert "--init" in cmd
    assert "--ipc=none" in cmd
    assert "--ulimit" in cmd
    assert "nofile=512:512" in cmd
    assert "--name" in cmd and "vulnbox-test123" in cmd

    with pytest.raises(ValueError, match="Invalid environment variable"):
        be.build_command(tmp_path, "echo hi", env={"BAD-KEY": "1"})

    with pytest.raises(ValueError, match="disallowed control characters"):
        be.build_command(tmp_path, "echo hi", env={"OK_KEY": "line1\nline2"})

    removed: list[str] = []

    def fake_run(args, **_kwargs):
        if args[:2] == ["docker", "run"]:
            raise subprocess.TimeoutExpired(cmd=args, timeout=1)
        if args[:3] == ["docker", "rm", "-f"]:
            removed.append(args[3])
            return subprocess.CompletedProcess(args, 0, "", "")
        raise AssertionError(f"Unexpected call: {args}")

    with patch("vulnbox.sandbox.docker_backend.subprocess.run", side_effect=fake_run):
        res = be.run(tmp_path, "sleep 30", policy=SandboxPolicy(timeout_sec=1))
    assert res.timed_out is True
    assert res.exit_code == 124
    assert len(removed) == 1 and removed[0].startswith("vulnbox-")


def test_local_sandbox_kills_process_group_and_cleans_tmp_home(tmp_path: Path):
    before_dirs = set(Path("/tmp").glob("vulnbox-home-*"))
    be = LocalSandboxBackend()
    res = be.run(tmp_path, "sleep 15", policy=SandboxPolicy(timeout_sec=1))
    after_dirs = set(Path("/tmp").glob("vulnbox-home-*"))

    assert res.timed_out is True
    assert res.exit_code == 124
    # Temporary home directory must be cleaned up automatically
    assert after_dirs - before_dirs == set()


def test_llm_base_url_blocks_file_scheme_and_cloud_metadata():
    validate_llm_base_url("http://127.0.0.1:11434/v1")
    validate_llm_base_url("https://api.openai.com/v1")

    with pytest.raises(ValueError, match="Unsupported LLM base URL scheme"):
        validate_llm_base_url("file:///etc/passwd")

    with pytest.raises(ValueError, match="link-local/metadata"):
        validate_llm_base_url("http://169.254.169.254/latest/meta-data")

    with pytest.raises(ValueError, match="link-local/metadata"):
        validate_llm_base_url("http://metadata.google.internal/computeMetadata/v1")


def test_scrubbed_workspace_context_manager_cleans_up_on_error(tmp_path: Path):
    (tmp_path / "hello.py").write_text("print('hi')\n", encoding="utf-8")
    ws_path: Path | None = None
    with pytest.raises(RuntimeError, match="boom"):
        with ScrubbedWorkspace(tmp_path) as sws:
            ws_path = sws.path
            assert ws_path.is_dir()
            raise RuntimeError("boom")
    assert ws_path is not None and not ws_path.exists()


def test_plugin_registry_and_engine_sdk_extensibility(tmp_path: Path):
    """Prove custom analyzer + patcher + regression test + reporter plug in cleanly."""
    repo = tmp_path / "custom_repo"
    repo.mkdir()
    (repo / "config.txt").write_text("ALLOW_INSECURE=true\n", encoding="utf-8")

    reg = PluginRegistry()

    class CustomConfigAnalyzer:
        name = "custom-config"

        def run(self, ctx: AnalysisContext) -> list[Finding]:
            cfg = ctx.workspace_dir / "config.txt"
            if cfg.is_file() and "ALLOW_INSECURE=true" in cfg.read_text(encoding="utf-8"):
                return [
                    Finding(
                        finding_id="CUSTOM-CFG-001-aaaa1111",
                        rule_id="CUSTOM-CFG-001",
                        cwe_id="CWE-16",
                        title="Insecure Config Flag Enabled",
                        category="config",
                        severity="high",
                        file_path="config.txt",
                        start_line=1,
                        end_line=1,
                        message="ALLOW_INSECURE=true is enabled",
                        recommended_fix="Set ALLOW_INSECURE=false",
                    )
                ]
            return []

    class CustomSummaryReporter:
        name = "summary_txt"

        def write(self, report: AuditReport, out_dir: Path) -> Path:
            out = out_dir / "summary.txt"
            out.write_text(f"findings={len(report.findings)}\n", encoding="utf-8")
            return out

    reg.register_analyzer(CustomConfigAnalyzer())
    reg.register_reporter(CustomSummaryReporter())

    @reg.register_patcher("CUSTOM-CFG-001")
    def _patch_custom(finding: Finding, ws: Path) -> PatchCandidate | None:
        old = (ws / "config.txt").read_text(encoding="utf-8")
        new = old.replace("ALLOW_INSECURE=true", "ALLOW_INSECURE=false")
        return PatchCandidate(
            patch_id=f"patch-{finding.finding_id}",
            finding_id=finding.finding_id,
            rule_id=finding.rule_id,
            strategy="config_hardening",
            description="Disable ALLOW_INSECURE",
            unified_diff=make_unified_diff("config.txt", old, new),
        )

    @reg.register_regression_test("CUSTOM-CFG-001")
    def _reg_custom(_finding: Finding) -> tuple[str, str]:
        return (
            "tests/test_security_custom_cfg.py",
            "from pathlib import Path\ndef test_cfg():\n    assert 'ALLOW_INSECURE=false' in Path('config.txt').read_text()\n",
        )

    out_dir = tmp_path / "out"
    engine = VulnBoxEngine(backend="local", registry=reg)
    report, written = engine.remediate(repo, out_dir=out_dir)

    assert len(report.findings) == 1
    assert len(report.verifications) == 1
    assert report.verifications[0].verified is True
    assert "summary_txt" in written
    assert written["summary_txt"].read_text(encoding="utf-8") == "findings=1\n"
    # Original repo untouched
    assert (repo / "config.txt").read_text(encoding="utf-8") == "ALLOW_INSECURE=true\n"
