"""Tests for Phase 1: dependency-layer builder, target .venv reuse, and graceful boot-skip."""

from __future__ import annotations

import json
import sys
from pathlib import Path

from vulnbox.models import (
    DynamicProbeSpec,
    PatchCandidate,
    ProbeExpectation,
    RepoProfile,
)
from vulnbox.remediation.dynamic_probe import classify_boot_skip_error, run_dynamic_probe
from vulnbox.remediation.verifier import verify_patch
from vulnbox.sandbox.dep_builder import (
    compute_dependency_hash,
    discover_top_level_manifests,
    prepare_manifest_build_context,
)
from vulnbox.sandbox.docker_backend import DockerSandboxBackend
from vulnbox.sandbox.local_backend import LocalSandboxBackend, find_target_venv_bin


def test_manifest_only_build_context_excludes_source_and_secrets(tmp_path: Path):
    repo = tmp_path / "app"
    repo.mkdir()
    (repo / "requirements.txt").write_text("fastapi==0.115.0\n", encoding="utf-8")
    (repo / "package.json").write_text(json.dumps({"dependencies": {"express": "^4.19.0"}}), encoding="utf-8")
    (repo / ".env").write_text("API_SECRET=super_secret_should_never_copy\n", encoding="utf-8")
    (repo / "app.py").write_text("print('proprietary code')\n", encoding="utf-8")

    manifests = discover_top_level_manifests(repo)
    assert sorted(m.name for m in manifests) == ["package.json", "requirements.txt"]

    h1, m1 = compute_dependency_hash(repo)
    h2, _ = compute_dependency_hash(repo)
    assert h1 == h2 and len(h1) == 12
    assert len(m1) == 2

    ctx = tmp_path / "ctx"
    df_path, copied = prepare_manifest_build_context(repo, ctx, base_image="vulnbox-sandbox:latest")
    dockerfile = df_path.read_text(encoding="utf-8")

    assert sorted(copied) == ["package.json", "requirements.txt"]
    assert (ctx / "requirements.txt").is_file()
    assert (ctx / "package.json").is_file()
    assert not (ctx / ".env").exists()
    assert not (ctx / "app.py").exists()
    assert "--ignore-scripts" in dockerfile
    assert "pip install --no-cache-dir" in dockerfile


def test_local_backend_auto_reuses_target_repo_venv(tmp_path: Path):
    repo = tmp_path / "repo_with_venv"
    venv_bin = repo / ".venv" / "bin"
    venv_bin.mkdir(parents=True)
    py_stub = venv_bin / "python3"
    py_stub.write_text("#!/bin/sh\necho PYTHON_STUB\n", encoding="utf-8")
    py_stub.chmod(0o755)
    helper = venv_bin / "vb_fake_tool"
    helper.write_text("#!/bin/sh\necho VENV_TOOL_OK\n", encoding="utf-8")
    helper.chmod(0o755)

    assert find_target_venv_bin(repo) == venv_bin.resolve()

    ws = tmp_path / "ws"
    ws.mkdir()
    backend = LocalSandboxBackend(target_repo_path=repo)
    res = backend.run(ws, "vb_fake_tool")
    assert res.exit_code == 0
    assert "VENV_TOOL_OK" in res.stdout


def test_docker_backend_network_override():
    backend = DockerSandboxBackend(image="vulnbox-deps:abc123", network_override="vulnbox-net-test")
    cmd = backend.build_command(Path("/tmp"), "echo hi")
    assert "--network" in cmd
    assert "vulnbox-net-test" in cmd
    assert "--network=none" not in cmd
    assert "vulnbox-deps:abc123" in cmd


def test_boot_skip_classification_and_graceful_verify_patch(tmp_path: Path):
    assert classify_boot_skip_error("ModuleNotFoundError: No module named 'django'") is not None
    assert classify_boot_skip_error("Error: Cannot find module 'express'") is not None
    assert classify_boot_skip_error("ConnectionRefusedError: [Errno 111]") is not None
    assert classify_boot_skip_error("AssertionError: wrong status") is None

    # Create a tiny repo whose server fails to boot with ModuleNotFoundError
    repo = tmp_path / "missing_dep_repo"
    repo.mkdir()
    (repo / "app.py").write_text("import nonexistent_third_party_pkg_xyz\n", encoding="utf-8")
    (repo / "util.py").write_text("import yaml\n\ndef parse(s):\n    return yaml.load(s)\n", encoding="utf-8")

    spec = DynamicProbeSpec(
        probe_id="probe-missing-dep",
        rule_id="PY-YAML-001",
        method="GET",
        path="/health",
        vulnerable_expectation=ProbeExpectation(status_codes=[200]),
        fixed_expectation=ProbeExpectation(status_codes=[400]),
    )
    backend = LocalSandboxBackend()
    probe_res = run_dynamic_probe(
        repo,
        backend=backend,
        start_cmd=f"{sys.executable} app.py",
        spec=spec,
        allow_inprocess_fallback=False,
    )
    assert probe_res.skipped is True
    assert probe_res.skip_reason is not None and "ModuleNotFoundError" in probe_res.skip_reason

    # Verify that verify_patch treats skipped dynamic probe as dynamic_confirmed_and_fixed=None
    # rather than falsely failing verification!
    diff = (
        "--- a/util.py\n"
        "+++ b/util.py\n"
        "@@ -1,4 +1,4 @@\n"
        " import yaml\n"
        " \n"
        " def parse(s):\n"
        "-    return yaml.load(s)\n"
        "+    return yaml.safe_load(s)\n"
    )
    patch = PatchCandidate(
        patch_id="patch-yaml",
        finding_id="TEST-YAML-1",
        rule_id="PY-YAML-001",
        strategy="minimal_code_fix",
        description="Use safe_load",
        unified_diff=diff,
        probe_spec=spec,
    )
    prof = RepoProfile(
        repo_path=str(repo),
        ecosystem="python",
        start_command=f"{sys.executable} app.py",
    )
    ver = verify_patch(
        repo_path=repo,
        profile=prof,
        patch=patch,
        backend=backend,
        probe_spec=spec,
    )
    assert ver.dynamic_probe_before is not None
    assert ver.dynamic_probe_before.skipped is True
    assert ver.dynamic_confirmed_and_fixed is None
    assert ver.verified is True
