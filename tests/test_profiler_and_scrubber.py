"""Tests for repository profiling and pre-sandbox secret scrubbing."""

from pathlib import Path

from vulnbox.profiler import profile_repo
from vulnbox.scrubber import cleanup_workspace, create_scrubbed_workspace

FIXTURES = Path(__file__).parent / "fixtures"


def test_profile_python_repo():
    prof = profile_repo(FIXTURES / "py_sample_app")
    assert prof.ecosystem == "python"
    assert "requirements.txt" in prof.manifests
    assert "Dockerfile" in prof.dockerfiles
    assert ".env" in prof.env_files
    assert "python" in prof.test_commands
    assert prof.start_command is not None and "app.py" in prof.start_command


def test_profile_node_repo():
    prof = profile_repo(FIXTURES / "node_sample_app")
    assert prof.ecosystem == "node"
    assert "package.json" in prof.manifests
    assert "node" in prof.test_commands
    assert prof.start_command == "node server.mjs"


def test_scrubber_redacts_env_without_mutating_source():
    src_repo = FIXTURES / "py_sample_app"
    orig_env = (src_repo / ".env").read_text(encoding="utf-8")
    assert "super_secret_pw" in orig_env

    scrub = create_scrubbed_workspace(src_repo)
    ws = Path(scrub.sandbox_dir)
    try:
        assert ".env" in scrub.files_scrubbed
        assert scrub.secrets_redacted >= 2
        scrubbed_env = (ws / ".env").read_text(encoding="utf-8")
        assert "super_secret_pw" not in scrubbed_env
        assert "REDACTED_BY_VULNBOX_DATABASE_URL" in scrubbed_env
        assert "REDACTED_BY_VULNBOX_API_TOKEN" in scrubbed_env
        # Original file untouched
        assert (src_repo / ".env").read_text(encoding="utf-8") == orig_env
    finally:
        cleanup_workspace(ws)
        assert not ws.exists()
