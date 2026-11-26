"""Tests for loopback enforcement and active dynamic probe runner."""

from pathlib import Path

import pytest

from vulnbox.models import DynamicProbeSpec, ProbeExpectation
from vulnbox.profiler import profile_repo
from vulnbox.remediation.dynamic_probe import run_dynamic_probe, validate_loopback_url
from vulnbox.sandbox import LocalSandboxBackend
from vulnbox.scrubber import cleanup_workspace, create_scrubbed_workspace

FIXTURES = Path(__file__).parent / "fixtures"


def test_loopback_url_guard_rejects_external_hosts():
    validate_loopback_url("http://127.0.0.1:8080/health")
    validate_loopback_url("http://localhost:3000/api/data")

    with pytest.raises(ValueError, match="Refusing non-loopback"):
        validate_loopback_url("https://example.com/api")

    with pytest.raises(ValueError, match="Refusing non-loopback"):
        validate_loopback_url("http://169.254.169.254/latest/meta-data")


def test_active_probe_reproduces_python_yaml_vulnerability():
    repo = FIXTURES / "py_sample_app"
    prof = profile_repo(repo)
    scrub = create_scrubbed_workspace(repo)
    ws = Path(scrub.sandbox_dir)
    try:
        spec = DynamicProbeSpec(
            probe_id="probe-yaml-live",
            rule_id="PY-YAML-001",
            description="Active YAML tag probe",
            method="POST",
            path="/parse",
            headers={"Content-Type": "text/plain"},
            body="!!python/tuple [1, 2]",
            vulnerable_expectation=ProbeExpectation(status_codes=[200]),
            fixed_expectation=ProbeExpectation(status_codes=[400]),
        )
        res = run_dynamic_probe(
            ws,
            backend=LocalSandboxBackend(),
            start_cmd=prof.start_command or "",
            spec=spec,
            health_path="/health",
        )
        assert res.error is None
        assert res.status_code == 200
        assert res.matched_vulnerable is True
        assert res.matched_fixed is False
        assert "curl" in res.curl_command
        assert "/parse" in res.curl_command
    finally:
        cleanup_workspace(ws)
