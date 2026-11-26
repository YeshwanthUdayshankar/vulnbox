"""Tests for VulnBox local Web UI server, security headers, CSRF protection, and full API parity."""

from __future__ import annotations

import json
import threading
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

from vulnbox.reporting.sarif import validate_sarif
from vulnbox.ui import create_ui_server

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture()
def ui_server():
    server = create_ui_server(host="127.0.0.1", port=0)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{port}", server.csrf_token
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def _post_json(url: str, payload: dict, token: str | None = None) -> tuple[int, dict]:
    headers = {"Content-Type": "application/json"}
    if token is not None:
        headers["X-VulnBox-Token"] = token
    req = urllib.request.Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers=headers,
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read().decode("utf-8"))


def test_ui_refuses_non_loopback_bind_by_default():
    with pytest.raises(ValueError, match="Refusing non-loopback bind host"):
        create_ui_server(host="0.0.0.0", port=0)


def test_ui_serves_html_with_security_headers_and_csrf_protection(ui_server):
    base_url, token = ui_server

    with urllib.request.urlopen(f"{base_url}/", timeout=5) as resp:
        assert resp.status == 200
        hdrs = {k.lower(): v for k, v in resp.headers.items()}
        csp = hdrs["content-security-policy"]
        assert "script-src 'self'" in csp
        assert "unsafe-inline" not in csp
        assert hdrs["x-frame-options"] == "DENY"
        assert hdrs["x-content-type-options"] == "nosniff"
        body = resp.read().decode("utf-8")
        assert f'content="{token}"' in body
        assert "/static/app.js" in body
        assert "/static/styles.css" in body

    # Static assets served cleanly
    for asset_path, needle in (("/static/styles.css", "--accent"), ("/static/app.js", "X-VulnBox-Token")):
        with urllib.request.urlopen(f"{base_url}{asset_path}", timeout=5) as resp:
            assert resp.status == 200
            assert needle in resp.read().decode("utf-8")

    # POST without CSRF token must be rejected with 403
    status, data = _post_json(
        f"{base_url}/api/profile",
        {"repo_path": str(FIXTURES / "py_sample_app")},
        token=None,
    )
    assert status == 403
    assert "CSRF" in data["error"]


def test_ui_handles_concurrent_scans_safely(ui_server):
    base_url, token = ui_server
    py_repo = str(FIXTURES / "py_sample_app")

    def _run_scan(_idx: int) -> tuple[int, str]:
        st, data = _post_json(
            f"{base_url}/api/scan",
            {"repo_path": py_repo, "backend": "local"},
            token=token,
        )
        return st, data["run_id"]

    with ThreadPoolExecutor(max_workers=4) as pool:
        results = list(pool.map(_run_scan, range(4)))

    assert all(st == 200 for st, _ in results)
    assert len({rid for _, rid in results}) == 4


def test_ui_doctor_profile_scan_probe_remediate_and_verify_patch(ui_server):
    base_url, token = ui_server
    py_repo = str(FIXTURES / "py_sample_app")

    # 1. Doctor
    with urllib.request.urlopen(f"{base_url}/api/doctor", timeout=5) as resp:
        assert resp.status == 200
        doc = json.loads(resp.read().decode("utf-8"))
        assert doc["local_ready"] is True
        assert any(s["name"] == "py_sample_app" for s in doc["samples"])

    # 2. Profile
    st, prof_data = _post_json(f"{base_url}/api/profile", {"repo_path": py_repo}, token=token)
    assert st == 200
    assert prof_data["profile"]["ecosystem"] == "python"

    # 3. Scan
    st, scan_data = _post_json(
        f"{base_url}/api/scan",
        {"repo_path": py_repo, "backend": "local"},
        token=token,
    )
    assert st == 200
    assert len(scan_data["report"]["findings"]) >= 6
    validate_sarif(scan_data["sarif"])

    # 4. Active Probe
    probe_spec = {
        "probe_id": "ui-yaml-probe",
        "rule_id": "PY-YAML-001",
        "description": "YAML SafeLoader check",
        "method": "POST",
        "path": "/parse",
        "headers": {"Content-Type": "text/plain"},
        "body": "!!python/tuple [1, 2]",
        "vulnerable_expectation": {"status_codes": [200]},
        "fixed_expectation": {"status_codes": [400]},
    }
    st, probe_data = _post_json(
        f"{base_url}/api/probe",
        {"repo_path": py_repo, "backend": "local", "probe_json": probe_spec},
        token=token,
    )
    assert st == 200
    assert probe_data["results"][0]["matched_vulnerable"] is True

    # 5. End-to-end Remediate + downloadable artifacts
    st, rem_data = _post_json(
        f"{base_url}/api/remediate",
        {"repo_path": py_repo, "backend": "local"},
        token=token,
    )
    assert st == 200
    run_id = rem_data["run_id"]
    verifications = rem_data["report"]["verifications"]
    assert sum(1 for v in verifications if v["verified"]) >= 6
    assert sum(1 for v in verifications if v["dynamic_confirmed_and_fixed"] is True) >= 2

    with urllib.request.urlopen(f"{base_url}/api/artifact/{run_id}/report.md", timeout=5) as resp:
        assert resp.status == 200
        assert "CONFIRMED -> FIXED" in resp.read().decode("utf-8")

    # 6. Verify custom patch via UI API
    yaml_patch = next(p for p in rem_data["report"]["patches"] if p["rule_id"] == "PY-YAML-001")
    st, ver_data = _post_json(
        f"{base_url}/api/verify-patch",
        {
            "repo_path": py_repo,
            "backend": "local",
            "finding_id": yaml_patch["finding_id"],
            "rule_id": "PY-YAML-001",
            "unified_diff": yaml_patch["unified_diff"],
            "probe_json": probe_spec,
        },
        token=token,
    )
    assert st == 200
    assert ver_data["verification"]["verified"] is True
    assert ver_data["verification"]["dynamic_confirmed_and_fixed"] is True

    # 7. Missing repo returns clean 400 JSON error
    st, err_data = _post_json(
        f"{base_url}/api/profile",
        {"repo_path": "/nonexistent/path/for/vulnbox"},
        token=token,
    )
    assert st == 400
    assert "does not exist" in err_data["error"]
