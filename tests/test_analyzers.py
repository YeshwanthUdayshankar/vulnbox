"""Tests for Python SAST, Node SAST, Config Hygiene, and Dependency Reachability."""

from pathlib import Path

from vulnbox.analyzers import run_all_analyzers
from vulnbox.scrubber import cleanup_workspace, create_scrubbed_workspace

FIXTURES = Path(__file__).parent / "fixtures"


def test_python_fixture_analyzers():
    scrub = create_scrubbed_workspace(FIXTURES / "py_sample_app")
    ws = Path(scrub.sandbox_dir)
    try:
        findings = run_all_analyzers(ws, scrub_summary=scrub)
        rules = {f.rule_id for f in findings}
        assert "PY-YAML-001" in rules
        assert "PY-PATH-001" in rules
        assert "PY-TLS-001" in rules
        assert "CFG-DOCKER-001" in rules
        assert "CFG-DOCKER-002" in rules
        assert "CFG-SECRET-001" in rules
        assert "DEP-CVE-2020-14343" in rules
        assert "DEP-CVE-2023-45803" in rules

        by_rule = {f.rule_id: f for f in findings}
        # PyYAML yaml.load is imported & invoked -> reachable
        assert by_rule["DEP-CVE-2020-14343"].reachability == "reachable"
        # urllib3 is in requirements.txt but never imported -> not_reachable
        assert by_rule["DEP-CVE-2023-45803"].reachability == "not_reachable"
    finally:
        cleanup_workspace(ws)


def test_node_fixture_analyzers():
    scrub = create_scrubbed_workspace(FIXTURES / "node_sample_app")
    ws = Path(scrub.sandbox_dir)
    try:
        findings = run_all_analyzers(ws, scrub_summary=scrub)
        rules = {f.rule_id for f in findings}
        assert "JS-PATH-001" in rules
        assert "JS-CORS-001" in rules
        assert "JS-TLS-001" in rules
        assert "DEP-CVE-2021-44906" in rules
        assert "DEP-CVE-2021-23337" in rules
    finally:
        cleanup_workspace(ws)
