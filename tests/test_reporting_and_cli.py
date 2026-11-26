"""Tests for SARIF 2.1.0 validation, Markdown reporting, and CLI commands."""

import json
from pathlib import Path

from typer.testing import CliRunner

from vulnbox.cli import app
from vulnbox.reporting.sarif import validate_sarif

FIXTURES = Path(__file__).parent / "fixtures"
runner = CliRunner()


def test_cli_doctor_and_profile():
    res_doc = runner.invoke(app, ["doctor"])
    assert res_doc.exit_code == 0
    assert "Local Isolated Sandbox" in res_doc.stdout

    res_prof = runner.invoke(app, ["profile", str(FIXTURES / "py_sample_app"), "--json"])
    assert res_prof.exit_code == 0
    data = json.loads(res_prof.stdout)
    assert data["ecosystem"] == "python"


def test_cli_remediate_produces_valid_sarif_markdown_and_patches(tmp_path: Path):
    out_dir = tmp_path / "py-out"
    res = runner.invoke(
        app,
        [
            "remediate",
            str(FIXTURES / "py_sample_app"),
            "--backend",
            "local",
            "--out",
            str(out_dir),
        ],
    )
    assert res.exit_code == 0, res.stdout

    repo_out = out_dir / "py_sample_app"
    sarif_path = repo_out / "findings.sarif.json"
    md_path = repo_out / "report.md"
    manifest_path = repo_out / "manifest.json"
    assert sarif_path.is_file()
    assert md_path.is_file()
    assert manifest_path.is_file()

    sarif_doc = json.loads(sarif_path.read_text(encoding="utf-8"))
    validate_sarif(sarif_doc)
    assert sarif_doc["version"] == "2.1.0"
    assert len(sarif_doc["runs"][0]["results"]) >= 6

    md_text = md_path.read_text(encoding="utf-8")
    assert "CONFIRMED -> FIXED" in md_text
    assert "curl -sS -i" in md_text
    assert "Mandatory Human-in-the-Loop (HITL) Review Gate" in md_text

    patches = list((repo_out / "patches").glob("*.patch"))
    assert len(patches) >= 4


def test_cli_verify_patch_command(tmp_path: Path):
    out_dir = tmp_path / "py-remediate"
    res = runner.invoke(
        app,
        [
            "remediate",
            str(FIXTURES / "py_sample_app"),
            "--backend",
            "local",
            "--out",
            str(out_dir),
        ],
    )
    assert res.exit_code == 0

    yaml_patch = next((out_dir / "py_sample_app" / "patches").glob("PY-YAML-001-*.patch"))
    finding_id = yaml_patch.stem
    probe_json = tmp_path / "probe.json"
    probe_json.write_text(
        json.dumps(
            {
                "probe_id": "cli-yaml-probe",
                "finding_id": finding_id,
                "rule_id": "PY-YAML-001",
                "description": "Verify YAML SafeLoader",
                "method": "POST",
                "path": "/parse",
                "headers": {"Content-Type": "text/plain"},
                "body": "!!python/tuple [1, 2]",
                "vulnerable_expectation": {"status_codes": [200]},
                "fixed_expectation": {"status_codes": [400]},
            }
        ),
        encoding="utf-8",
    )

    ver_res = runner.invoke(
        app,
        [
            "verify-patch",
            str(FIXTURES / "py_sample_app"),
            "--patch",
            str(yaml_patch),
            "--finding-id",
            finding_id,
            "--rule-id",
            "PY-YAML-001",
            "--probe",
            str(probe_json),
            "--backend",
            "local",
            "--json",
        ],
    )
    assert ver_res.exit_code == 0, ver_res.stdout
    ver_data = json.loads(ver_res.stdout)
    assert ver_data["verified"] is True
    assert ver_data["dynamic_confirmed_and_fixed"] is True
