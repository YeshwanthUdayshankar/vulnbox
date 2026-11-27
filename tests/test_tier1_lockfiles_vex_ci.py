"""Tests for Tier 1: lockfile-accurate parsing, PEP 440/SemVer pre-releases, offline OSV/KEV/EPSS cache,
OpenVEX v0.2.0 & CycloneDX 1.5 VEX output, CI gating, baselines, inline suppressions, and SARIF fingerprints."""

from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from vulnbox.analyzers import run_all_analyzers
from vulnbox.analyzers.advisory_feed import normalize_osv_record
from vulnbox.analyzers.dependency_reachability import DependencyReachabilityAnalyzer
from vulnbox.analyzers.lockfiles import (
    is_version_below,
    parse_node_dependencies,
    parse_python_dependencies,
)
from vulnbox.cli import app
from vulnbox.engine import VulnBoxEngine
from vulnbox.reporting.sarif import build_sarif, validate_sarif
from vulnbox.reporting.vex import build_cyclonedx_vex, build_openvex
from vulnbox.suppressions import (
    compute_finding_fingerprint,
    filter_by_baseline,
    load_baseline,
    should_fail_ci,
    write_baseline,
)


def test_semver_and_pep440_prerelease_version_comparison():
    # Pre-releases must sort strictly below the final release
    assert is_version_below("1.0rc1", "1.0", ecosystem="python") is True
    assert is_version_below("1.0.0a1", "1.0.0", ecosystem="python") is True
    assert is_version_below("5.4", "5.4", ecosystem="python") is False
    assert is_version_below("4.17.21-rc.1", "4.17.21", ecosystem="node") is True
    assert is_version_below("4.17.21", "4.17.21", ecosystem="node") is False
    assert is_version_below("1.0.0-alpha.1", "1.0.0-beta.1", ecosystem="node") is True


def test_lockfiles_override_loose_manifest_ranges(tmp_path: Path):
    # package.json has loose range ^4.17.0, but package-lock.json pins patched 4.17.21 -> NOT vulnerable!
    node_v3 = tmp_path / "node_v3"
    node_v3.mkdir()
    (node_v3 / "package.json").write_text(
        json.dumps({"dependencies": {"lodash": "^4.17.0"}}),
        encoding="utf-8",
    )
    (node_v3 / "package-lock.json").write_text(
        json.dumps(
            {
                "lockfileVersion": 3,
                "packages": {
                    "": {"name": "demo"},
                    "node_modules/lodash": {"version": "4.17.21"},
                },
            }
        ),
        encoding="utf-8",
    )
    deps = parse_node_dependencies(node_v3)
    assert len(deps) == 1
    assert deps[0].name == "lodash" and deps[0].version == "4.17.21" and deps[0].is_lockfile is True
    assert DependencyReachabilityAnalyzer().analyze(node_v3) == []

    # yarn.lock & pnpm-lock.yaml & poetry.lock exact extraction
    yarn_dir = tmp_path / "yarn_app"
    yarn_dir.mkdir()
    (yarn_dir / "yarn.lock").write_text(
        '"minimist@^1.2.0":\n  version "1.2.5"\n',
        encoding="utf-8",
    )
    y_deps = parse_node_dependencies(yarn_dir)
    assert any(d.name == "minimist" and d.version == "1.2.5" and d.is_lockfile for d in y_deps)

    pnpm_dir = tmp_path / "pnpm_app"
    pnpm_dir.mkdir()
    (pnpm_dir / "pnpm-lock.yaml").write_text(
        "lockfileVersion: '9.0'\npackages:\n  lodash@4.17.20:\n    resolution: {}\n",
        encoding="utf-8",
    )
    p_deps = parse_node_dependencies(pnpm_dir)
    assert any(d.name == "lodash" and d.version == "4.17.20" and d.is_lockfile for d in p_deps)

    poetry_dir = tmp_path / "poetry_app"
    poetry_dir.mkdir()
    (poetry_dir / "poetry.lock").write_text(
        '[[package]]\nname = "PyYAML"\nversion = "5.3.1"\n',
        encoding="utf-8",
    )
    py_deps = parse_python_dependencies(poetry_dir)
    assert any(d.name == "pyyaml" and d.version == "5.3.1" and d.is_lockfile for d in py_deps)


def test_offline_osv_cache_kev_epss_and_vex_generation(tmp_path: Path):
    cache_dir = tmp_path / "adv_cache"
    cache_dir.mkdir()

    norm = normalize_osv_record(
        {
            "id": "GHSA-demo-1234",
            "aliases": ["CVE-2024-99999"],
            "summary": "Demo vuln in demo-pkg",
            "database_specific": {"severity": "HIGH", "cwe_ids": ["CWE-94"]},
            "affected": [
                {
                    "package": {"ecosystem": "PyPI", "name": "demo-pkg"},
                    "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "2.0.0"}]}],
                    "ecosystem_specific": {"imports": [{"symbols": ["danger_fn"]}]},
                }
            ],
        },
        ecosystem="python",
        package_name="demo-pkg",
    )
    assert norm is not None and norm["advisory_id"] == "CVE-2024-99999"

    (cache_dir / "osv_cache.json").write_text(
        json.dumps({"updated_at": "2026-11-27T00:00:00Z", "advisories": [norm]}),
        encoding="utf-8",
    )
    (cache_dir / "kev_cache.json").write_text(
        json.dumps({"updated_at": "2026-11-27T00:00:00Z", "cves": ["CVE-2024-99999"]}),
        encoding="utf-8",
    )
    (cache_dir / "epss_cache.json").write_text(
        json.dumps(
            {
                "updated_at": "2026-11-27T00:00:00Z",
                "scores": {"CVE-2024-99999": {"epss": 0.875, "percentile": 0.99}},
            }
        ),
        encoding="utf-8",
    )

    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "requirements.txt").write_text("demo-pkg==1.5.0\npyyaml==5.3.1\n", encoding="utf-8")
    # app.py imports yaml.load (reachable), but never imports demo_pkg (not_reachable!)
    (repo / "app.py").write_text("import yaml\n\ndef load(s):\n    return yaml.load(s)\n", encoding="utf-8")

    out_dir = tmp_path / "out"
    engine = VulnBoxEngine(backend="local")
    report, written = engine.scan(repo, out_dir=out_dir, advisory_cache_dir=cache_dir)

    assert "openvex" in written and written["openvex"].is_file()
    assert "cyclonedx_vex" in written and written["cyclonedx_vex"].is_file()

    dep_by_cve = {
        f.metadata["advisory_id"]: f for f in report.findings if f.category == "dependency"
    }
    assert dep_by_cve["CVE-2024-99999"].reachability == "not_reachable"
    assert dep_by_cve["CVE-2024-99999"].metadata["cisa_kev"] is True
    assert dep_by_cve["CVE-2024-99999"].metadata["epss_score"] == 0.875
    assert dep_by_cve["CVE-2020-14343"].reachability == "reachable"

    openvex = build_openvex(report)
    assert openvex["@context"] == "https://openvex.dev/ns/v0.2.0"
    stmts = {s["vulnerability"]["name"]: s for s in openvex["statements"]}
    assert stmts["CVE-2024-99999"]["status"] == "not_affected"
    assert stmts["CVE-2024-99999"]["justification"] == "vulnerable_code_not_in_execute_path"
    assert stmts["CVE-2020-14343"]["status"] == "affected"

    cdx = build_cyclonedx_vex(report)
    assert cdx["bomFormat"] == "CycloneDX" and cdx["specVersion"] == "1.5"
    cdx_by_id = {v["id"]: v for v in cdx["vulnerabilities"]}
    assert cdx_by_id["CVE-2024-99999"]["analysis"]["state"] == "not_affected"
    assert cdx_by_id["CVE-2024-99999"]["analysis"]["justification"] == "code_not_reachable"
    assert cdx_by_id["CVE-2020-14343"]["analysis"]["state"] == "exploitable"

    sarif = build_sarif(report)
    validate_sarif(sarif)
    for res in sarif["runs"][0]["results"]:
        assert "primaryLocationLineHash" in res["partialFingerprints"]
        assert "security-severity" in res["properties"]


def test_inline_suppressions_baseline_and_cli_fail_on_gate(tmp_path: Path):
    repo = tmp_path / "ci_repo"
    repo.mkdir()
    (repo / "app.py").write_text(
        "import yaml\n"
        "def a(s):\n"
        "    return yaml.load(s)  # vulnbox: ignore[PY-YAML-001]\n"
        "def b(s):\n"
        "    return yaml.load(s)\n",
        encoding="utf-8",
    )
    findings = run_all_analyzers(repo)
    yaml_findings = [f for f in findings if f.rule_id == "PY-YAML-001"]
    assert len(yaml_findings) == 1
    assert yaml_findings[0].start_line == 5

    # Write baseline, then shift line numbers by inserting comments above -> baseline STILL matches!
    baseline_file = tmp_path / "baseline.json"
    write_baseline(yaml_findings, baseline_file)
    fp_before = compute_finding_fingerprint(yaml_findings[0])

    (repo / "app.py").write_text(
        "# header 1\n# header 2\nimport yaml\n"
        "def a(s):\n"
        "    return yaml.load(s)  # vulnbox: ignore[PY-YAML-001]\n"
        "def b(s):\n"
        "    return yaml.load(s)\n",
        encoding="utf-8",
    )
    shifted_findings = [f for f in run_all_analyzers(repo) if f.rule_id == "PY-YAML-001"]
    assert shifted_findings[0].start_line == 7
    assert compute_finding_fingerprint(shifted_findings[0]) == fp_before

    kept, baselined_n = filter_by_baseline(shifted_findings, load_baseline(baseline_file))
    assert kept == [] and baselined_n == 1
    assert should_fail_ci(shifted_findings, "high") is True
    assert should_fail_ci(shifted_findings, "critical") is False

    # CLI `--fail-on high` exits 1 without baseline and 0 with baseline!
    runner = CliRunner()
    res_fail = runner.invoke(
        app,
        ["scan", str(repo), "--backend", "local", "--fail-on", "high", "--out", str(tmp_path / "o1")],
    )
    assert res_fail.exit_code == 1

    res_pass = runner.invoke(
        app,
        [
            "scan",
            str(repo),
            "--backend",
            "local",
            "--baseline",
            str(baseline_file),
            "--fail-on",
            "high",
            "--out",
            str(tmp_path / "o2"),
        ],
    )
    assert res_pass.exit_code == 0
