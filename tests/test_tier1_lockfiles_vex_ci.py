"""Tests for Tier 1: lockfile-accurate parsing, PEP 440/SemVer pre-releases, multi-branch OSV ranges,
CVSS v3 scoring, PyPI import aliases, sound OpenVEX/CycloneDX VEX output, CI gating, baselines,
and inline suppression visibility in Markdown & SARIF."""

from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from vulnbox.analyzers import run_all_analyzers
from vulnbox.analyzers.advisory_feed import (
    compute_cvss_v3_base_score,
    normalize_osv_record,
)
from vulnbox.analyzers.dependency_reachability import DependencyReachabilityAnalyzer
from vulnbox.analyzers.lockfiles import (
    is_version_below,
    is_version_in_ranges,
    parse_node_dependencies,
    parse_python_dependencies,
)
from vulnbox.cli import app
from vulnbox.engine import VulnBoxEngine
from vulnbox.models import VerificationResult
from vulnbox.reporting.markdown import render_markdown_report
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
    assert is_version_below("1.0rc1", "1.0", ecosystem="python") is True
    assert is_version_below("1.0.0a1", "1.0.0", ecosystem="python") is True
    assert is_version_below("5.4", "5.4", ecosystem="python") is False
    assert is_version_below("4.17.21-rc.1", "4.17.21", ecosystem="node") is True
    assert is_version_below("4.17.21", "4.17.21", ecosystem="node") is False
    assert is_version_below("1.0.0-alpha.1", "1.0.0-beta.1", ecosystem="node") is True


def test_osv_multibranch_ranges_cvss3_vector_scoring_and_pypi_aliases():
    # Exact CVSS v3.1 Base Score calculation from vector strings
    assert compute_cvss_v3_base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H") == 9.8
    assert compute_cvss_v3_base_score("CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:U/C:L/I:N/A:N") == 2.6
    assert compute_cvss_v3_base_score("CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N") == 5.4

    # Multi-branch OSV advisory (e.g. Django 3.2.20 fixed on 3.2.x AND 4.2.3 fixed on 4.2.x)
    norm_django = normalize_osv_record(
        {
            "id": "PYSEC-2023-DEMO",
            "aliases": ["CVE-2023-36053"],
            "summary": "Django multi-branch advisory",
            "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:U/C:L/I:N/A:N"}],
            "affected": [
                {
                    "package": {"ecosystem": "PyPI", "name": "Django"},
                    "ranges": [
                        {
                            "type": "ECOSYSTEM",
                            "events": [
                                {"introduced": "3.2"},
                                {"fixed": "3.2.20"},
                                {"introduced": "4.2"},
                                {"fixed": "4.2.3"},
                            ],
                        }
                    ],
                }
            ],
        },
        ecosystem="python",
        package_name="django",
    )
    assert norm_django is not None
    assert norm_django["severity"] == "low"  # CVSS 2.6, NOT fallback "high"!
    ranges = norm_django["affected_ranges"]
    assert len(ranges) == 2
    # Django 3.2.20 is ALREADY patched on 3.2.x -> MUST NOT be flagged against 4.2.3!
    assert is_version_in_ranges("3.2.20", ranges, ecosystem="python") == (False, None)
    # Django 3.2.19 IS affected and recommends upgrading to 3.2.20 (its own branch fix)
    assert is_version_in_ranges("3.2.19", ranges, ecosystem="python") == (True, "3.2.20")
    assert is_version_in_ranges("4.2.2", ranges, ecosystem="python") == (True, "4.2.3")
    assert is_version_in_ranges("4.2.3", ranges, ecosystem="python") == (False, None)

    # PyPI distribution -> import module alias mapping
    for pkg, expected_imp in [("pillow", "PIL"), ("beautifulsoup4", "bs4"), ("pyyaml", "yaml")]:
        rec = normalize_osv_record(
            {
                "id": f"GHSA-{pkg}-1",
                "affected": [
                    {
                        "package": {"ecosystem": "PyPI", "name": pkg},
                        "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "9.9.9"}]}],
                    }
                ],
            },
            ecosystem="python",
            package_name=pkg,
        )
        assert rec is not None and expected_imp in rec["imports"]

    # Unfixed OSV vulnerability (`introduced: "0"` with NO fix yet) MUST NOT be dropped!
    unfixed = normalize_osv_record(
        {
            "id": "GHSA-unfixed-0day",
            "aliases": ["CVE-2026-00001"],
            "summary": "Unpatched zero-day",
            "affected": [
                {
                    "package": {"ecosystem": "PyPI", "name": "zero-pkg"},
                    "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}]}],
                }
            ],
        },
        ecosystem="python",
        package_name="zero-pkg",
    )
    assert unfixed is not None
    assert unfixed["affected_ranges"] == [{"introduced": "0"}]
    assert unfixed["fixed_version"] == ""
    assert is_version_in_ranges("9.9.9", unfixed["affected_ranges"], ecosystem="python") == (True, None)

    # GIT commit-SHA ranges MUST be ignored (only ECOSYSTEM / SEMVER ranges evaluated!)
    with_git = normalize_osv_record(
        {
            "id": "PYSEC-2024-GIT",
            "affected": [
                {
                    "package": {"ecosystem": "PyPI", "name": "git-pkg"},
                    "ranges": [
                        {
                            "type": "GIT",
                            "events": [
                                {"introduced": "0"},
                                {"fixed": "9999abcdef1234567890abcdef1234567890abcd"},
                            ],
                        },
                        {
                            "type": "ECOSYSTEM",
                            "events": [{"introduced": "0"}, {"fixed": "1.2.0"}],
                        },
                    ],
                }
            ],
        },
        ecosystem="python",
        package_name="git-pkg",
    )
    assert with_git is not None
    assert with_git["affected_ranges"] == [{"introduced": "0", "fixed": "1.2.0"}]
    assert is_version_in_ranges("1.2.0", with_git["affected_ranges"], ecosystem="python") == (False, None)
    # GIT-only range with no ECOSYSTEM/SEMVER returns None instead of SHA-digit comparison
    git_only = normalize_osv_record(
        {
            "id": "PYSEC-2024-GITONLY",
            "affected": [
                {
                    "package": {"ecosystem": "PyPI", "name": "git-only"},
                    "ranges": [
                        {
                            "type": "GIT",
                            "events": [{"introduced": "0"}, {"fixed": "abcdef123456"}],
                        }
                    ],
                }
            ],
        },
        ecosystem="python",
        package_name="git-only",
    )
    assert git_only is None


def test_lockfiles_override_loose_manifest_ranges(tmp_path: Path):
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

    yarn_dir = tmp_path / "yarn_app"
    yarn_dir.mkdir()
    (yarn_dir / "yarn.lock").write_text(
        '"myapp@workspace:.":\n  version: 0.0.0-use.local\n  dependencies:\n    lodash: ^4.17.20\n\n'
        '"express@^4.18.0":\n  version "4.18.2"\n  dependencies:\n    minimist "^1.2.0"\n\n'
        '"minimist@^1.2.0":\n  version "1.2.5"\n',
        encoding="utf-8",
    )
    y_deps = parse_node_dependencies(yarn_dir)
    assert any(d.name == "minimist" and d.version == "1.2.5" and d.is_lockfile for d in y_deps)
    from vulnbox.analyzers.lockfiles import compute_reverse_dependents

    yarn_rev = compute_reverse_dependents(yarn_dir, "node")
    assert "express" in yarn_rev[Path(".")]["minimist"]
    # First-party Yarn Berry `@workspace:.` entry MUST NOT count as a third-party dependent!
    assert "lodash" not in yarn_rev[Path(".")]

    # First-party npm workspace packages/* and link:true entries MUST NOT count as third-party dependents!
    npm_ws = tmp_path / "npm_ws"
    npm_ws.mkdir()
    (npm_ws / "package-lock.json").write_text(
        json.dumps(
            {
                "lockfileVersion": 3,
                "packages": {
                    "": {"dependencies": {"lodash": "^4.17.20"}},
                    "packages/web": {"name": "web", "dependencies": {"lodash": "^4.17.20"}},
                    "node_modules/web": {"resolved": "packages/web", "link": True, "dependencies": {"lodash": "^4.17.20"}},
                    "node_modules/lodash": {"version": "4.17.20"},
                },
            }
        ),
        encoding="utf-8",
    )
    npm_ws_rev = compute_reverse_dependents(npm_ws, "node")
    assert "lodash" not in npm_ws_rev[Path(".")]

    # Monorepo per-folder reverse-dependency graph isolation:
    # svc_a has a uv.lock, while svc_b only has flat requirements.txt -> svc_b MUST NOT inherit svc_a's graph_known!
    mono = tmp_path / "mono"
    (mono / "svc_a").mkdir(parents=True)
    (mono / "svc_b").mkdir(parents=True)
    (mono / "svc_a" / "uv.lock").write_text('[[package]]\nname = "click"\nversion = "8.1.7"\n', encoding="utf-8")
    (mono / "svc_b" / "requirements.txt").write_text("urllib3==2.0.5\nrequests==2.31.0\n", encoding="utf-8")
    (mono / "svc_b" / "app.py").write_text("import urllib3\nurllib3.disable_warnings()\n", encoding="utf-8")
    mono_deps = DependencyReachabilityAnalyzer().analyze(mono)
    u3 = next(f for f in mono_deps if f.metadata["package"] == "urllib3")
    assert u3.reachability == "under_investigation"
    assert u3.metadata["reachability_basis"] == "imported_safe_symbols_but_has_dependents"

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


def test_offline_osv_cache_kev_epss_and_sound_vex_generation(tmp_path: Path):
    cache_dir = tmp_path / "adv_cache"
    cache_dir.mkdir()

    norm_direct_safe = normalize_osv_record(
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
    norm_unimported = normalize_osv_record(
        {
            "id": "GHSA-trans-5678",
            "aliases": ["CVE-2024-88888"],
            "summary": "Transitive vuln in transitive-pkg",
            "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
            "affected": [
                {
                    "package": {"ecosystem": "PyPI", "name": "transitive-pkg"},
                    "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "3.0.0"}]}],
                }
            ],
        },
        ecosystem="python",
        package_name="transitive-pkg",
    )
    assert norm_direct_safe is not None and norm_unimported is not None
    assert norm_unimported["severity"] == "critical"

    (cache_dir / "osv_cache.json").write_text(
        json.dumps({"updated_at": "2026-11-27T00:00:00Z", "advisories": [norm_direct_safe, norm_unimported]}),
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
    # Use uv.lock so the full dependency graph is known:
    # - demo-pkg has ZERO reverse dependents (safe symbols only -> provably not_affected!)
    # - urllib3 is depended on by requests (even though app.py only calls urllib3.disable_warnings -> MUST stay under_investigation!)
    # - transitive-pkg is unimported -> MUST stay under_investigation!
    # - pyyaml is directly imported calling yaml.load -> affected!
    (repo / "uv.lock").write_text(
        '[[package]]\nname = "demo-pkg"\nversion = "1.5.0"\n\n'
        '[[package]]\nname = "transitive-pkg"\nversion = "1.0.0"\n\n'
        '[[package]]\nname = "pyyaml"\nversion = "5.3.1"\n\n'
        '[[package]]\nname = "urllib3"\nversion = "2.0.5"\n\n'
        '[[package]]\nname = "requests"\nversion = "2.31.0"\n'
        'dependencies = [\n  { name = "urllib3" },\n]\n',
        encoding="utf-8",
    )
    (repo / "app.py").write_text(
        "import yaml\nimport demo_pkg\nimport urllib3\n\n"
        "def load(s):\n    demo_pkg.safe_fn()\n    urllib3.disable_warnings()\n    return yaml.load(s)\n",
        encoding="utf-8",
    )

    out_dir = tmp_path / "out"
    engine = VulnBoxEngine(backend="local")
    report, written = engine.scan(repo, out_dir=out_dir, advisory_cache_dir=cache_dir)

    assert "openvex" in written and written["openvex"].is_file()
    assert "cyclonedx_vex" in written and written["cyclonedx_vex"].is_file()

    dep_by_cve = {
        f.metadata["advisory_id"]: f for f in report.findings if f.category == "dependency"
    }
    assert dep_by_cve["CVE-2024-99999"].reachability == "not_reachable"
    assert dep_by_cve["CVE-2024-99999"].metadata["reachability_basis"] == "imported_safe_symbols_no_dependents"
    assert dep_by_cve["CVE-2024-99999"].metadata["cisa_kev"] is True
    assert dep_by_cve["CVE-2024-99999"].metadata["epss_score"] == 0.875
    # urllib3 has reverse dependent `requests` in uv.lock -> MUST NOT claim not_affected!
    assert dep_by_cve["CVE-2023-45803"].reachability == "under_investigation"
    assert dep_by_cve["CVE-2023-45803"].metadata["reachability_basis"] == "imported_safe_symbols_but_has_dependents"
    assert "requests" in dep_by_cve["CVE-2023-45803"].metadata["reverse_dependents"]
    assert dep_by_cve["CVE-2024-88888"].reachability == "under_investigation"
    assert dep_by_cve["CVE-2024-88888"].metadata["reachability_basis"] == "not_directly_imported"
    assert dep_by_cve["CVE-2020-14343"].reachability == "reachable"

    openvex = build_openvex(report)
    assert openvex["@context"] == "https://openvex.dev/ns/v0.2.0"
    stmts = {s["vulnerability"]["name"]: s for s in openvex["statements"]}
    assert stmts["CVE-2024-99999"]["status"] == "not_affected"
    assert stmts["CVE-2024-99999"]["justification"] == "vulnerable_code_not_in_execute_path"
    assert stmts["CVE-2023-45803"]["status"] == "under_investigation"
    assert stmts["CVE-2024-88888"]["status"] == "under_investigation"
    assert stmts["CVE-2020-14343"]["status"] == "affected"

    cdx = build_cyclonedx_vex(report)
    assert cdx["bomFormat"] == "CycloneDX" and cdx["specVersion"] == "1.5"
    # Every affects[].ref MUST exist in top-level CycloneDX `components`
    comp_refs = {c["bom-ref"] for c in cdx["components"]}
    for vuln in cdx["vulnerabilities"]:
        for aff in vuln["affects"]:
            assert aff["ref"] in comp_refs
    cdx_by_id = {v["id"]: v for v in cdx["vulnerabilities"]}
    assert cdx_by_id["CVE-2024-99999"]["analysis"]["state"] == "not_affected"
    assert cdx_by_id["CVE-2024-88888"]["analysis"]["state"] == "in_triage"
    assert cdx_by_id["CVE-2020-14343"]["analysis"]["state"] == "exploitable"

    # Verified fixed VEX statement MUST attach to the PATCHED version's PURL (6.0.2), NOT old 5.3.1!
    yaml_finding = dep_by_cve["CVE-2020-14343"]
    fixed_report = report.model_copy(
        update={
            "verifications": [
                VerificationResult(
                    patch_id="p-yaml",
                    finding_id=yaml_finding.finding_id,
                    sandbox_backend="local",
                    baseline_tests_passed=True,
                    patch_applied=True,
                    finding_resolved=True,
                    no_new_findings=True,
                    existing_tests_passed_after=True,
                    verified=True,
                    summary="upgraded",
                )
            ]
        }
    )
    fixed_ov = {s["vulnerability"]["name"]: s for s in build_openvex(fixed_report)["statements"]}
    assert fixed_ov["CVE-2020-14343"]["status"] == "fixed"
    assert fixed_ov["CVE-2020-14343"]["products"][0]["@id"] == "pkg:pypi/pyyaml@6.0.2"
    fixed_cdx = build_cyclonedx_vex(fixed_report)
    fixed_cdx_yaml = {v["id"]: v for v in fixed_cdx["vulnerabilities"]}["CVE-2020-14343"]
    assert fixed_cdx_yaml["affects"][0]["ref"] == "pkg:pypi/pyyaml@6.0.2"
    assert "pkg:pypi/pyyaml@6.0.2" in {c["bom-ref"] for c in fixed_cdx["components"]}

    # VEX uncertainty gate: loose manifest_range or go_directive_lower_bound MUST emit under_investigation / in_triage
    # (NEVER firm affected / not_affected / fixed) even when symbols are called!
    uncertain_yaml = yaml_finding.model_copy(
        update={
            "metadata": {
                **yaml_finding.metadata,
                "version_source": "manifest_range",
            }
        }
    )
    uncertain_go = yaml_finding.model_copy(
        update={
            "finding_id": "F-GO-LOW",
            "rule_id": "DEP-GO-2023-2102",
            "metadata": {
                "ecosystem": "go",
                "package": "stdlib",
                "installed_version": "1.21.1",
                "fixed_version": "1.21.3",
                "advisory_id": "GO-2023-2102",
                "version_source": "go_directive_lower_bound",
                "confidence": "low",
            },
        }
    )
    uncertain_report = report.model_copy(update={"findings": [uncertain_yaml, uncertain_go], "verifications": []})
    unc_ov = {s["vulnerability"]["name"]: s for s in build_openvex(uncertain_report)["statements"]}
    assert unc_ov["CVE-2020-14343"]["status"] == "under_investigation"
    assert "unknown" in unc_ov["CVE-2020-14343"]["status_notes"].lower()
    assert unc_ov["GO-2023-2102"]["status"] == "under_investigation"
    unc_cdx = {v["id"]: v for v in build_cyclonedx_vex(uncertain_report)["vulnerabilities"]}
    assert unc_cdx["CVE-2020-14343"]["analysis"]["state"] == "in_triage"
    assert unc_cdx["GO-2023-2102"]["analysis"]["state"] == "in_triage"

    sarif = build_sarif(report)
    validate_sarif(sarif)
    for res in sarif["runs"][0]["results"]:
        assert "primaryLocationLineHash" in res["partialFingerprints"]
        assert "security-severity" in res["properties"]


def test_inline_suppressions_visibility_baseline_stability_and_cli_fail_on_gate(tmp_path: Path):
    repo = tmp_path / "ci_repo"
    repo.mkdir()
    (repo / "app.py").write_text(
        "import yaml\n"
        "def a(s):\n"
        "    return yaml.load(s)  # vulnbox: ignore[PY-YAML-001]\n"
        "def b(s):\n"
        "    x = 1\n"
        "    return yaml.load(s)\n"
        "    y = 2\n",
        encoding="utf-8",
    )
    findings = run_all_analyzers(repo)
    yaml_findings = [f for f in findings if f.rule_id == "PY-YAML-001"]
    assert len(yaml_findings) == 1
    assert yaml_findings[0].start_line == 6

    # Inline suppressions MUST be surfaced in AuditReport, Markdown, and SARIF 2.1.0 `suppressions`
    report, _ = VulnBoxEngine(backend="local").scan(repo)
    assert len(report.suppressed_findings) == 1
    assert report.suppressed_findings[0].rule_id == "PY-YAML-001"
    md = render_markdown_report(report)
    assert "Suppressed Findings (Inline)" in md
    sarif = build_sarif(report)
    validate_sarif(sarif)
    suppressed_sarif = [r for r in sarif["runs"][0]["results"] if r.get("suppressions")]
    assert len(suppressed_sarif) == 1
    assert suppressed_sarif[0]["suppressions"][0]["kind"] == "inSource"

    # Write baseline, then BOTH shift lines AND edit neighboring lines above/below -> baseline STILL matches!
    baseline_file = tmp_path / "baseline.json"
    write_baseline(yaml_findings, baseline_file)
    fp_before = compute_finding_fingerprint(yaml_findings[0])

    (repo / "app.py").write_text(
        "# header 1\n# header 2\nimport yaml\n"
        "def a(s):\n"
        "    return yaml.load(s)  # vulnbox: ignore[PY-YAML-001]\n"
        "def b(s):\n"
        "    x = 999  # edited neighboring line above\n"
        "    return yaml.load(s)\n"
        "    y = 888  # edited neighboring line below\n",
        encoding="utf-8",
    )
    shifted_findings = [f for f in run_all_analyzers(repo) if f.rule_id == "PY-YAML-001"]
    assert shifted_findings[0].start_line == 8
    assert compute_finding_fingerprint(shifted_findings[0]) == fp_before

    kept, baselined_n = filter_by_baseline(shifted_findings, load_baseline(baseline_file))
    assert kept == [] and baselined_n == 1
    assert should_fail_ci(shifted_findings, "high") is True
    assert should_fail_ci(shifted_findings, "critical") is False

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
