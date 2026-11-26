"""End-to-end tests for active before/after curl probing, patching, and dual verification."""

from pathlib import Path

from vulnbox.analyzers import run_all_analyzers
from vulnbox.profiler import profile_repo
from vulnbox.remediation import (
    generate_patch_for_finding,
    generate_regression_test,
    infer_probe_for_finding,
    verify_patch,
)
from vulnbox.sandbox import LocalSandboxBackend
from vulnbox.scrubber import cleanup_workspace, create_scrubbed_workspace

FIXTURES = Path(__file__).parent / "fixtures"


def test_python_end_to_end_active_curl_and_dual_verification():
    repo = FIXTURES / "py_sample_app"
    orig_app_src = (repo / "app.py").read_text(encoding="utf-8")
    prof = profile_repo(repo)
    backend = LocalSandboxBackend()

    scrub = create_scrubbed_workspace(repo)
    ws = Path(scrub.sandbox_dir)
    try:
        findings = run_all_analyzers(ws, scrub_summary=scrub)
        by_rule = {f.rule_id: f for f in findings}

        # Verify PY-YAML-001 and PY-PATH-001 with LIVE before/after curl probes!
        for rule in ("PY-YAML-001", "PY-PATH-001"):
            finding = by_rule[rule]
            patch = generate_patch_for_finding(finding, ws)
            assert patch is not None, f"Expected patch for {rule}"
            reg = generate_regression_test(finding)
            assert reg is not None
            patch.regression_test_path, patch.regression_test_code = reg
            probe = infer_probe_for_finding(finding, ws)
            assert probe is not None, f"Expected active curl probe for {rule}"

            result = verify_patch(
                repo_path=repo,
                profile=prof,
                patch=patch,
                backend=backend,
                finding=finding,
                probe_spec=probe,
            )
            assert result.verified is True, f"{rule} failed verification: {result.summary} | {result.logs}"
            assert result.finding_resolved is True
            assert result.existing_tests_passed_after is True
            assert result.regression_test_failed_before is True
            assert result.regression_test_passed_after is True
            assert result.dynamic_probe_before is not None
            assert result.dynamic_probe_before.matched_vulnerable is True
            assert result.dynamic_probe_after is not None
            assert result.dynamic_probe_after.matched_fixed is True
            assert result.dynamic_probe_after.matched_vulnerable is False
            assert result.dynamic_confirmed_and_fixed is True
    finally:
        cleanup_workspace(ws)

    # Confirm zero mutation of target repo
    assert (repo / "app.py").read_text(encoding="utf-8") == orig_app_src


def test_node_end_to_end_active_curl_and_dual_verification():
    repo = FIXTURES / "node_sample_app"
    orig_server_src = (repo / "server.mjs").read_text(encoding="utf-8")
    prof = profile_repo(repo)
    backend = LocalSandboxBackend()

    scrub = create_scrubbed_workspace(repo)
    ws = Path(scrub.sandbox_dir)
    try:
        findings = run_all_analyzers(ws, scrub_summary=scrub)
        by_rule = {f.rule_id: f for f in findings}

        # Verify JS-PATH-001 and JS-CORS-001 with LIVE before/after curl probes!
        for rule in ("JS-PATH-001", "JS-CORS-001"):
            finding = by_rule[rule]
            patch = generate_patch_for_finding(finding, ws)
            assert patch is not None, f"Expected patch for {rule}"
            reg = generate_regression_test(finding)
            assert reg is not None
            patch.regression_test_path, patch.regression_test_code = reg
            probe = infer_probe_for_finding(finding, ws)
            assert probe is not None, f"Expected active curl probe for {rule}"

            result = verify_patch(
                repo_path=repo,
                profile=prof,
                patch=patch,
                backend=backend,
                finding=finding,
                probe_spec=probe,
            )
            assert result.verified is True, f"{rule} failed verification: {result.summary} | {result.logs}"
            assert result.dynamic_probe_before is not None
            assert result.dynamic_probe_before.matched_vulnerable is True
            assert result.dynamic_probe_after is not None
            assert result.dynamic_probe_after.matched_fixed is True
            assert result.dynamic_confirmed_and_fixed is True
            assert result.existing_tests_passed_after is True
    finally:
        cleanup_workspace(ws)

    # Confirm zero mutation of target repo
    assert (repo / "server.mjs").read_text(encoding="utf-8") == orig_server_src
