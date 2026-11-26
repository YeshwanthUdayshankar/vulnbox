"""Markdown audit & remediation report renderer."""

from __future__ import annotations

from vulnbox.models import AuditReport


def render_markdown_report(report: AuditReport) -> str:
    """Render a human-readable Markdown report with active before/after curl proof."""
    ver_by_finding = {v.finding_id: v for v in report.verifications}
    patch_by_finding = {p.finding_id: p for p in report.patches}

    total = len(report.findings)
    verified_count = sum(1 for v in report.verifications if v.verified)
    active_confirmed = sum(
        1 for v in report.verifications if v.dynamic_confirmed_and_fixed is True
    )

    lines: list[str] = [
        "# VulnBox Sandboxed Security & Remediation Report",
        "",
        "## Executive Summary",
        "",
        "| Field | Value |",
        "| :--- | :--- |",
        f"| **Repository** | `{report.profile.repo_path}` |",
        f"| **Ecosystem** | `{report.profile.ecosystem}` |",
        f"| **Sandbox Backend** | `{report.sandbox_backend}` |",
        f"| **Timestamp (UTC)** | `{report.timestamp}` |",
        f"| **Files Scrubbed / Secrets Redacted** | {len(report.scrub_summary.files_scrubbed)} files / {report.scrub_summary.secrets_redacted} redactions |",
        f"| **Total Findings** | {total} |",
        f"| **Dual-Verified Patches** | {verified_count} / {len(report.patches)} |",
        f"| **Actively Confirmed & Fixed (Live `curl` Probe)** | {active_confirmed} |",
        "",
        "## Findings Overview",
        "",
    ]

    if not report.findings:
        lines.append("No vulnerabilities or hygiene issues detected.")
    else:
        lines.extend(
            [
                "| Finding ID | Rule | CWE | Severity | Location | Reachability | Active Probe | Patch Status |",
                "| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |",
            ]
        )
        for f in report.findings:
            ver = ver_by_finding.get(f.finding_id)
            if ver is None:
                active_str = "N/A"
                patch_str = "Manual review"
            else:
                if ver.dynamic_confirmed_and_fixed is True:
                    active_str = "CONFIRMED -> FIXED"
                elif ver.dynamic_confirmed_and_fixed is False:
                    active_str = "FAILED"
                else:
                    active_str = "Static/Unit"
                patch_str = "VERIFIED" if ver.verified else "UNVERIFIED"
            lines.append(
                f"| `{f.finding_id}` | `{f.rule_id}` | `{f.cwe_id}` | **{f.severity.upper()}** "
                f"| `{f.file_path}:{f.start_line}` | `{f.reachability}` | {active_str} | **{patch_str}** |"
            )

    lines.extend(["", "## Detailed Findings & Sandbox Verification Evidence", ""])

    for f in report.findings:
        ver = ver_by_finding.get(f.finding_id)
        patch = patch_by_finding.get(f.finding_id)
        lines.extend(
            [
                f"### {f.title} (`{f.finding_id}`)",
                "",
                f"- **Rule / CWE:** `{f.rule_id}` / `{f.cwe_id}`",
                f"- **Severity:** `{f.severity}` | **Category:** `{f.category}` | **Reachability:** `{f.reachability}`",
                f"- **Location:** `{f.file_path}:{f.start_line}-{f.end_line}`",
                f"- **Details:** {f.message}",
                f"- **Recommended Fix:** {f.recommended_fix}",
                "",
            ]
        )
        if f.snippet:
            lines.extend(["```text", f.snippet, "```", ""])

        if ver is not None:
            lines.extend(
                [
                    "#### Sandbox Verification Results",
                    "",
                    f"- **Overall Verified:** `{ver.verified}` ({ver.summary})",
                    f"- **Static Finding Resolved:** `{ver.finding_resolved}` | **No New Findings:** `{ver.no_new_findings}`",
                    f"- **Existing Test Suite:** baseline=`{ver.baseline_tests_passed}`, post-patch=`{ver.existing_tests_passed_after}`",
                ]
            )
            if ver.regression_test_failed_before is not None:
                lines.append(
                    f"- **Defensive Regression Test:** failed_before=`{ver.regression_test_failed_before}`, passed_after=`{ver.regression_test_passed_after}`"
                )
            lines.append("")

            if ver.dynamic_probe_before is not None:
                lines.extend(
                    [
                        "#### Active Loopback Verification (`curl` Before vs. After Patch)",
                        "",
                        "```bash",
                        ver.dynamic_probe_before.curl_command,
                        "```",
                        "",
                        f"- **Pre-Patch Response:** HTTP `{ver.dynamic_probe_before.status_code}` | `matched_vulnerable={ver.dynamic_probe_before.matched_vulnerable}`",
                    ]
                )
                if ver.dynamic_probe_before.response_body_excerpt:
                    lines.append(
                        f"  - Excerpt: `{ver.dynamic_probe_before.response_body_excerpt[:160].replace(chr(10), ' ')}`"
                    )
                if ver.dynamic_probe_after is not None:
                    lines.append(
                        f"- **Post-Patch Response (Same Probe):** HTTP `{ver.dynamic_probe_after.status_code}` | `matched_fixed={ver.dynamic_probe_after.matched_fixed}` | `matched_vulnerable={ver.dynamic_probe_after.matched_vulnerable}`"
                    )
                    if ver.dynamic_probe_after.response_body_excerpt:
                        lines.append(
                            f"  - Excerpt: `{ver.dynamic_probe_after.response_body_excerpt[:160].replace(chr(10), ' ')}`"
                        )
                lines.append("")

        if patch is not None:
            lines.extend(
                [
                    f"#### Suggested Patch (`patches/{f.finding_id}.patch`)",
                    "",
                    "```diff",
                    patch.unified_diff.rstrip("\n"),
                    "```",
                    "",
                ]
            )
            if patch.regression_test_path:
                lines.append(f"- **Generated Regression Test:** `{patch.regression_test_path}`")
                lines.append("")

    lines.extend(
        [
            "---",
            "",
            "## Mandatory Human-in-the-Loop (HITL) Review Gate",
            "",
            "`vulnbox` never modifies your target repository directly. Before applying any suggested patch:",
            "1. Review each unified diff in `patches/` for business-logic and compatibility impact.",
            "2. Confirm every active `curl` before/after probe and regression test passed (`VERIFIED`).",
            "3. Apply selected patches cleanly with `git apply patches/<finding_id>.patch` and copy the generated regression tests into your repository test suite.",
            "",
        ]
    )

    return "\n".join(lines)
