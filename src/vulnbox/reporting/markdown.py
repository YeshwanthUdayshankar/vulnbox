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
    mem_confirmed = sum(
        1 for v in report.verifications if v.memory_leak_confirmed_and_fixed is True
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
        f"| **LLM Assistance** | `{f'enabled ({report.llm_model})' if report.llm_enabled else 'disabled (deterministic only)'}` |",
        f"| **Timestamp (UTC)** | `{report.timestamp}` |",
        f"| **Files Scrubbed / Secrets Redacted** | {len(report.scrub_summary.files_scrubbed)} files / {report.scrub_summary.secrets_redacted} redactions |",
        f"| **Total Findings** | {total} |",
        f"| **Dual-Verified Patches** | {verified_count} / {len(report.patches)} |",
        f"| **Actively Confirmed & Fixed (Live `curl` Probe)** | {active_confirmed} |",
        f"| **Memory & FD Leaks Confirmed & Fixed** | {mem_confirmed} |",
        f"| **Guardrail Events (Blocks / Warnings)** | {sum(1 for g in report.guardrail_events if g.decision == 'block')} blocked / {sum(1 for g in report.guardrail_events if g.decision == 'warn')} warnings |",
        "",
    ]

    if report.call_graph_summary is not None:
        cg = report.call_graph_summary
        prov_str = ", ".join(f"`{k}`={v}" for k, v in sorted(cg.edges_by_provenance.items())) or "none"
        lines.extend(
            [
                "## Hybrid Call Graph Summary",
                "",
                f"- **Nodes / Edges:** `{cg.total_nodes}` nodes / `{cg.total_edges}` edges ({prov_str})",
                f"- **Entrypoints Detected:** `{len(cg.entrypoints)}`",
                f"- **Dynamic Sites Resolved at Runtime:** `{cg.runtime_resolved_count}` | **Remaining Unresolved Sites:** `{len(cg.unresolved_sites)}`",
                "",
            ]
        )

    lines.extend(["## Findings Overview", ""])

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
                elif ver.memory_leak_confirmed_and_fixed is True:
                    active_str = "LEAK -> FIXED"
                elif ver.dynamic_probe_before is not None and ver.dynamic_probe_before.skipped:
                    active_str = "SKIPPED"
                elif ver.dynamic_confirmed_and_fixed is False or ver.memory_leak_confirmed_and_fixed is False:
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
                pb = ver.dynamic_probe_before
                lines.extend(
                    [
                        f"#### Active Loopback Verification (`curl` Before vs. After Patch — mode: `{pb.probe_mode}`)",
                        "",
                        "```bash",
                        pb.curl_command,
                        "```",
                        "",
                    ]
                )
                if pb.skipped:
                    lines.append(
                        f"- **Probe Status:** `SKIPPED` — {pb.skip_reason or pb.error or 'missing runtime deps or services'}"
                    )
                else:
                    lines.append(
                        f"- **Pre-Patch Response:** HTTP `{pb.status_code}` | `matched_vulnerable={pb.matched_vulnerable}`"
                    )
                    if pb.response_body_excerpt:
                        lines.append(
                            f"  - Excerpt: `{pb.response_body_excerpt[:160].replace(chr(10), ' ')}`"
                        )
                    if pb.outbound_calls:
                        hosts = ", ".join(
                            f"`{c.method} {c.host}{c.path}` (HTTP {c.status_code})"
                            for c in pb.outbound_calls[:10]
                        )
                        lines.append(f"  - **Intercepted Outbound Calls (SSRF Canary):** {hosts}")
                    if ver.dynamic_probe_after is not None:
                        pa = ver.dynamic_probe_after
                        if pa.skipped:
                            lines.append(
                                f"- **Post-Patch Response:** `SKIPPED` — {pa.skip_reason or pa.error}"
                            )
                        else:
                            lines.append(
                                f"- **Post-Patch Response (Same Probe):** HTTP `{pa.status_code}` | `matched_fixed={pa.matched_fixed}` | `matched_vulnerable={pa.matched_vulnerable}`"
                            )
                            if pa.response_body_excerpt:
                                lines.append(
                                    f"  - Excerpt: `{pa.response_body_excerpt[:160].replace(chr(10), ' ')}`"
                                )
                lines.append("")

            if ver.memory_probe_before is not None:
                mb = ver.memory_probe_before
                lines.extend(
                    [
                        "#### Active Memory & File-Descriptor Leak Verification (Before vs. After Patch)",
                        "",
                        f"- **Endpoint:** `{mb.endpoint}`",
                        f"- **Pre-Patch:** slope=`{mb.bytes_per_request_slope:.1f} B/req` ($R^2={mb.r_squared:.2f}$), heap_growth=`{mb.total_heap_growth_bytes} B`, fd_delta=`{mb.fd_delta}`, `leak_detected={mb.leak_detected}`",
                    ]
                )
                if mb.retainer_summary:
                    lines.append(f"  - Root Cause Attribution: {mb.retainer_summary}")
                if ver.memory_probe_after is not None:
                    ma = ver.memory_probe_after
                    lines.append(
                        f"- **Post-Patch (Same Stress Loop):** slope=`{ma.bytes_per_request_slope:.1f} B/req` ($R^2={ma.r_squared:.2f}$), heap_growth=`{ma.total_heap_growth_bytes} B`, fd_delta=`{ma.fd_delta}`, `leak_detected={ma.leak_detected}`"
                    )
                lines.append("")

        if patch is not None:
            if patch.root_cause_explanation:
                lines.append(f"- **Core Issue:** {patch.root_cause_explanation}")
            if patch.probe_explanation:
                lines.append(f"- **How the Probe Verifies It:** {patch.probe_explanation}")
            if patch.fix_explanation:
                lines.append(f"- **How the Fix Resolves It:** {patch.fix_explanation}")
            if patch.strategy == "llm_synthesized":
                lines.append(f"- **Patch Source:** `llm_synthesized` (attempts={patch.llm_attempts})")
            if any((patch.root_cause_explanation, patch.probe_explanation, patch.fix_explanation)):
                lines.append("")

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

    if report.guardrail_events:
        lines.extend(
            [
                "---",
                "",
                "## Guardrail Audit Trail",
                "",
                "| Gate | Decision | Finding ID | Reason |",
                "| :--- | :--- | :--- | :--- |",
            ]
        )
        for ev in report.guardrail_events:
            clean_reason = " ".join(ev.reason.splitlines()).replace("|", "\\|")
            lines.append(
                f"| `{ev.gate}` | **{ev.decision.upper()}** | `{ev.finding_id or '-'}` | {clean_reason} |"
            )
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
