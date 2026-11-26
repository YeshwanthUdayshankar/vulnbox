"""Analyzer registry and combined runner."""

from __future__ import annotations

from pathlib import Path

from vulnbox.analyzers.config_hygiene import ConfigHygieneAnalyzer
from vulnbox.analyzers.dependency_reachability import DependencyReachabilityAnalyzer
from vulnbox.analyzers.node_sast import NodeSASTAnalyzer
from vulnbox.analyzers.python_sast import PythonSASTAnalyzer
from vulnbox.models import Finding, ScrubSummary


def run_all_analyzers(
    workspace_dir: Path,
    scrub_summary: ScrubSummary | None = None,
    advisories_path: Path | None = None,
) -> list[Finding]:
    """Run all deterministic analyzers and return deduplicated findings."""
    findings: list[Finding] = []
    findings.extend(PythonSASTAnalyzer().analyze(workspace_dir))
    findings.extend(NodeSASTAnalyzer().analyze(workspace_dir))
    findings.extend(ConfigHygieneAnalyzer().analyze(workspace_dir, scrub_summary=scrub_summary))
    findings.extend(DependencyReachabilityAnalyzer(advisories_path).analyze(workspace_dir))

    seen: set[str] = set()
    deduped: list[Finding] = []
    for f in findings:
        if f.finding_id not in seen:
            seen.add(f.finding_id)
            deduped.append(f)
    return deduped


__all__ = [
    "ConfigHygieneAnalyzer",
    "DependencyReachabilityAnalyzer",
    "NodeSASTAnalyzer",
    "PythonSASTAnalyzer",
    "run_all_analyzers",
]
