"""Registry-backed analyzer adapters and combined runner."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from vulnbox.analyzers.config_hygiene import ConfigHygieneAnalyzer
from vulnbox.analyzers.dependency_reachability import DependencyReachabilityAnalyzer
from vulnbox.analyzers.memory_leaks import MemoryLeakAnalyzer
from vulnbox.analyzers.node_sast import NodeSASTAnalyzer
from vulnbox.analyzers.python_sast import PythonSASTAnalyzer
from vulnbox.models import Finding, RepoProfile, ScrubSummary
from vulnbox.registry import AnalysisContext, PluginRegistry, default_registry


class _PythonSASTPlugin:
    name = "python-sast"

    def run(self, ctx: AnalysisContext) -> list[Finding]:
        return PythonSASTAnalyzer().analyze(ctx.workspace_dir)


class _NodeSASTPlugin:
    name = "node-sast"

    def run(self, ctx: AnalysisContext) -> list[Finding]:
        return NodeSASTAnalyzer().analyze(ctx.workspace_dir)


class _ConfigHygienePlugin:
    name = "config-hygiene"

    def run(self, ctx: AnalysisContext) -> list[Finding]:
        return ConfigHygieneAnalyzer().analyze(ctx.workspace_dir, scrub_summary=ctx.scrub_summary)


class _DependencyReachabilityPlugin:
    name = "dependency-reachability"

    def run(self, ctx: AnalysisContext) -> list[Finding]:
        return DependencyReachabilityAnalyzer(ctx.advisories_path).analyze(
            ctx.workspace_dir, call_graph=ctx.call_graph
        )


class _MemoryLeaksPlugin:
    name = "memory-leaks"

    def run(self, ctx: AnalysisContext) -> list[Finding]:
        return MemoryLeakAnalyzer().analyze(ctx.workspace_dir, call_graph=ctx.call_graph)


def register_builtin_analyzers(registry: PluginRegistry = default_registry) -> None:
    """Register all built-in deterministic analyzers into the target registry."""
    registry.register_analyzer(_PythonSASTPlugin())
    registry.register_analyzer(_NodeSASTPlugin())
    registry.register_analyzer(_ConfigHygienePlugin())
    registry.register_analyzer(_DependencyReachabilityPlugin())
    registry.register_analyzer(_MemoryLeaksPlugin())


register_builtin_analyzers(default_registry)


def run_all_analyzers(
    workspace_dir: Path,
    scrub_summary: ScrubSummary | None = None,
    advisories_path: Path | None = None,
    profile: RepoProfile | None = None,
    registry: PluginRegistry | None = None,
    call_graph: Any | None = None,
) -> list[Finding]:
    """Run all registered analyzers (including entry_points plugins) and deduplicate findings."""
    reg = registry or default_registry
    if reg is default_registry:
        reg.load_entry_point_plugins()

    ctx = AnalysisContext(
        workspace_dir=workspace_dir,
        profile=profile,
        scrub_summary=scrub_summary,
        advisories_path=advisories_path,
        call_graph=call_graph,
    )
    findings: list[Finding] = []
    for analyzer in reg.list_analyzers():
        findings.extend(analyzer.run(ctx))

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
    "MemoryLeakAnalyzer",
    "NodeSASTAnalyzer",
    "PythonSASTAnalyzer",
    "register_builtin_analyzers",
    "run_all_analyzers",
]
