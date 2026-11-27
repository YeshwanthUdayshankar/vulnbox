"""Extensible plugin registry for analyzers, patchers, regression tests, probes, and reporters."""

from __future__ import annotations

import importlib.metadata
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol, runtime_checkable

from vulnbox.models import (
    AuditReport,
    DynamicProbeSpec,
    Finding,
    MemoryLeakProbeSpec,
    PatchCandidate,
    RepoProfile,
    ScrubSummary,
)


@dataclass(frozen=True)
class AnalysisContext:
    """Uniform context passed to every registered analyzer."""

    workspace_dir: Path
    profile: RepoProfile | None = None
    scrub_summary: ScrubSummary | None = None
    advisories_path: Path | None = None
    advisory_cache_dir: Path | None = None
    call_graph: Any | None = None


@runtime_checkable
class AnalyzerPlugin(Protocol):
    """Protocol implemented by built-in and third-party security analyzers."""

    name: str

    def run(self, ctx: AnalysisContext) -> list[Finding]: ...


@runtime_checkable
class ReporterPlugin(Protocol):
    """Protocol implemented by built-in and third-party report exporters."""

    name: str

    def write(self, report: AuditReport, out_dir: Path) -> Path: ...


@runtime_checkable
class MemoryProfilerAdapter(Protocol):
    """Pluggable memory/FD profiler backend with graceful compatibility checks."""

    name: str
    priority: int  # Higher priority adapters are checked first

    def check_compatibility(
        self, start_cmd: str, backend_name: str
    ) -> tuple[bool, str]: ...

    def prepare_sandbox(
        self,
        probe_dir: Path,
        probe_dir_sb: str,
        start_cmd: str,
        is_docker: bool,
    ) -> dict[str, Any]: ...


PatcherFn = Callable[[Finding, Path], PatchCandidate | None]
RegressionTestFn = Callable[[Finding], tuple[str, str] | None]
ProbeInferFn = Callable[[Finding, Path], DynamicProbeSpec | None]
MemoryProbeInferFn = Callable[[Finding, Path, Any | None], MemoryLeakProbeSpec | None]


class PluginRegistry:
    """Central extensible registry supporting decorators and pip entry_points discovery."""

    def __init__(self) -> None:
        self._analyzers: dict[str, AnalyzerPlugin] = {}
        self._patchers: dict[str, PatcherFn] = {}
        self._category_patchers: dict[str, PatcherFn] = {}
        self._regression_tests: dict[str, RegressionTestFn] = {}
        self._category_regression_tests: dict[str, RegressionTestFn] = {}
        self._probes: dict[str, ProbeInferFn] = {}
        self._memory_probes: dict[str, MemoryProbeInferFn] = {}
        self._memory_profilers: dict[str, MemoryProfilerAdapter] = {}
        self._reporters: dict[str, ReporterPlugin] = {}
        self._entry_points_loaded: bool = False

    # --- Analyzers ---

    def register_analyzer(self, analyzer: AnalyzerPlugin) -> AnalyzerPlugin:
        self._analyzers[analyzer.name] = analyzer
        return analyzer

    def list_analyzers(self) -> list[AnalyzerPlugin]:
        return list(self._analyzers.values())

    # --- Patchers ---

    def register_patcher(
        self,
        *rule_ids: str,
        category: str | None = None,
    ) -> Callable[[PatcherFn], PatcherFn]:
        def _decorator(fn: PatcherFn) -> PatcherFn:
            for rid in rule_ids:
                self._patchers[rid] = fn
            if category is not None:
                self._category_patchers[category] = fn
            return fn

        return _decorator

    def get_patcher(self, finding: Finding) -> PatcherFn | None:
        return self._patchers.get(finding.rule_id) or self._category_patchers.get(
            finding.category
        )

    # --- Regression Test Generators ---

    def register_regression_test(
        self,
        *rule_ids: str,
        category: str | None = None,
    ) -> Callable[[RegressionTestFn], RegressionTestFn]:
        def _decorator(fn: RegressionTestFn) -> RegressionTestFn:
            for rid in rule_ids:
                self._regression_tests[rid] = fn
            if category is not None:
                self._category_regression_tests[category] = fn
            return fn

        return _decorator

    def get_regression_test_generator(self, finding: Finding) -> RegressionTestFn | None:
        return self._regression_tests.get(
            finding.rule_id
        ) or self._category_regression_tests.get(finding.category)

    # --- Active Dynamic Probe Inference ---

    def register_probe(self, *rule_ids: str) -> Callable[[ProbeInferFn], ProbeInferFn]:
        def _decorator(fn: ProbeInferFn) -> ProbeInferFn:
            for rid in rule_ids:
                self._probes[rid] = fn
            return fn

        return _decorator

    def get_probe_inferrer(self, finding: Finding) -> ProbeInferFn | None:
        return self._probes.get(finding.rule_id)

    # --- Active Memory & Resource Leak Probe Inference ---

    def register_memory_probe(self, *rule_ids: str) -> Callable[[MemoryProbeInferFn], MemoryProbeInferFn]:
        def _decorator(fn: MemoryProbeInferFn) -> MemoryProbeInferFn:
            for rid in rule_ids:
                self._memory_probes[rid] = fn
            return fn

        return _decorator

    def get_memory_probe_inferrer(self, finding: Finding) -> MemoryProbeInferFn | None:
        return self._memory_probes.get(finding.rule_id)

    # --- Pluggable Memory Profiler Backends ---

    def register_memory_profiler(
        self, profiler: MemoryProfilerAdapter
    ) -> MemoryProfilerAdapter:
        self._memory_profilers[profiler.name] = profiler
        return profiler

    def list_memory_profilers(self) -> list[MemoryProfilerAdapter]:
        return sorted(
            self._memory_profilers.values(),
            key=lambda p: p.priority,
            reverse=True,
        )

    def select_memory_profiler(
        self, start_cmd: str, backend_name: str
    ) -> tuple[MemoryProfilerAdapter | None, list[str]]:
        """Pick the highest-priority compatible memory profiler or return skip reasons."""
        reasons: list[str] = []
        for profiler in self.list_memory_profilers():
            ok, reason = profiler.check_compatibility(start_cmd, backend_name)
            if ok:
                return profiler, reasons
            reasons.append(f"{profiler.name}: {reason}")
        return None, reasons

    # --- Reporters ---

    def register_reporter(self, reporter: ReporterPlugin) -> ReporterPlugin:
        self._reporters[reporter.name] = reporter
        return reporter

    def list_reporters(self) -> list[ReporterPlugin]:
        return list(self._reporters.values())

    # --- Third-party entry_points discovery ---

    def load_entry_point_plugins(self, group: str = "vulnbox.plugins") -> list[str]:
        """Discover and invoke installed third-party plugin hooks once."""
        if self._entry_points_loaded:
            return []
        self._entry_points_loaded = True
        loaded: list[str] = []
        for ep in importlib.metadata.entry_points(group=group):
            registrar = ep.load()
            if callable(registrar):
                registrar(self)
                loaded.append(ep.name)
        return loaded


default_registry = PluginRegistry()
