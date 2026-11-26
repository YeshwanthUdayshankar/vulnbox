"""Hybrid call-graph builder merging static AST/Tree-sitter graphs with optional runtime traces."""

from __future__ import annotations

from pathlib import Path

from vulnbox.callgraph.graph import CallGraph
from vulnbox.callgraph.runtime_tracer import collect_runtime_call_graph
from vulnbox.callgraph.static_node import build_node_static_call_graph
from vulnbox.callgraph.static_python import build_python_static_call_graph
from vulnbox.models import RepoProfile
from vulnbox.sandbox.base import SandboxBackend, SandboxPolicy


def build_hybrid_call_graph(
    workspace_dir: Path,
    profile: RepoProfile | None = None,
    backend: SandboxBackend | None = None,
    policy: SandboxPolicy | None = None,
    *,
    include_runtime: bool = False,
) -> CallGraph:
    """Build a unified provenance-tagged call graph across Python and JS/TS files."""
    cg = CallGraph()
    cg.merge(build_python_static_call_graph(workspace_dir))
    cg.merge(build_node_static_call_graph(workspace_dir))

    if include_runtime and profile is not None and backend is not None:
        rt_graph = collect_runtime_call_graph(
            workspace_dir,
            profile=profile,
            backend=backend,
            policy=policy,
            static_graph=cg,
        )
        cg.merge(rt_graph)

    return cg
