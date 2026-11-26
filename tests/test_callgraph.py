"""Tests for the Hybrid Provenance-Tagged Call Graph (static AST/Tree-sitter + sandbox runtime)."""

from __future__ import annotations

from pathlib import Path

from vulnbox.analyzers.dependency_reachability import DependencyReachabilityAnalyzer
from vulnbox.callgraph import build_hybrid_call_graph
from vulnbox.engine import VulnBoxEngine
from vulnbox.profiler import profile_repo
from vulnbox.sandbox.local_backend import LocalSandboxBackend

FIXTURES = Path(__file__).parent / "fixtures"


def test_python_static_call_graph_extracts_fastapi_depends_and_flags_getattr(tmp_path: Path) -> None:
    (tmp_path / "db.py").write_text(
        "def get_db():\n    return 'db'\n",
        encoding="utf-8",
    )
    (tmp_path / "api.py").write_text(
        "from fastapi import Depends, FastAPI\n"
        "from db import get_db\n"
        "app = FastAPI()\n"
        "@app.get('/items')\n"
        "def list_items(db=Depends(get_db)):\n"
        "    fn = getattr(db, 'fetch')\n"
        "    return fn()\n",
        encoding="utf-8",
    )

    cg = build_hybrid_call_graph(tmp_path)
    edge_pairs = {(e.caller, e.callee): e.provenance for e in cg.edges}
    assert edge_pairs.get(("api.py::list_items", "db.py::get_db")) == "framework_introspected"
    assert any(u.reason == "dynamic_getattr" and u.file_path == "api.py" for u in cg.unresolved_sites)


def test_node_tree_sitter_call_graph_extracts_express_routes_and_subscript_gaps(tmp_path: Path) -> None:
    (tmp_path / "helper.mjs").write_text(
        "export function runJob(x) { return x; }\n",
        encoding="utf-8",
    )
    (tmp_path / "index.mjs").write_text(
        "import { runJob } from './helper.mjs';\n"
        "const table = { job: runJob };\n"
        "function handleReq(req, res) { return table[req.action](req); }\n"
        "app.get('/run', handleReq);\n",
        encoding="utf-8",
    )

    cg = build_hybrid_call_graph(tmp_path)
    edge_pairs = {(e.caller, e.callee): e.provenance for e in cg.edges}
    assert edge_pairs.get(("index.mjs::route:/run", "index.mjs::handleReq")) == "framework_introspected"
    assert any(u.reason == "subscript_dispatch" and u.file_path == "index.mjs" for u in cg.unresolved_sites)


def test_runtime_deep_tracing_resolves_python_getattr_and_node_subscript_gaps() -> None:
    backend = LocalSandboxBackend()

    # Python: getattr(Actions, action) unresolved statically -> resolved at runtime by sys.monitoring
    py_repo = FIXTURES / "py_leaky_app"
    py_static = build_hybrid_call_graph(py_repo)
    assert any(u.reason == "dynamic_getattr" for u in py_static.unresolved_sites)

    py_hybrid = build_hybrid_call_graph(
        py_repo, profile=profile_repo(py_repo), backend=backend, include_runtime=True
    )
    assert py_hybrid.runtime_resolved_count >= 1
    assert any(
        e.provenance == "runtime_observed" and "store_item" in e.callee for e in py_hybrid.edges
    )

    # Node.js: HANDLERS[action](key) unresolved statically -> resolved at runtime via V8 Inspector
    node_repo = FIXTURES / "node_leaky_app"
    node_static = build_hybrid_call_graph(node_repo)
    assert any(u.reason == "subscript_dispatch" for u in node_static.unresolved_sites)

    node_hybrid = build_hybrid_call_graph(
        node_repo, profile=profile_repo(node_repo), backend=backend, include_runtime=True
    )
    assert node_hybrid.runtime_resolved_count >= 1
    assert any(
        e.provenance == "runtime_observed" and "storeItem" in e.callee for e in node_hybrid.edges
    )


def test_dependency_reachability_attaches_entrypoint_call_path() -> None:
    py_sample = FIXTURES / "py_sample_app"
    cg = build_hybrid_call_graph(py_sample)
    findings = DependencyReachabilityAnalyzer().analyze(py_sample, call_graph=cg)
    yaml_finding = next(f for f in findings if f.rule_id == "DEP-CVE-2020-14343")
    assert yaml_finding.reachability == "reachable"
    call_path = yaml_finding.metadata.get("call_path")
    assert isinstance(call_path, list) and len(call_path) >= 2
    assert any("yaml.load" in step for step in call_path)


def test_engine_scan_includes_call_graph_summary() -> None:
    engine = VulnBoxEngine(backend="local")
    report, _ = engine.scan(FIXTURES / "py_leaky_app", deep=True)
    assert report.call_graph_summary is not None
    assert report.call_graph_summary.total_nodes >= 3
    assert report.call_graph_summary.runtime_resolved_count >= 1
