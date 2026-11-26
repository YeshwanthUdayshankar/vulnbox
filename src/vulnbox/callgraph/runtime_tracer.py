"""Sandbox runtime call-graph tracer for Python (sys.monitoring) and Node.js (V8 Inspector)."""

from __future__ import annotations

import json
import shlex
import shutil
import sys
from pathlib import Path

from vulnbox.callgraph.graph import CallGraph
from vulnbox.models import CallEdge, CallNode, CallNodeLanguage, RepoProfile
from vulnbox.sandbox.base import SandboxBackend, SandboxPolicy

_PY_HOOK_SRC = Path(__file__).resolve().with_name("_py_trace_hook.py")
_NODE_HOOK_SRC = Path(__file__).resolve().with_name("_node_trace_hook.mjs")


def _load_trace_payload(
    trace_file: Path,
    language: CallNodeLanguage,
    static_graph: CallGraph | None = None,
) -> CallGraph:
    cg = CallGraph()
    if not trace_file.is_file():
        return cg
    try:
        data = json.loads(trace_file.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return cg

    for item in data.get("nodes", ()):
        cg.add_node(
            CallNode(
                node_id=item["node_id"],
                file_path=item["file_path"],
                symbol=item["symbol"],
                line=int(item.get("line", 1)),
                language=language,
            )
        )
    for item in data.get("edges", ()):
        cg.add_edge(
            CallEdge(
                caller=item["caller"],
                callee=item["callee"],
                file_path=item["file_path"],
                line=int(item.get("line", 1)),
                provenance="runtime_observed",
            )
        )

    # For Node.js precise coverage: link dynamically executed functions back to unresolved
    # dispatch sites in the same file when V8 CPU sampling was too coarse to catch fast calls.
    executed = set(data.get("executed_functions", ()))
    if executed and static_graph is not None:
        known_callees = {e.callee for e in static_graph.edges} | {e.callee for e in cg.edges}
        for site in static_graph.unresolved_sites:
            for fn_id in sorted(executed):
                if fn_id in known_callees or fn_id == site.caller:
                    continue
                if fn_id.startswith(f"{site.file_path}::"):
                    cg.add_edge(
                        CallEdge(
                            caller=site.caller,
                            callee=fn_id,
                            file_path=site.file_path,
                            line=site.line,
                            provenance="runtime_observed",
                        )
                    )
    return cg


def collect_runtime_call_graph(
    workspace_dir: Path,
    profile: RepoProfile,
    backend: SandboxBackend,
    policy: SandboxPolicy | None = None,
    static_graph: CallGraph | None = None,
) -> CallGraph:
    """Run existing tests inside the sandbox with runtime tracing hooks to capture ground-truth edges."""
    pol = policy or SandboxPolicy()
    combined = CallGraph()
    if not profile.test_commands:
        return combined

    hook_dir = workspace_dir / ".vulnbox_trace"
    hook_dir.mkdir(parents=True, exist_ok=True)
    ws_path_in_sandbox = "/workspace" if backend.name == "docker" else str(workspace_dir)
    hook_dir_in_sandbox = (
        "/workspace/.vulnbox_trace" if backend.name == "docker" else str(hook_dir)
    )

    try:
        if "python" in profile.test_commands:
            py_hook_dir = hook_dir / "pyhook"
            py_hook_dir.mkdir(parents=True, exist_ok=True)
            shutil.copy2(_PY_HOOK_SRC, py_hook_dir / "sitecustomize.py")
            py_out = hook_dir / "py_trace.json"
            py_out_sb = f"{hook_dir_in_sandbox}/py_trace.json"
            py_hook_sb = f"{hook_dir_in_sandbox}/pyhook"

            test_cmd = profile.test_commands["python"]
            if backend.name != "docker" and test_cmd.startswith("python3 "):
                test_cmd = f"{shlex.quote(sys.executable)} {test_cmd[len('python3 ') :]}"

            backend.run(
                workspace_dir,
                test_cmd,
                env={
                    "PYTHONPATH": f"{py_hook_sb}:{ws_path_in_sandbox}",
                    "VULNBOX_TRACE_WORKSPACE": ws_path_in_sandbox,
                    "VULNBOX_TRACE_OUT": py_out_sb,
                },
                policy=pol,
            )
            combined.merge(_load_trace_payload(py_out, "python", static_graph))

        if "node" in profile.test_commands:
            node_hook = hook_dir / "_node_trace_hook.mjs"
            shutil.copy2(_NODE_HOOK_SRC, node_hook)
            node_out = hook_dir / "node_trace.json"
            node_out_sb = f"{hook_dir_in_sandbox}/node_trace.json"
            node_hook_sb = f"{hook_dir_in_sandbox}/_node_trace_hook.mjs"

            backend.run(
                workspace_dir,
                profile.test_commands["node"],
                env={
                    "NODE_OPTIONS": f"--import file://{node_hook_sb}",
                    "VULNBOX_TRACE_WORKSPACE": ws_path_in_sandbox,
                    "VULNBOX_TRACE_OUT": node_out_sb,
                },
                policy=pol,
            )
            combined.merge(_load_trace_payload(node_out, "javascript", static_graph))
    finally:
        shutil.rmtree(hook_dir, ignore_errors=True)

    return combined
