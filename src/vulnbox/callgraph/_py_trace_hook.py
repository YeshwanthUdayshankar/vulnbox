"""Sandbox runtime call-graph hook for Python (PEP 669 sys.monitoring + 3.11 fallback).

Copied into an ephemeral sandbox hook directory as `sitecustomize.py` and controlled
exclusively via `VULNBOX_TRACE_WORKSPACE` and `VULNBOX_TRACE_OUT` environment variables.
"""

from __future__ import annotations

import atexit
import json
import os
import signal
import sys
from pathlib import Path

_WORKSPACE = os.environ.get("VULNBOX_TRACE_WORKSPACE", "")
_OUT_FILE = os.environ.get("VULNBOX_TRACE_OUT", "")
_EDGES: set[tuple[str, str, str, int]] = set()
_NODES: dict[str, tuple[str, str, int]] = {}
_FLUSHED = False


def _rel_in_workspace(filename: str, ws_root: str) -> str | None:
    if not filename or filename.startswith("<"):
        return None
    try:
        resolved = str(Path(filename).resolve())
    except OSError:
        return None
    if resolved.startswith(ws_root + os.sep):
        rel = resolved[len(ws_root) + 1 :]
        if not rel.startswith((".vulnbox", "__pycache__")):
            return rel.replace("\\", "/")
    return None


def _qual_symbol(frame) -> str:
    code = frame.f_code
    name = getattr(code, "co_qualname", code.co_name)
    return str(name)


def _record_edge(caller_frame, callee_frame, ws_root: str) -> None:
    if caller_frame is None or callee_frame is None:
        return
    caller_rel = _rel_in_workspace(caller_frame.f_code.co_filename, ws_root)
    if caller_rel is None:
        return
    callee_file = callee_frame.f_code.co_filename
    callee_rel = _rel_in_workspace(callee_file, ws_root)
    caller_sym = _qual_symbol(caller_frame)
    callee_sym = _qual_symbol(callee_frame)
    if caller_sym == "<module>" and callee_sym == "<module>":
        return

    caller_id = f"{caller_rel}::{caller_sym}"
    _NODES[caller_id] = (caller_rel, caller_sym, caller_frame.f_code.co_firstlineno)
    if callee_rel is not None:
        callee_id = f"{callee_rel}::{callee_sym}"
        _NODES[callee_id] = (callee_rel, callee_sym, callee_frame.f_code.co_firstlineno)
    else:
        mod = callee_frame.f_globals.get("__name__", "")
        if not mod or mod.startswith(("_", "pytest", "pluggy", "importlib", "unittest")):
            return
        callee_id = f"external::{mod}.{callee_sym}"

    if caller_id != callee_id:
        _EDGES.add((caller_id, callee_id, caller_rel, int(caller_frame.f_lineno)))


def _flush() -> None:
    global _FLUSHED
    if _FLUSHED or not _OUT_FILE:
        return
    _FLUSHED = True
    payload = {
        "nodes": [
            {"node_id": nid, "file_path": fp, "symbol": sym, "line": ln}
            for nid, (fp, sym, ln) in sorted(_NODES.items())
        ],
        "edges": [
            {"caller": c, "callee": t, "file_path": fp, "line": ln}
            for c, t, fp, ln in sorted(_EDGES)
        ],
    }
    try:
        out_path = Path(_OUT_FILE)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        # Merge with any prior child-process dump in the same sandbox run
        if out_path.is_file():
            try:
                prev = json.loads(out_path.read_text(encoding="utf-8"))
                seen_n = {n["node_id"]: n for n in prev.get("nodes", [])}
                for n in payload["nodes"]:
                    seen_n[n["node_id"]] = n
                seen_e = {
                    (e["caller"], e["callee"], e["file_path"], e["line"]): e
                    for e in prev.get("edges", [])
                }
                for e in payload["edges"]:
                    seen_e[(e["caller"], e["callee"], e["file_path"], e["line"])] = e
                payload = {"nodes": list(seen_n.values()), "edges": list(seen_e.values())}
            except (OSError, ValueError):
                pass
        out_path.write_text(json.dumps(payload), encoding="utf-8")
    except OSError:
        pass


def _install() -> None:
    if not _WORKSPACE or not _OUT_FILE:
        return
    ws_root = str(Path(_WORKSPACE).resolve())
    atexit.register(_flush)

    prev_sigterm = signal.getsignal(signal.SIGTERM)

    def _on_sigterm(signum, frame):
        _flush()
        if callable(prev_sigterm):
            prev_sigterm(signum, frame)
        raise SystemExit(0)

    try:
        signal.signal(signal.SIGTERM, _on_sigterm)
    except (OSError, ValueError):
        pass

    monitoring = getattr(sys, "monitoring", None)
    if monitoring is not None:
        tool_id = None
        for cand in (4, 3, 2, 5):
            if monitoring.get_tool(cand) is None:
                tool_id = cand
                break
        if tool_id is not None:
            monitoring.use_tool_id(tool_id, "vulnbox_callgraph")

            def _on_py_start(code, _offset):
                try:
                    frame = sys._getframe(1)
                    if frame.f_code is code:
                        _record_edge(frame.f_back, frame, ws_root)
                except ValueError:
                    pass

            monitoring.register_callback(tool_id, monitoring.events.PY_START, _on_py_start)
            monitoring.set_events(tool_id, monitoring.events.PY_START)
            return

    def _profile_fn(frame, event, _arg):
        if event == "call":
            _record_edge(frame.f_back, frame, ws_root)

    sys.setprofile(_profile_fn)


_install()
