"""Sandbox Python memory-probe preload (`sitecustomize.py`) using stdlib tracemalloc + gc.

Activated only when `VULNBOX_MEM_SNAP_FILE` is set. Responds to SIGUSR1 by forcing GC,
diffing tracemalloc snapshots against the warmup baseline, and atomically writing JSON.
"""

from __future__ import annotations

import gc
import json
import os
import signal
import tracemalloc
from pathlib import Path
from typing import Any

_SNAP_FILE = os.environ.get("VULNBOX_MEM_SNAP_FILE", "")
_WORKSPACE = os.environ.get("VULNBOX_MEM_WORKSPACE", "")
_BASELINE_SNAP: tracemalloc.Snapshot | None = None
_SEQ = 0


def _rel_path(filename: str, ws_root: str) -> str:
    try:
        resolved = str(Path(filename).resolve())
        if ws_root and resolved.startswith(ws_root + os.sep):
            return resolved[len(ws_root) + 1 :].replace("\\", "/")
    except OSError:
        pass
    return filename


def _install() -> None:
    if not _SNAP_FILE:
        return
    ws_root = str(Path(_WORKSPACE).resolve()) if _WORKSPACE else ""
    tracemalloc.start(15)

    def _on_sigusr1(_signum, _frame) -> None:
        global _BASELINE_SNAP, _SEQ
        _SEQ += 1
        gc.collect()
        gc.collect()
        snap = tracemalloc.take_snapshot()
        current_bytes, _peak_bytes = tracemalloc.get_traced_memory()
        gc_garbage_count = len(gc.garbage)

        top_allocs: list[dict[str, Any]] = []
        retainer_summary = ""
        if _SEQ <= 2 or _BASELINE_SNAP is None:
            # seq=1 warms up snapshot machinery; seq=2 captures clean S0 baseline
            _BASELINE_SNAP = snap
        else:
            # Prefer workspace frames (excluding .vulnbox_memprobe) first
            diffs = snap.compare_to(_BASELINE_SNAP, "lineno")
            ws_diffs = [
                d
                for d in diffs
                if d.size_diff > 0
                and d.traceback
                and ws_root
                and str(Path(d.traceback[0].filename).resolve()).startswith(ws_root + os.sep)
                and ".vulnbox_memprobe" not in d.traceback[0].filename
            ]
            chosen = ws_diffs[:5] if ws_diffs else [d for d in diffs if d.size_diff > 0][:5]
            for stat in chosen:
                frame = stat.traceback[0]
                loc = f"{_rel_path(frame.filename, ws_root)}:{frame.lineno}"
                tb_lines = [
                    f"{_rel_path(f.filename, ws_root)}:{f.lineno}" for f in stat.traceback[:4]
                ]
                top_allocs.append(
                    {
                        "location": loc,
                        "size_diff_bytes": int(stat.size_diff),
                        "count_diff": int(stat.count_diff),
                        "traceback_excerpt": " <- ".join(tb_lines),
                    }
                )
            if top_allocs:
                retainer_summary = (
                    f"Top retained allocation at {top_allocs[0]['location']} "
                    f"(+{int(top_allocs[0]['size_diff_bytes']) / 1024:.1f} KB, "
                    f"+{top_allocs[0]['count_diff']} blocks)"
                )

        payload = {
            "seq": _SEQ,
            "heap_bytes": int(current_bytes),
            "gc_uncollectable": int(gc_garbage_count),
            "top_allocations": top_allocs,
            "retainer_summary": retainer_summary,
        }
        out = Path(_SNAP_FILE)
        tmp = out.with_suffix(".tmp")
        try:
            tmp.write_text(json.dumps(payload), encoding="utf-8")
            os.replace(tmp, out)
        except OSError:
            pass

    try:
        signal.signal(signal.SIGUSR1, _on_sigusr1)
    except (OSError, ValueError):
        pass


_install()
