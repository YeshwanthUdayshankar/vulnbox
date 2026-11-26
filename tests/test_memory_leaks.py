"""Tests for static memory/resource leak rules and active before/after heap & FD slope verification."""

from __future__ import annotations

from pathlib import Path

from vulnbox.analyzers.memory_leaks import MemoryLeakAnalyzer
from vulnbox.callgraph import build_hybrid_call_graph
from vulnbox.engine import VulnBoxEngine
from vulnbox.reporting.sarif import build_sarif, validate_sarif

FIXTURES = Path(__file__).parent / "fixtures"


def test_static_memory_leak_rules_and_false_positive_guards(tmp_path: Path) -> None:
    # Leaky Python patterns
    (tmp_path / "leaky.py").write_text(
        "import asyncio\n"
        "from functools import lru_cache\n"
        "user_cache = {}\n"
        "class Svc:\n"
        "    @lru_cache(maxsize=None)\n"
        "    def compute(self, x):\n"
        "        user_cache[x] = x\n"
        "        return x\n"
        "def bad_read(p):\n"
        "    fh = open(p, encoding='utf-8')\n"
        "    return fh.read()\n"
        "async def bg():\n"
        "    asyncio.create_task(asyncio.sleep(0))\n",
        encoding="utf-8",
    )
    # Safe Python patterns (must produce ZERO findings)
    (tmp_path / "safe.py").write_text(
        "from collections import deque\n"
        "from functools import lru_cache\n"
        "safe_cache = {}\n"
        "safe_ring = deque(maxlen=64)\n"
        "@lru_cache(maxsize=128)\n"
        "def pure_fn(x):\n"
        "    if len(safe_cache) >= 64:\n"
        "        safe_cache.pop(next(iter(safe_cache)))\n"
        "    safe_cache[x] = x\n"
        "    return x\n"
        "def good_read(p):\n"
        "    with open(p, encoding='utf-8') as fh:\n"
        "        return fh.read()\n",
        encoding="utf-8",
    )
    # Leaky JS patterns
    (tmp_path / "leaky.mjs").write_text(
        "import fs from 'node:fs';\n"
        "const itemCache = new Map();\n"
        "setInterval(() => {}, 1000);\n"
        "export function handler(req, res) {\n"
        "  itemCache.set(req.url, 'x');\n"
        "  process.on('ping', () => req.url);\n"
        "  const s = fs.createReadStream('a.txt');\n"
        "  return s;\n"
        "}\n",
        encoding="utf-8",
    )

    cg = build_hybrid_call_graph(tmp_path)
    findings = MemoryLeakAnalyzer().analyze(tmp_path, call_graph=cg)
    rule_ids = {f.rule_id for f in findings}
    files = {f.file_path for f in findings}

    assert "safe.py" not in files
    assert {"MEM-PY-001", "MEM-PY-002", "MEM-PY-003", "MEM-PY-004"}.issubset(rule_ids)
    assert {"MEM-JS-001", "MEM-JS-002", "MEM-JS-003", "MEM-JS-004"}.issubset(rule_ids)


def test_python_leaky_app_end_to_end_before_after_heap_and_fd_verification(tmp_path: Path) -> None:
    engine = VulnBoxEngine(backend="local")
    out_dir = tmp_path / "out-py-leaks"
    report, written = engine.remediate(
        FIXTURES / "py_leaky_app",
        deep=True,
        check_leaks=True,
        out_dir=out_dir,
    )

    rule_ids = {f.rule_id for f in report.findings}
    assert "MEM-PY-001" in rule_ids
    assert "MEM-PY-003" in rule_ids
    assert len(report.verifications) >= 2
    assert all(v.verified for v in report.verifications), [v.summary for v in report.verifications]

    # Confirm active before/after heap slope + FD delta verification succeeded!
    by_rule = {
        next(f.rule_id for f in report.findings if f.finding_id == v.finding_id): v
        for v in report.verifications
    }
    cache_ver = by_rule["MEM-PY-001"]
    assert cache_ver.memory_probe_before is not None and cache_ver.memory_probe_before.leak_detected is True
    assert cache_ver.memory_probe_after is not None and cache_ver.memory_probe_after.leak_detected is False
    assert cache_ver.memory_leak_confirmed_and_fixed is True

    fd_ver = by_rule["MEM-PY-003"]
    assert fd_ver.memory_probe_before is not None and fd_ver.memory_probe_before.fd_delta > 5
    assert fd_ver.memory_probe_after is not None and fd_ver.memory_probe_after.fd_delta <= 5
    assert fd_ver.memory_leak_confirmed_and_fixed is True

    # Validate SARIF 2.1.0 output
    validate_sarif(build_sarif(report))
    assert (out_dir / "report.md").is_file()


def test_node_leaky_app_end_to_end_before_after_heap_verification(tmp_path: Path) -> None:
    engine = VulnBoxEngine(backend="local")
    out_dir = tmp_path / "out-node-leaks"
    report, _ = engine.remediate(
        FIXTURES / "node_leaky_app",
        deep=True,
        check_leaks=True,
        out_dir=out_dir,
    )

    rule_ids = {f.rule_id for f in report.findings}
    assert "MEM-JS-001" in rule_ids
    assert "MEM-JS-002" in rule_ids
    assert len(report.verifications) >= 2
    assert all(v.verified for v in report.verifications), [v.summary for v in report.verifications]

    by_rule = {
        next(f.rule_id for f in report.findings if f.finding_id == v.finding_id): v
        for v in report.verifications
    }
    assert by_rule["MEM-JS-001"].memory_leak_confirmed_and_fixed is True
    assert by_rule["MEM-JS-002"].memory_leak_confirmed_and_fixed is True
    validate_sarif(build_sarif(report))


def test_incompatible_memory_profiler_degrades_gracefully_without_breaking_verification() -> None:
    """If no memory profiler is compatible (e.g., unsupported OS/runtime), scan & verify must not break."""
    from vulnbox.analyzers import register_builtin_analyzers
    from vulnbox.callgraph.ts_utils import available_tree_sitter_languages, get_parser_for_ext
    from vulnbox.registry import PluginRegistry, default_registry

    class _IncompatibleProfiler:
        name = "mock-incompatible-profiler"
        priority = 100

        def check_compatibility(self, start_cmd: str, backend_name: str) -> tuple[bool, str]:
            return False, "Simulated unsupported OS (no SIGUSR1 / no /proc)"

        def prepare_sandbox(self, probe_dir, probe_dir_sb, start_cmd, is_docker):
            raise AssertionError("Should never be invoked when incompatible")

    # Build an isolated registry reusing built-in analyzers/patchers/tests/probes,
    # but ONLY registering the incompatible memory profiler.
    reg = PluginRegistry()
    register_builtin_analyzers(reg)
    reg._patchers.update(default_registry._patchers)
    reg._category_patchers.update(default_registry._category_patchers)
    reg._regression_tests.update(default_registry._regression_tests)
    reg._category_regression_tests.update(default_registry._category_regression_tests)
    reg._memory_probes.update(default_registry._memory_probes)
    reg.register_memory_profiler(_IncompatibleProfiler())

    engine = VulnBoxEngine(backend="local", registry=reg)

    # 1. Scan with deep=True + check_leaks=True completes cleanly with skipped=True
    scan_report, _ = engine.scan(FIXTURES / "py_leaky_app", deep=True, check_leaks=True)
    assert len(scan_report.memory_probes) >= 2
    assert all(mp.skipped and mp.skip_reason for mp in scan_report.memory_probes)

    # 2. Remediate with deep=True + check_leaks=True still verifies patches cleanly (no false failure!)
    rem_report, _ = engine.remediate(FIXTURES / "py_leaky_app", deep=True, check_leaks=True)
    assert len(rem_report.verifications) >= 2
    assert all(v.verified for v in rem_report.verifications)
    assert all(v.memory_probe_before is not None and v.memory_probe_before.skipped for v in rem_report.verifications)
    assert all(v.memory_leak_confirmed_and_fixed is None for v in rem_report.verifications)

    # 3. Default registry falls back to language-agnostic os-proc-fallback for non-Python/Node binaries
    selected, _ = default_registry.select_memory_profiler("./my-go-server", "docker")
    assert selected is not None and selected.name == "os-proc-fallback"

    # 4. Tree-sitter utility reports loaded grammars and returns None cleanly for unsupported extensions
    assert "javascript" in available_tree_sitter_languages()
    assert get_parser_for_ext(".unknown_ext") is None

