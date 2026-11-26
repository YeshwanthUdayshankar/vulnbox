"""Precision regression tests distilled from real-world popular open-source benchmarks."""

from __future__ import annotations

from pathlib import Path

from vulnbox.analyzers.memory_leaks import MemoryLeakAnalyzer
from vulnbox.analyzers.node_sast import NodeSASTAnalyzer
from vulnbox.analyzers.python_sast import PythonSASTAnalyzer


def test_node_sast_skips_minified_bundles_and_regexp_exec(tmp_path: Path):
    (tmp_path / "socket.io.min.js").write_text(
        'var n=/^test/;var a=n.exec(t||"");\n',
        encoding="utf-8",
    )
    (tmp_path / "parser.js").write_text(
        'const pattern = /^foo/;\nfunction run(t) { return pattern.exec(t + "bar"); }\n',
        encoding="utf-8",
    )
    findings = NodeSASTAnalyzer().analyze(tmp_path)
    assert [f for f in findings if f.rule_id == "JS-CMD-001"] == []


def test_memory_leaks_respects_open_followed_by_with_and_browser_ready_interval(tmp_path: Path):
    (tmp_path / "loader.py").write_text(
        "def load(p):\n"
        "    try:\n"
        "        f = open(p, 'rb')\n"
        "    except FileNotFoundError:\n"
        "        return None\n"
        "    with f:\n"
        "        return f.read()\n",
        encoding="utf-8",
    )
    static_dir = tmp_path / "app" / "static" / "js"
    static_dir.mkdir(parents=True)
    (static_dir / "clock.js").write_text(
        "$(document).ready(function () {\n"
        "  setInterval(() => { console.log('tick'); }, 1000);\n"
        "});\n",
        encoding="utf-8",
    )
    findings = MemoryLeakAnalyzer().analyze(tmp_path)
    assert [f for f in findings if f.rule_id in ("MEM-PY-003", "MEM-JS-003")] == []


def test_python_sast_skips_regex_guarded_path_join_and_setup_py_and_triages_checksum_md5(tmp_path: Path):
    (tmp_path / "setup.py").write_text(
        "import os\ndef read(name):\n    with open(os.path.join('.', name)) as f:\n        return f.read()\n",
        encoding="utf-8",
    )
    (tmp_path / "safe_cfg.py").write_text(
        "import os, re, hashlib\n"
        "CONFIG_FILE = 'settings.json'\n"
        "def load_cfg(base, name):\n"
        "    if re.fullmatch(r'[A-Za-z0-9_-]+', name):\n"
        "        with open(os.path.join(base, f'{name}.json')) as f:\n"
        "            return f.read()\n"
        "def load_const(base):\n"
        "    with open(os.path.join(base, CONFIG_FILE)) as f:\n"
        "        return f.read()\n"
        "def make_etag(body):\n"
        "    etag_hash = hashlib.md5(body).hexdigest()\n"
        "    return etag_hash\n",
        encoding="utf-8",
    )
    findings = PythonSASTAnalyzer().analyze(tmp_path)
    assert [f for f in findings if f.rule_id == "PY-PATH-001"] == []
    md5_findings = [f for f in findings if f.rule_id == "PY-HASH-001"]
    assert len(md5_findings) == 1
    assert md5_findings[0].severity == "low"
