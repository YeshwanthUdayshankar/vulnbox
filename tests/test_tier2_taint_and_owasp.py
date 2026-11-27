"""Tests for Tier 2: flow-sensitive source->sink taint engine & all 10 OWASP rule families."""

from __future__ import annotations

import sys
from pathlib import Path

from vulnbox.analyzers.node_sast import NodeSASTAnalyzer
from vulnbox.analyzers.python_sast import PythonSASTAnalyzer
from vulnbox.engine import VulnBoxEngine
from vulnbox.remediation.dynamic_probe import infer_probe_for_finding

FIXTURES = Path(__file__).parent / "fixtures"


def test_taint_engine_guard_soundness_reassignment_and_fastapi_depends(tmp_path: Path):
    (tmp_path / "tricky.py").write_text(
        "import os, re, requests\n"
        "from pathlib import Path\n"
        "from fastapi import FastAPI, Depends\n"
        "app = FastAPI()\n"
        "\n"
        "def vulnerable_with_decoy(filename):\n"
        "    other = str(Path('config.ini').resolve())\n"
        "    if other.startswith('/etc/'):\n"
        "        pass\n"
        "    target = os.path.join('/srv/public', filename)\n"
        "    with open(target) as f:\n"
        "        return f.read()\n"
        "\n"
        "def vulnerable_unanchored_re_match(filename):\n"
        "    if re.match(r'[a-z]+', filename):\n"
        "        target = os.path.join('/srv/public', filename)\n"
        "        with open(target) as f:\n"
        "            return f.read()\n"
        "\n"
        "def vulnerable_prefix_without_sep(filename):\n"
        "    target = os.path.join('/srv/data', filename)\n"
        "    if not os.path.realpath(target).startswith('/srv/data'):\n"
        "        raise ValueError('bad')\n"
        "    with open(target) as f:\n"
        "        return f.read()\n"
        "\n"
        "def vulnerable_reassigned_after_sanitize(filename, request):\n"
        "    safe = os.path.basename(filename)\n"
        "    safe = request.args.get('file')\n"
        "    target = os.path.join('/srv/public', safe)\n"
        "    with open(target) as f:\n"
        "        return f.read()\n"
        "\n"
        "def vulnerable_noop_if_guard(filename):\n"
        "    target = os.path.join('/srv/public', filename)\n"
        "    if Path(target).resolve().is_relative_to(Path('/srv/public')):\n"
        "        pass\n"
        "    with open(target) as f:\n"
        "        return f.read()\n"
        "\n"
        "def vulnerable_wildcard_regex(filename):\n"
        "    if re.fullmatch(r'^.*$', filename):\n"
        "        target = os.path.join('/srv/public', filename)\n"
        "        with open(target) as f:\n"
        "            return f.read()\n"
        "\n"
        "def genuinely_safe_abort_guard(filename):\n"
        "    from flask import abort\n"
        "    target = os.path.join('/srv/data', filename)\n"
        "    if not Path(target).resolve().is_relative_to(Path('/srv/data')):\n"
        "        abort(403)\n"
        "    with open(target) as f:\n"
        "        return f.read()\n"
        "\n"
        "def genuinely_safe_basename(filename):\n"
        "    safe_name = os.path.basename(filename)\n"
        "    target = os.path.join('/srv/public', safe_name)\n"
        "    with open(target) as f:\n"
        "        return f.read()\n"
        "\n"
        "def genuinely_safe_sep_guard(filename):\n"
        "    target = os.path.join('/srv/data', filename)\n"
        "    if not os.path.realpath(target).startswith('/srv/data' + os.sep):\n"
        "        raise ValueError('bad')\n"
        "    with open(target) as f:\n"
        "        return f.read()\n"
        "\n"
        "@app.get('/items')\n"
        "def fastapi_depends_not_tainted(cfg=Depends(lambda: 'https://api.internal')):\n"
        "    return requests.get(cfg).text\n"
        "\n"
        "@app.get('/ssrf-blocklist')\n"
        "def ssrf_blocklist_not_allowlist(url: str):\n"
        "    from urllib.parse import urlparse\n"
        "    if urlparse(url).hostname != '169.254.169.254':\n"
        "        return requests.get(url).text\n"
        "\n"
        "@app.get('/ssrf-allowlist-abort')\n"
        "def ssrf_allowlist_abort(url: str):\n"
        "    from urllib.parse import urlparse\n"
        "    from flask import abort\n"
        "    if urlparse(url).hostname not in ('api.example.com',):\n"
        "        abort(403)\n"
        "    return requests.get(url).text\n",
        encoding="utf-8",
    )
    findings = PythonSASTAnalyzer().analyze(tmp_path)
    path_fns = {f.metadata["function"] for f in findings if f.rule_id == "PY-PATH-001"}
    assert "vulnerable_with_decoy" in path_fns
    assert "vulnerable_unanchored_re_match" in path_fns
    assert "vulnerable_prefix_without_sep" in path_fns
    assert "vulnerable_reassigned_after_sanitize" in path_fns
    assert "vulnerable_noop_if_guard" in path_fns
    assert "vulnerable_wildcard_regex" in path_fns
    assert "genuinely_safe_abort_guard" not in path_fns
    assert "genuinely_safe_basename" not in path_fns
    assert "genuinely_safe_sep_guard" not in path_fns
    # FastAPI Depends(...) and allowlist+abort MUST NOT trigger PY-SSRF-001,
    # whereas hostname != '169.254.169.254' blocklist MUST still trigger PY-SSRF-001!
    ssrf_lines = [f.start_line for f in findings if f.rule_id == "PY-SSRF-001"]
    assert len(ssrf_lines) == 1

    # JS AST taint:
    # 1. `if (!p.startsWith('/')) return;` MUST NOT count as path confinement
    # 2. Unresolved `f = base + '/../etc/passwd'` MUST NOT be sanitized by `f.startsWith(base + path.sep)` even if `path.resolve(` appears elsewhere
    # 3. Resolved `r = path.resolve(base, req.query.file)` checked with `r.startsWith(base + path.sep)` IS sanitized inside branch
    # 4. `if (u.startsWith('/') || u.startsWith('//'))` and `if (u.startsWith('/') && !u.startsWith('//'))` (missing `/\`) MUST stay flagged as JS-REDIR-001
    # 5. Full `u.startsWith('/') && !u.startsWith('//') && !u.startsWith('/\\')` and negated `||` early-exit ARE safe!
    from vulnbox.analyzers.taint import JsTaintTracker
    from vulnbox.callgraph.ts_utils import parse_source, walk_nodes

    js_src = (
        "const path = require('path');\n"
        "function handler(req, res) {\n"
        "  const p = path.resolve('/srv/data', req.query.file);\n"
        "  if (!p.startsWith('/')) return;\n"
        "  const badTarget = p;\n"
        "  const f = '/srv/data/' + req.query.file;\n"
        "  if (f.startsWith('/srv/data' + path.sep)) {\n"
        "    const unresolvedTarget = f;\n"
        "  }\n"
        "  const prom = resolve('/srv/data/' + req.query.file);\n"
        "  if (prom.startsWith('/srv/data' + path.sep)) {\n"
        "    const promiseResolveTarget = prom;\n"
        "  }\n"
        "  if (p.startsWith('/srv/data' + path.sep)) {\n"
        "    const safeTarget = p;\n"
        "  }\n"
        "  const u1 = req.query.u1;\n"
        "  if (u1.startsWith('/') || u1.startsWith('//')) { res.redirect(u1); }\n"
        "  const u2 = req.query.u2;\n"
        "  if (u2.startsWith('/') && !u2.startsWith('//')) { res.redirect(u2); }\n"
        "  const u3 = req.query.u3;\n"
        "  if (u3.startsWith('/') && !u3.startsWith('//') && !u3.startsWith('/\\\\')) { res.redirect(u3); }\n"
        "}\n"
        "function earlyExitHandler(req, res) {\n"
        "  const u4 = req.query.next;\n"
        "  if (!u4.startsWith('/') || u4.startsWith('//') || u4.startsWith('/\\\\')) return;\n"
        "  res.redirect(u4);\n"
        "}\n"
    )
    tree, raw = parse_source(js_src, ".js")
    assert tree is not None
    tracker = JsTaintTracker(tree.root_node, raw)

    def _rhs(var_name: bytes):
        return [
            n.child_by_field_name("value")
            for n in walk_nodes(tree.root_node)
            if n.type == "variable_declarator"
            and n.child_by_field_name("name") is not None
            and raw[n.child_by_field_name("name").start_byte : n.child_by_field_name("name").end_byte] == var_name
        ][0]

    assert tracker.is_tainted(_rhs(b"badTarget"), "path") is not None
    assert tracker.is_tainted(_rhs(b"unresolvedTarget"), "path") is not None
    assert tracker.is_tainted(_rhs(b"promiseResolveTarget"), "path") is not None
    assert tracker.is_tainted(_rhs(b"safeTarget"), "path") is None

    (tmp_path / "js_redir.js").write_text(js_src, encoding="utf-8")
    js_redirs = [f for f in NodeSASTAnalyzer().analyze(tmp_path) if f.rule_id == "JS-REDIR-001"]
    # Only u1 (`||`) and u2 (missing `/\`) should fire; u3 and u4 are properly guarded!
    assert len(js_redirs) == 2


def test_python_xxe_lxml_high_vs_stdlib_low_and_ast_defusedxml(tmp_path: Path):
    (tmp_path / "lxml_vuln.py").write_text(
        "from lxml import etree\n"
        "def parse_untrusted(xml_bytes):\n"
        "    return etree.fromstring(xml_bytes)\n"
        "def parse_safe(xml_bytes):\n"
        "    safe_parser = etree.XMLParser(resolve_entities=False, no_network=True)\n"
        "    return etree.fromstring(xml_bytes, parser=safe_parser)\n",
        encoding="utf-8",
    )
    (tmp_path / "stdlib_vs_defused.py").write_text(
        "# comment mentioning defusedxml should NOT disable stdlib detection\n"
        "import xml.etree.ElementTree as ET\n"
        "def parse_stdlib(xml_bytes):\n"
        "    return ET.fromstring(xml_bytes)\n",
        encoding="utf-8",
    )
    (tmp_path / "real_defused.py").write_text(
        "import defusedxml.ElementTree as ET\n"
        "def parse_ok(xml_bytes):\n"
        "    return ET.fromstring(xml_bytes)\n",
        encoding="utf-8",
    )
    findings = [f for f in PythonSASTAnalyzer().analyze(tmp_path) if f.rule_id == "PY-XXE-001"]
    by_file = {f.file_path: f for f in findings}
    assert "lxml_vuln.py" in by_file
    assert by_file["lxml_vuln.py"].severity == "high"
    assert by_file["lxml_vuln.py"].cwe_id == "CWE-611"
    # parse_safe inside lxml_vuln.py must NOT be flagged (only 1 finding in lxml_vuln.py)
    assert len([f for f in findings if f.file_path == "lxml_vuln.py"]) == 1

    assert "stdlib_vs_defused.py" in by_file
    assert by_file["stdlib_vs_defused.py"].severity == "low"
    assert by_file["stdlib_vs_defused.py"].cwe_id == "CWE-776"
    assert "real_defused.py" not in by_file

    # When lockfile pins lxml >= 5.0, default parser drops to low, while explicit resolve_entities=True stays high!
    lxml5_dir = tmp_path / "lxml5_app"
    lxml5_dir.mkdir()
    (lxml5_dir / "uv.lock").write_text('[[package]]\nname = "lxml"\nversion = "5.3.0"\n', encoding="utf-8")
    (lxml5_dir / "xml_app.py").write_text(
        "from lxml import etree\n"
        "def default_p(data):\n    return etree.fromstring(data)\n"
        "def explicit_xxe(data):\n    p = etree.XMLParser(resolve_entities=True)\n    return etree.fromstring(data, parser=p)\n",
        encoding="utf-8",
    )
    lxml5_xxe = [f for f in PythonSASTAnalyzer().analyze(lxml5_dir) if f.rule_id == "PY-XXE-001"]
    sevs = sorted(f.severity for f in lxml5_xxe)
    assert "high" in sevs and "low" in sevs


def test_python_owasp_rule_families_detection_and_negative_guards(tmp_path: Path):
    (tmp_path / "vuln_web.py").write_text(
        "import random\n"
        "import requests\n"
        "import jwt\n"
        "from lxml import etree\n"
        "from flask import Flask, request, redirect, render_template_string\n"
        "\n"
        "app = Flask(__name__)\n"
        "app.secret_key = 'super-hardcoded-flask-prod-key'\n"
        "\n"
        "@app.route('/ssrf')\n"
        "def ssrf_route():\n"
        "    target = request.args.get('url')\n"
        "    return requests.get(target).text\n"
        "\n"
        "@app.route('/ssti')\n"
        "def ssti_route():\n"
        "    name = request.args.get('name')\n"
        "    return render_template_string('Hello ' + name)\n"
        "\n"
        "@app.route('/xxe')\n"
        "def xxe_route():\n"
        "    return str(etree.fromstring(request.data))\n"
        "\n"
        "def decode_bad_jwt(tok):\n"
        "    return jwt.decode(tok, options={'verify_signature': False})\n"
        "\n"
        "def generate_reset_token():\n"
        "    return ''.join(random.choice('abcdef012345') for _ in range(16))\n"
        "\n"
        "@app.route('/nosql')\n"
        "def nosql_route(users_col):\n"
        "    payload = request.get_json()\n"
        "    return users_col.find_one(payload)\n"
        "\n"
        "@app.route('/go')\n"
        "def open_redir():\n"
        "    nxt = request.args.get('next')\n"
        "    return redirect(nxt)\n"
        "\n"
        "@app.route('/bypass-go')\n"
        "def proto_rel_bypass_redir():\n"
        "    nxt = request.args.get('next')\n"
        "    if nxt.startswith('/'):\n"
        "        return redirect(nxt)\n"
        "    return redirect('/')\n"
        "\n"
        "@app.route('/bypass-backslash')\n"
        "def backslash_bypass_redir():\n"
        "    nxt = request.args.get('next')\n"
        "    if nxt.startswith('/') and not nxt.startswith('//'):\n"
        "        return redirect(nxt)\n"
        "    return redirect('/')\n"
        "\n"
        "@app.route('/bypass-wrong-idx')\n"
        "def wrong_idx_bypass_redir():\n"
        "    nxt = request.args.get('next')\n"
        "    if nxt.startswith('/') and nxt[0] != 'a':\n"
        "        return redirect(nxt)\n"
        "    return redirect('/')\n"
        "\n"
        "@app.route('/safe-go')\n"
        "def safe_redir():\n"
        "    nxt = request.args.get('next')\n"
        "    if nxt.startswith('/') and not nxt.startswith(('//', '/\\\\')):\n"
        "        return redirect(nxt)\n"
        "    return redirect('/')\n"
        "\n"
        "@app.route('/safe-go-idx1')\n"
        "def safe_redir_idx1():\n"
        "    nxt = request.args.get('next')\n"
        "    if nxt.startswith('/') and nxt[1] not in ('/', '\\\\'):\n"
        "        return redirect(nxt)\n"
        "    return redirect('/')\n",
        encoding="utf-8",
    )

    findings = PythonSASTAnalyzer().analyze(tmp_path)
    rule_ids = {f.rule_id for f in findings}
    for expected in (
        "PY-SECRET-001",
        "PY-SSRF-001",
        "PY-SSTI-001",
        "PY-XXE-001",
        "PY-JWT-001",
        "PY-RAND-001",
        "PY-NOSQL-001",
        "PY-REDIR-001",
    ):
        assert expected in rule_ids, f"Missing expected rule {expected}; got {rule_ids}"

    # open_redir, proto_rel_bypass_redir, backslash_bypass_redir, and wrong_idx_bypass_redir ALL fire (4),
    # while safe_redir (rejects both // and /\) and safe_redir_idx1 (index 1 != / or \) do NOT!
    redir_lines = [f.start_line for f in findings if f.rule_id == "PY-REDIR-001"]
    assert len(redir_lines) == 4


def test_node_owasp_rule_families_detection(tmp_path: Path):
    (tmp_path / "server.js").write_text(
        "import jwt from 'jsonwebtoken';\n"
        "import session from 'express-session';\n"
        "\n"
        "app.use(session({ secret: 'hardcoded-express-secret-123' }));\n"
        "\n"
        "app.get('/fetch', async (req, res) => {\n"
        "  const { url } = req.query;\n"
        "  const r = await fetch(url);\n"
        "  res.send(`<div>${req.query.msg}</div>`);\n"
        "});\n"
        "\n"
        "app.post('/login', async (req, res) => {\n"
        "  const user = await Users.findOne(req.body);\n"
        "  const claims = jwt.decode(req.headers.authorization);\n"
        "  const resetToken = Math.random().toString(36).slice(2);\n"
        "  res.redirect(req.query.next);\n"
        "});\n"
        "\n"
        "function renderBad(el, input) {\n"
        "  el.innerHTML = input;\n"
        "}\n"
        "\n"
        "function mergeUnsafe(target, key, sub, val) {\n"
        "  target[key][sub] = val;\n"
        "}\n",
        encoding="utf-8",
    )
    findings = NodeSASTAnalyzer().analyze(tmp_path)
    rule_ids = {f.rule_id for f in findings}
    for expected in (
        "JS-SECRET-001",
        "JS-SSRF-001",
        "JS-XSS-001",
        "JS-NOSQL-001",
        "JS-JWT-001",
        "JS-RAND-001",
        "JS-REDIR-001",
        "JS-PROTO-001",
    ):
        assert expected in rule_ids, f"Missing expected rule {expected}; got {rule_ids}"


def test_static_ssrf_finding_infers_and_runs_live_ssrf_canary_probe():
    integrated = FIXTURES / "py_integrated_app"
    findings = PythonSASTAnalyzer().analyze(integrated)
    ssrf = next((f for f in findings if f.rule_id == "PY-SSRF-001"), None)
    assert ssrf is not None

    spec = infer_probe_for_finding(ssrf, integrated)
    assert spec is not None
    assert "169.254.169.254" in spec.path

    res = VulnBoxEngine(backend="local").probe(
        integrated,
        specs=[spec],
        start_cmd=f"{sys.executable} app.py",
        mock_integrations=True,
    )[0]
    assert res.status_code == 200
    assert res.matched_vulnerable is True
    assert any("169.254.169.254" in c.host for c in res.outbound_calls)
