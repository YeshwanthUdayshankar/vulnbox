"""Tests for Tier 2: intra-procedural source->sink taint engine & all 10 new OWASP rule families."""

from __future__ import annotations

import sys
from pathlib import Path

from vulnbox.analyzers.node_sast import NodeSASTAnalyzer
from vulnbox.analyzers.python_sast import PythonSASTAnalyzer
from vulnbox.engine import VulnBoxEngine
from vulnbox.remediation.dynamic_probe import infer_probe_for_finding

FIXTURES = Path(__file__).parent / "fixtures"


def test_taint_engine_distinguishes_real_sanitizer_from_unrelated_resolve(tmp_path: Path):
    # An unrelated `Path("x").resolve()` and `foo.startswith("a")` must NOT mask a real PY-PATH-001!
    (tmp_path / "tricky.py").write_text(
        "import os\n"
        "from pathlib import Path\n"
        "def vulnerable_with_decoy(filename):\n"
        "    other = str(Path('config.ini').resolve())\n"
        "    if other.startswith('/etc'):\n"
        "        pass\n"
        "    target = os.path.join('/srv/public', filename)\n"
        "    with open(target) as f:\n"
        "        return f.read()\n"
        "\n"
        "def genuinely_safe(filename):\n"
        "    safe_name = os.path.basename(filename)\n"
        "    target = os.path.join('/srv/public', safe_name)\n"
        "    with open(target) as f:\n"
        "        return f.read()\n",
        encoding="utf-8",
    )
    findings = [f for f in PythonSASTAnalyzer().analyze(tmp_path) if f.rule_id == "PY-PATH-001"]
    fns = {f.metadata["function"] for f in findings}
    assert "vulnerable_with_decoy" in fns
    assert "genuinely_safe" not in fns


def test_python_owasp_rule_families_detection_and_negative_guards(tmp_path: Path):
    (tmp_path / "vuln_web.py").write_text(
        "import random\n"
        "import requests\n"
        "import jwt\n"
        "import xml.etree.ElementTree as ET\n"
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
        "    return str(ET.fromstring(request.data))\n"
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
        "@app.route('/safe-go')\n"
        "def safe_redir():\n"
        "    nxt = request.args.get('next')\n"
        "    if nxt.startswith('/'):\n"
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

    # Verify safe_redir did NOT trigger PY-REDIR-001
    redir_lines = [f.start_line for f in findings if f.rule_id == "PY-REDIR-001"]
    assert len(redir_lines) == 1


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
