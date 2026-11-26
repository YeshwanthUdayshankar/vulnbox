"""Tests for Phases 2, 3, and 4: format-preserving scrubbing, expected-shape HTTP mocks,
SSRF canary, Redis/SMTP shims, HS256 test-JWT auth, and in-process probing."""

from __future__ import annotations

import shutil
import smtplib
import socket
import sys
from pathlib import Path

import pytest

from vulnbox.engine import VulnBoxEngine
from vulnbox.models import DynamicProbeSpec, MockRule, ProbeExpectation
from vulnbox.remediation._service_shims import TinyRedisShim, TinySmtpShim
from vulnbox.remediation.auth_helper import mint_hs256_jwt, resolve_auth_headers
from vulnbox.remediation.dynamic_probe import run_dynamic_probe, run_inprocess_probe
from vulnbox.remediation.mock_inferrer import infer_mock_rules
from vulnbox.sandbox.local_backend import LocalSandboxBackend
from vulnbox.scrubber import cleanup_workspace, create_scrubbed_workspace, parse_workspace_env_vars

FIXTURES = Path(__file__).parent / "fixtures"
INTEGRATED_APP = FIXTURES / "py_integrated_app"


def test_format_preserving_scrubber_preserves_syntax_and_markers():
    scrub = create_scrubbed_workspace(INTEGRATED_APP)
    ws = Path(scrub.sandbox_dir)
    try:
        env_text = (ws / ".env").read_text(encoding="utf-8")
        assert "super_real_db_secret" not in env_text
        assert "real_redis_secret" not in env_text
        assert "real_prod_jwt_signing_key_never_expose" not in env_text

        env_vars = parse_workspace_env_vars(ws)
        assert env_vars["DATABASE_URL"].startswith("postgresql://vulnbox:REDACTED_BY_VULNBOX_DATABASE_URL@127.0.0.1:5432/")
        assert env_vars["REDIS_URL"].startswith("redis://:REDACTED_BY_VULNBOX_REDIS_URL@127.0.0.1:6379/")
        assert env_vars["STRIPE_API_URL"].startswith("http://127.0.0.1:18080/mock/REDACTED_BY_VULNBOX_STRIPE_API_URL")
        assert "REDACTED_BY_VULNBOX_JWT_SECRET" in env_vars["JWT_SECRET"]
        assert len(env_vars["JWT_SECRET"]) >= 32
    finally:
        cleanup_workspace(ws)


def test_expected_shape_mock_inference_python_and_js(tmp_path: Path):
    rules = infer_mock_rules(INTEGRATED_APP)
    stripe_rule = next((r for r in rules if r.host_pattern == "api.stripe.com"), None)
    assert stripe_rule is not None
    assert stripe_rule.status == 200
    assert stripe_rule.json_body is not None
    assert "id" in stripe_rule.json_body
    assert stripe_rule.json_body["charge_status"] == "succeeded"
    assert isinstance(stripe_rule.json_body["amount"], int)

    # Also verify JS destructuring & property access inference
    js_repo = tmp_path / "js_api"
    js_repo.mkdir()
    (js_repo / "client.mjs").write_text(
        """
        async function fetchOrder() {
          const res = await fetch("https://api.example.org/v2/orders");
          const { order_id, is_paid, total_amount } = await res.json();
          return { order_id, is_paid, total_amount };
        }
        """,
        encoding="utf-8",
    )
    js_rules = infer_mock_rules(js_repo)
    ex_rule = next((r for r in js_rules if r.host_pattern == "api.example.org"), None)
    assert ex_rule is not None
    assert ex_rule.json_body is not None
    assert "order_id" in ex_rule.json_body
    assert ex_rule.json_body["is_paid"] is True
    assert isinstance(ex_rule.json_body["total_amount"], int)


def test_live_python_https_mock_ssrf_canary_redis_shim_and_jwt_auth():
    engine = VulnBoxEngine(backend="local")

    # 1. Expected-shape HTTP 200 auto-mock for https://api.stripe.com/v1/charges (zero manual mocks!)
    checkout_spec = DynamicProbeSpec(
        probe_id="probe-stripe-checkout",
        method="POST",
        path="/checkout",
        vulnerable_expectation=ProbeExpectation(
            status_codes=[200],
            body_contains=["succeeded"],
            outbound_hosts_contain=["api.stripe.com"],
        ),
        fixed_expectation=ProbeExpectation(status_codes=[400]),
    )

    # 2. Zero-container RESP2 Redis shim
    redis_spec = DynamicProbeSpec(
        probe_id="probe-redis-shim",
        method="GET",
        path="/cache",
        vulnerable_expectation=ProbeExpectation(status_codes=[200], body_contains=["hello"]),
        fixed_expectation=ProbeExpectation(status_codes=[500]),
    )

    # 3. Auto-minted HS256 test-JWT verified against format-preserving scrubbed .env JWT_SECRET
    admin_spec = DynamicProbeSpec(
        probe_id="probe-admin-jwt",
        method="GET",
        path="/admin",
        vulnerable_expectation=ProbeExpectation(status_codes=[200], body_contains=["tester", "admin"]),
        fixed_expectation=ProbeExpectation(status_codes=[401]),
    )

    # 4. SSRF Canary capturing 169.254.169.254 inside air-gapped sandbox!
    ssrf_spec = DynamicProbeSpec(
        probe_id="probe-ssrf-canary",
        method="GET",
        path="/fetch?url=http://169.254.169.254/latest/meta-data/",
        vulnerable_expectation=ProbeExpectation(
            status_codes=[200],
            outbound_hosts_contain=["169.254.169.254"],
        ),
        fixed_expectation=ProbeExpectation(
            status_codes=[400, 403],
            outbound_hosts_not_contain=["169.254.169.254"],
        ),
    )

    results = engine.probe(
        INTEGRATED_APP,
        specs=[checkout_spec, redis_spec, admin_spec, ssrf_spec],
        start_cmd=f"{sys.executable} app.py",
        mock_integrations=True,
        auth_jwt_claims={"sub": "tester", "role": "admin"},
    )
    assert len(results) == 4

    r_checkout, r_redis, r_admin, r_ssrf = results
    assert r_checkout.status_code == 200 and r_checkout.matched_vulnerable is True
    assert any("api.stripe.com" in c.host for c in r_checkout.outbound_calls)

    assert r_redis.status_code == 200 and r_redis.matched_vulnerable is True
    assert '"hello"' in r_redis.response_body_excerpt

    assert r_admin.status_code == 200 and r_admin.matched_vulnerable is True
    assert '"admin"' in r_admin.response_body_excerpt

    assert r_ssrf.status_code == 200 and r_ssrf.matched_vulnerable is True
    assert any("169.254.169.254" in c.host for c in r_ssrf.outbound_calls)


def test_explicit_user_mock_override_and_strict_mode():
    engine = VulnBoxEngine(backend="local")
    custom_rule = MockRule(
        host_pattern="api.stripe.com",
        path_prefix="/v1/charges",
        status=200,
        json_body={"id": "ch_custom_999", "charge_status": "custom_override", "amount": 4242},
        source="user",
    )
    spec = DynamicProbeSpec(
        probe_id="probe-custom-mock",
        method="POST",
        path="/checkout",
        vulnerable_expectation=ProbeExpectation(
            status_codes=[200], body_contains=["ch_custom_999", "custom_override", "4242"]
        ),
        fixed_expectation=ProbeExpectation(status_codes=[400]),
    )
    res = engine.probe(
        INTEGRATED_APP,
        specs=[spec],
        start_cmd=f"{sys.executable} app.py",
        mock_integrations=True,
        mock_rules=[custom_rule],
        mocks_strict=True,
    )[0]
    assert res.status_code == 200
    assert res.matched_vulnerable is True


@pytest.mark.skipif(shutil.which("node") is None, reason="Node.js not available")
def test_node_fetch_https_interception_and_expected_shape(tmp_path: Path):
    repo = tmp_path / "node_integrated"
    repo.mkdir()
    (repo / "server.mjs").write_text(
        """
        import http from 'node:http';
        const port = Number(process.env.PORT || 8099);
        const srv = http.createServer(async (req, res) => {
          if (req.url === '/health') {
            res.writeHead(200, {'Content-Type': 'application/json'});
            res.end(JSON.stringify({ ok: true }));
            return;
          }
          if (req.url === '/ext') {
            const r = await fetch('https://api.github.com/user');
            const { login, is_verified } = await r.json();
            res.writeHead(200, {'Content-Type': 'application/json'});
            res.end(JSON.stringify({ login, is_verified }));
            return;
          }
          res.writeHead(404);
          res.end();
        });
        srv.listen(port, '127.0.0.1');
        """,
        encoding="utf-8",
    )
    spec = DynamicProbeSpec(
        probe_id="probe-node-fetch-mock",
        method="GET",
        path="/ext",
        vulnerable_expectation=ProbeExpectation(
            status_codes=[200],
            body_contains=["vb_mock_login", "true"],
            outbound_hosts_contain=["api.github.com"],
        ),
        fixed_expectation=ProbeExpectation(status_codes=[500]),
    )
    res = run_dynamic_probe(
        repo,
        backend=LocalSandboxBackend(),
        start_cmd="node server.mjs",
        spec=spec,
        mock_integrations=True,
    )
    assert res.status_code == 200
    assert res.matched_vulnerable is True
    assert any("api.github.com" in c.host for c in res.outbound_calls)


def test_redis_and_smtp_service_shims_directly():
    redis = TinyRedisShim(port=0)
    rport = redis.start()
    smtp = TinySmtpShim(port=0)
    sport = smtp.start()
    try:
        with socket.create_connection(("127.0.0.1", rport), timeout=2) as s:
            s.sendall(b"*1\r\n$4\r\nPING\r\n")
            assert b"+PONG" in s.recv(128)
            s.sendall(b"*3\r\n$3\r\nSET\r\n$1\r\nk\r\n$3\r\nval\r\n")
            assert b"+OK" in s.recv(128)
            s.sendall(b"*2\r\n$3\r\nGET\r\n$1\r\nk\r\n")
            assert b"$3\r\nval\r\n" in s.recv(128)

        with smtplib.SMTP("127.0.0.1", sport, timeout=2) as client:
            client.sendmail("a@vulnbox.invalid", ["b@vulnbox.invalid"], "Subject: hi\r\n\r\nbody")
        assert smtp.received_count == 1
    finally:
        redis.stop()
        smtp.stop()


def test_auth_helper_mints_valid_hs256_jwt():
    token = mint_hs256_jwt({"sub": "alice", "role": "auditor"}, secret="test_secret_1234567890")
    assert len(token.split(".")) == 3
    headers = resolve_auth_headers(auth_header="X-Custom: ok", auth_jwt_claims='{"sub":"bob"}')
    assert headers["X-Custom"] == "ok"
    assert headers["Authorization"].startswith("Bearer ")


def test_inprocess_probe_worker_with_mock_flask_style_app(tmp_path: Path):
    # Create a tiny zero-dependency Flask-like fake module in workspace so the test runs
    # reliably even without Flask/FastAPI installed in the test venv!
    repo = tmp_path / "fake_flask_repo"
    repo.mkdir()
    pkg = repo / "flask"
    pkg.mkdir()
    (pkg / "__init__.py").write_text(
        """
class _Resp:
    def __init__(self, status_code, body):
        self.status_code = status_code
        self.headers = {"Content-Type": "application/json"}
        self._body = body
    def get_data(self, as_text=False):
        return self._body if as_text else self._body.encode("utf-8")

class _Client:
    def __init__(self, routes):
        self._routes = routes
    def open(self, path, method="GET", headers=None, data=None):
        fn = self._routes.get(path)
        if fn is None:
            return _Resp(404, '{"error":"not_found"}')
        return _Resp(200, fn())

class Flask:
    def __init__(self, name):
        self._routes = {}
    def route(self, path):
        def deco(fn):
            self._routes[path] = fn
            return fn
        return deco
    def test_client(self):
        return _Client(self._routes)
        """,
        encoding="utf-8",
    )
    (repo / "app.py").write_text(
        """
import json
import urllib.request
from flask import Flask

app = Flask(__name__)

@app.route("/billing")
def billing():
    with urllib.request.urlopen("https://api.billing.example/v1/status", timeout=2) as r:
        data = json.loads(r.read().decode("utf-8"))
    return json.dumps({"billing_state": data["billing_state"]})
        """,
        encoding="utf-8",
    )

    spec = DynamicProbeSpec(
        probe_id="probe-inprocess-flask",
        method="GET",
        path="/billing",
        vulnerable_expectation=ProbeExpectation(
            status_codes=[200],
            body_contains=['"billing_state": "ok"'],
            outbound_hosts_contain=["api.billing.example"],
        ),
        fixed_expectation=ProbeExpectation(status_codes=[400]),
    )
    res = run_inprocess_probe(repo, backend=LocalSandboxBackend(), spec=spec, mock_integrations=True)
    assert res.probe_mode == "in_process"
    assert res.status_code == 200
    assert res.matched_vulnerable is True
    assert any("api.billing.example" in c.host for c in res.outbound_calls)
