"""Static expected-shape HTTP mock inference for air-gapped sandbox probing.

Scans Python (AST) and JavaScript/TypeScript source files to discover outbound HTTP
endpoints and the exact JSON keys the target code reads from responses (e.g.
`resp.json()["charge_status"]`, `data.get("items")`, `const { id, paid } = await res.json()`).
Synthesizes HTTP 200 OK `MockRule` payloads matching the expected schema so apps
dependent on external APIs (Stripe, Auth0, Slack, GitHub, internal microservices)
can run end-to-end inside `--network=none` sandboxes with zero hand-written mocks.
"""

from __future__ import annotations

import ast
import json
import os
import re
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from vulnbox.models import MockRule

SKIP_DIRS = {
    ".git",
    ".venv",
    "venv",
    "node_modules",
    "__pycache__",
    ".pytest_cache",
    ".ruff_cache",
    "dist",
    "build",
    "tests",
    "test",
    "__tests__",
    "vulnbox-out",
}

_HTTP_CALL_NAMES = {
    "get",
    "post",
    "put",
    "patch",
    "delete",
    "request",
    "urlopen",
    "send",
    "fetch",
}

_URL_LITERAL_RE = re.compile(r"""['"](https?://[A-Za-z0-9._:-]+(?:/[^\s'"`{}<>]*)?)['"]""")
_JS_DESTRUCTURE_RE = re.compile(
    r"""(?:const|let|var)\s*\{\s*([^}]+)\s*\}\s*=\s*(?:await\s+)?([A-Za-z_$][A-Za-z0-9_$.]*)\s*(?:\.json\(\)|\.data\b)?"""
)
_JS_JSON_ASSIGN_RE = re.compile(
    r"""(?:const|let|var)\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*(?:await\s+)?(?:[A-Za-z_$][A-Za-z0-9_$.]*\.json\(\)|JSON\.parse\([^)]*\)|(?:await\s+)?axios\.[a-z]+\([^)]*\))"""
)
_JS_PROP_READ_RE = re.compile(r"""\b([A-Za-z_$][A-Za-z0-9_$]*)(?:\.data)?\.([A-Za-z_$][A-Za-z0-9_$]*)""")
_JS_BRACKET_READ_RE = re.compile(r"""\b([A-Za-z_$][A-Za-z0-9_$]*)\s*\[\s*['"]([A-Za-z0-9_.-]+)['"]\s*\]""")
_JS_SKIP_PROPS = {
    "length",
    "map",
    "filter",
    "forEach",
    "reduce",
    "find",
    "some",
    "every",
    "includes",
    "push",
    "pop",
    "slice",
    "join",
    "split",
    "trim",
    "toLowerCase",
    "toUpperCase",
    "toString",
    "then",
    "catch",
    "finally",
    "json",
    "text",
    "ok",
    "status",
    "headers",
    "data",
}


def load_mock_rules(mock_path: Path) -> list[MockRule]:
    """Load explicit user-defined mock rules from a JSON file (`--mocks mocks.json`)."""
    raw: Any = json.loads(mock_path.read_text(encoding="utf-8"))
    if isinstance(raw, dict) and "rules" in raw:
        items = raw["rules"]
    elif isinstance(raw, list):
        items = raw
    else:
        items = [raw]
    rules: list[MockRule] = []
    for item in items:
        rule = MockRule.model_validate(item)
        rule.source = "user"
        rules.append(rule)
    return rules


def synthesize_value_for_key(key: str, type_hint: str | None = None) -> Any:
    """Synthesize a sensible typed dummy value for an inferred JSON response key."""
    low = key.lower()

    if type_hint == "bool" or low in (
        "ok",
        "success",
        "valid",
        "verified",
        "active",
        "enabled",
        "paid",
        "allowed",
        "authenticated",
        "authorized",
    ) or low.startswith(("is_", "has_", "can_")):
        return True

    if type_hint == "list" or low in (
        "items",
        "results",
        "records",
        "entries",
        "events",
        "charges",
        "users",
        "keys",
    ) or low.endswith(("_list", "_items")):
        return [{"id": "vb_mock_1", "name": "vulnbox_mock", "status": "ok"}]

    if low in ("roles", "scopes", "permissions", "tags") or low.endswith("_ids"):
        return ["vb_mock_1"]

    if type_hint == "float" or low.endswith(("_rate", "_score", "_ratio")):
        return 1.0

    if type_hint == "int" or low in (
        "amount",
        "total",
        "count",
        "expires_in",
        "balance",
        "price",
        "quantity",
        "age",
        "limit",
        "offset",
    ) or low.endswith(("_count", "_total", "_amount", "_ms", "_sec", "_seconds", "_at")):
        return 1700000000 if low.endswith("_at") else 100

    if type_hint == "dict" or low in (
        "user",
        "customer",
        "account",
        "metadata",
        "profile",
        "config",
        "settings",
        "result",
    ):
        return {"id": "vb_mock_1", "status": "ok", "email": "mock@vulnbox.invalid"}

    if low == "error":
        return None
    if "email" in low:
        return "mock@vulnbox.invalid"
    if any(tok in low for tok in ("url", "uri", "href", "endpoint")):
        return "http://127.0.0.1:18080/mock"
    if any(tok in low for tok in ("token", "jwt", "secret")):
        return "vb_mock_token_0123456789abcdef"
    if low == "currency":
        return "usd"
    if "charge_status" in low or "payment_status" in low:
        return "succeeded"
    if "status" in low or "state" in low:
        return "ok"
    if low == "id" or low.endswith("_id"):
        return "vb_mock_id_1"
    if low == "name" or low.endswith("_name"):
        return "vulnbox_mock"
    return f"vb_mock_{key}"


def _extract_url_from_ast(node: ast.AST) -> tuple[str, str] | None:
    """Extract (host, path_prefix) from a string literal or JoinedStr URL expression."""
    raw_url: str | None = None
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        raw_url = node.value
    elif isinstance(node, ast.JoinedStr) and node.values:
        first = node.values[0]
        if isinstance(first, ast.Constant) and isinstance(first.value, str):
            raw_url = first.value
    if not raw_url or not raw_url.startswith(("http://", "https://")):
        return None
    parsed = urlparse(raw_url)
    host = (parsed.hostname or "").lower()
    if not host or host in ("127.0.0.1", "localhost", "::1"):
        return None
    path = parsed.path or "/"
    return host, path


def _type_hint_from_default(node: ast.AST | None) -> str | None:
    if node is None:
        return None
    if isinstance(node, ast.Constant):
        if isinstance(node.value, bool):
            return "bool"
        if isinstance(node.value, int):
            return "int"
        if isinstance(node.value, float):
            return "float"
        if isinstance(node.value, str):
            return "str"
    if isinstance(node, (ast.List, ast.Tuple)):
        return "list"
    if isinstance(node, ast.Dict):
        return "dict"
    return None


def _is_http_call(call: ast.Call) -> bool:
    func = call.func
    if isinstance(func, ast.Name) and func.id in _HTTP_CALL_NAMES:
        return True
    if isinstance(func, ast.Attribute) and func.attr in _HTTP_CALL_NAMES:
        return True
    return False


def _is_json_decode_call(call: ast.Call, resp_vars: set[str]) -> tuple[bool, str | None]:
    func = call.func
    if isinstance(func, ast.Attribute) and func.attr == "json":
        if isinstance(func.value, ast.Name) and func.value.id in resp_vars:
            return True, func.value.id
        if isinstance(func.value, ast.Call) and _is_http_call(func.value):
            return True, None
    if (
        isinstance(func, ast.Attribute)
        and func.attr in ("loads", "load")
        and isinstance(func.value, ast.Name)
        and func.value.id == "json"
    ):
        for sub in ast.walk(call):
            if isinstance(sub, ast.Name) and sub.id in resp_vars:
                return True, sub.id
    return False, None


def _set_nested_field(target: dict[str, Any], path_keys: list[str], type_hint: str | None) -> None:
    cur = target
    for key in path_keys[:-1]:
        existing = cur.get(key)
        if not isinstance(existing, dict):
            existing = {}
            cur[key] = existing
        cur = existing
    leaf = path_keys[-1]
    if leaf not in cur:
        cur[leaf] = synthesize_value_for_key(leaf, type_hint)


def _analyze_python_file(
    py_file: Path,
    endpoint_fields: dict[tuple[str, str], dict[str, Any]],
    global_fields: dict[str, Any],
) -> None:
    try:
        src = py_file.read_text(encoding="utf-8", errors="ignore")
        tree = ast.parse(src, filename=str(py_file))
    except (OSError, SyntaxError):
        return

    resp_vars: set[str] = set()
    resp_endpoints: dict[str, tuple[str, str]] = {}
    json_vars: dict[str, tuple[str, str] | None] = {}
    file_endpoints: list[tuple[str, str]] = []

    # Pass 1: identify HTTP calls, response variables, and JSON decoded variables
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and _is_http_call(node):
            for arg in list(node.args) + [kw.value for kw in node.keywords]:
                ep = _extract_url_from_ast(arg)
                if ep:
                    file_endpoints.append(ep)
                    endpoint_fields.setdefault(ep, {})
                    break

        if isinstance(node, ast.Assign) and isinstance(node.value, ast.Call):
            if _is_http_call(node.value):
                ep: tuple[str, str] | None = None
                for arg in list(node.value.args) + [kw.value for kw in node.value.keywords]:
                    ep = _extract_url_from_ast(arg)
                    if ep:
                        break
                for tgt in node.targets:
                    if isinstance(tgt, ast.Name):
                        resp_vars.add(tgt.id)
                        if ep:
                            resp_endpoints[tgt.id] = ep
            else:
                is_json, src_resp = _is_json_decode_call(node.value, resp_vars)
                if is_json:
                    ep = resp_endpoints.get(src_resp) if src_resp else None
                    for tgt in node.targets:
                        if isinstance(tgt, ast.Name):
                            json_vars[tgt.id] = ep

        if isinstance(node, ast.With):
            for item in node.items:
                if isinstance(item.context_expr, ast.Call) and _is_http_call(item.context_expr):
                    ep = None
                    for arg in list(item.context_expr.args) + [
                        kw.value for kw in item.context_expr.keywords
                    ]:
                        ep = _extract_url_from_ast(arg)
                        if ep:
                            break
                    if isinstance(item.optional_vars, ast.Name):
                        resp_vars.add(item.optional_vars.id)
                        if ep:
                            resp_endpoints[item.optional_vars.id] = ep

    # Pass 2: collect key reads on json_vars and inline resp.json()[...]
    for node in ast.walk(tree):
        # data["a"]["b"] or data["a"]
        if isinstance(node, ast.Subscript):
            keys: list[str] = []
            cur: ast.AST = node
            while isinstance(cur, ast.Subscript):
                if isinstance(cur.slice, ast.Constant) and isinstance(cur.slice.value, str):
                    keys.append(cur.slice.value)
                    cur = cur.value
                else:
                    break
            if keys:
                keys.reverse()
                matched_ep: tuple[str, str] | None = None
                matched = False
                if isinstance(cur, ast.Name) and cur.id in json_vars:
                    matched = True
                    matched_ep = json_vars[cur.id]
                elif isinstance(cur, ast.Call):
                    is_json, src_resp = _is_json_decode_call(cur, resp_vars)
                    if is_json:
                        matched = True
                        matched_ep = resp_endpoints.get(src_resp) if src_resp else None
                if matched:
                    _set_nested_field(global_fields, keys, None)
                    if matched_ep:
                        _set_nested_field(endpoint_fields.setdefault(matched_ep, {}), keys, None)

        # data.get("key", default)
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "get"
            and node.args
            and isinstance(node.args[0], ast.Constant)
            and isinstance(node.args[0].value, str)
        ):
            key = node.args[0].value
            hint = _type_hint_from_default(node.args[1] if len(node.args) > 1 else None)
            recv = node.func.value
            matched = False
            matched_ep = None
            if isinstance(recv, ast.Name) and recv.id in json_vars:
                matched = True
                matched_ep = json_vars[recv.id]
            elif isinstance(recv, ast.Call):
                is_json, src_resp = _is_json_decode_call(recv, resp_vars)
                if is_json:
                    matched = True
                    matched_ep = resp_endpoints.get(src_resp) if src_resp else None
            if matched:
                _set_nested_field(global_fields, [key], hint)
                if matched_ep:
                    _set_nested_field(endpoint_fields.setdefault(matched_ep, {}), [key], hint)

    # Associate file-level discovered fields with endpoints mentioned in the same file
    if len(file_endpoints) == 1 and global_fields:
        ep_dict = endpoint_fields.setdefault(file_endpoints[0], {})
        for k, v in global_fields.items():
            ep_dict.setdefault(k, v)


def _analyze_js_file(
    js_file: Path,
    endpoint_fields: dict[tuple[str, str], dict[str, Any]],
    global_fields: dict[str, Any],
) -> None:
    try:
        src = js_file.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return

    file_endpoints: list[tuple[str, str]] = []
    for m in _URL_LITERAL_RE.finditer(src):
        parsed = urlparse(m.group(1))
        host = (parsed.hostname or "").lower()
        if host and host not in ("127.0.0.1", "localhost", "::1"):
            ep = (host, parsed.path or "/")
            file_endpoints.append(ep)
            endpoint_fields.setdefault(ep, {})

    if not file_endpoints and "fetch(" not in src and "axios." not in src and "https." not in src:
        return

    file_fields: dict[str, Any] = {}
    json_vars: set[str] = set()
    for m in _JS_JSON_ASSIGN_RE.finditer(src):
        json_vars.add(m.group(1))

    for m in _JS_DESTRUCTURE_RE.finditer(src):
        rhs = m.group(2)
        if ".json" in m.group(0) or ".data" in m.group(0) or rhs in json_vars:
            raw_keys = m.group(1).split(",")
            for part in raw_keys:
                key = part.strip().split(":")[0].split("=")[0].strip()
                if key and re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", key):
                    file_fields.setdefault(key, synthesize_value_for_key(key))

    for m in _JS_PROP_READ_RE.finditer(src):
        var_name, prop = m.group(1), m.group(2)
        if var_name in json_vars and prop not in _JS_SKIP_PROPS:
            file_fields.setdefault(prop, synthesize_value_for_key(prop))

    for m in _JS_BRACKET_READ_RE.finditer(src):
        var_name, prop = m.group(1), m.group(2)
        if var_name in json_vars:
            file_fields.setdefault(prop, synthesize_value_for_key(prop))

    for k, v in file_fields.items():
        global_fields.setdefault(k, v)
    for ep in file_endpoints:
        ep_dict = endpoint_fields.setdefault(ep, {})
        for k, v in file_fields.items():
            ep_dict.setdefault(k, v)


def infer_mock_rules(workspace_dir: Path) -> list[MockRule]:
    """Infer HTTP 200 expected-shape mock rules from target Python and JS/TS source code."""
    root = Path(workspace_dir).resolve()
    endpoint_fields: dict[tuple[str, str], dict[str, Any]] = {}
    global_fields: dict[str, Any] = {}

    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in sorted(dirnames) if d not in SKIP_DIRS]
        for fname in sorted(filenames):
            fpath = Path(dirpath) / fname
            if fname.endswith(".py"):
                _analyze_python_file(fpath, endpoint_fields, global_fields)
            elif fname.endswith((".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx")):
                _analyze_js_file(fpath, endpoint_fields, global_fields)

    rules: list[MockRule] = []
    for (host, path_prefix), fields in sorted(endpoint_fields.items()):
        payload: dict[str, Any] = {"ok": True, "status": "ok", "mocked_by": "vulnbox"}
        payload.update(fields)
        rules.append(
            MockRule(
                host_pattern=host,
                path_prefix=path_prefix,
                method="*",
                status=200,
                json_body=payload,
                source="inferred",
            )
        )

    # Catch-all inferred rule combining every discovered JSON response key so dynamic URLs also get 200 + expected data
    catch_all_payload: dict[str, Any] = {"ok": True, "status": "ok", "mocked_by": "vulnbox"}
    catch_all_payload.update(global_fields)
    rules.append(
        MockRule(
            host_pattern="*",
            path_prefix="/",
            method="*",
            status=200,
            json_body=catch_all_payload,
            source="inferred_default",
        )
    )
    return rules
