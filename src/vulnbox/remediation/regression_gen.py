"""Registry-backed defensive security regression test generators."""

from __future__ import annotations

import re

from vulnbox.models import Finding
from vulnbox.registry import PluginRegistry, default_registry


def _safe_ident(raw: str) -> str:
    return re.sub(r"[^a-zA-Z0-9_]", "_", raw).lower()


@default_registry.register_regression_test("PY-YAML-001")
def _reg_py_yaml(finding: Finding) -> tuple[str, str]:
    slug = _safe_ident(finding.finding_id)
    code = f'''"""Security regression test for {finding.finding_id} ({finding.cwe_id})."""

import ast
from pathlib import Path


def test_no_unsafe_yaml_load():
    src = Path({finding.file_path!r}).read_text(encoding="utf-8")
    tree = ast.parse(src)
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            if isinstance(node.func.value, ast.Name) and node.func.value.id == "yaml":
                assert node.func.attr not in ("unsafe_load", "full_load"), (
                    f"Unsafe yaml.{{node.func.attr}} still present in {finding.file_path}"
                )
                if node.func.attr == "load":
                    safe_loader = any(
                        kw.arg == "Loader"
                        and getattr(kw.value, "attr", getattr(kw.value, "id", ""))
                        in ("SafeLoader", "CSafeLoader", "BaseLoader")
                        for kw in node.keywords
                    )
                    assert safe_loader, "yaml.load() must use SafeLoader or yaml.safe_load()"
'''
    return (f"tests/test_security_{slug}.py", code)


@default_registry.register_regression_test("PY-TLS-001")
def _reg_py_tls(finding: Finding) -> tuple[str, str]:
    slug = _safe_ident(finding.finding_id)
    code = f'''"""Security regression test for {finding.finding_id} ({finding.cwe_id})."""

from pathlib import Path


def test_tls_verification_enabled():
    src = Path({finding.file_path!r}).read_text(encoding="utf-8")
    assert "verify=False" not in src, "TLS verification must not be disabled"
'''
    return (f"tests/test_security_{slug}.py", code)


@default_registry.register_regression_test("PY-DEBUG-001")
def _reg_py_debug(finding: Finding) -> tuple[str, str]:
    slug = _safe_ident(finding.finding_id)
    code = f'''"""Security regression test for {finding.finding_id} ({finding.cwe_id})."""

from pathlib import Path


def test_debug_mode_disabled():
    src = Path({finding.file_path!r}).read_text(encoding="utf-8")
    assert "debug=True" not in src, "Server debug mode must be disabled"
'''
    return (f"tests/test_security_{slug}.py", code)


@default_registry.register_regression_test("PY-HASH-001")
def _reg_py_hash(finding: Finding) -> tuple[str, str]:
    slug = _safe_ident(finding.finding_id)
    code = f'''"""Security regression test for {finding.finding_id} ({finding.cwe_id})."""

from pathlib import Path


def test_no_weak_hash_algorithm():
    src = Path({finding.file_path!r}).read_text(encoding="utf-8")
    assert "hashlib.md5(" not in src and "hashlib.sha1(" not in src
'''
    return (f"tests/test_security_{slug}.py", code)


@default_registry.register_regression_test("PY-PATH-001")
def _reg_py_path(finding: Finding) -> tuple[str, str]:
    slug = _safe_ident(finding.finding_id)
    code = f'''"""Security regression test for {finding.finding_id} ({finding.cwe_id})."""

from pathlib import Path


def test_path_confinement_enforced():
    src = Path({finding.file_path!r}).read_text(encoding="utf-8")
    assert "is_relative_to" in src or ("resolve(" in src and "startswith(" in src), (
        "Path resolution must enforce base directory confinement"
    )
'''
    return (f"tests/test_security_{slug}.py", code)


@default_registry.register_regression_test("PY-SQL-001")
def _reg_py_sql(finding: Finding) -> tuple[str, str]:
    slug = _safe_ident(finding.finding_id)
    code = f'''"""Security regression test for {finding.finding_id} ({finding.cwe_id})."""

import ast
from pathlib import Path


def test_sql_queries_are_parameterized():
    src = Path({finding.file_path!r}).read_text(encoding="utf-8")
    tree = ast.parse(src)
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "execute"
            and node.args
        ):
            first = node.args[0]
            assert not isinstance(first, (ast.JoinedStr, ast.BinOp)), (
                "SQL execute() must use parameterized placeholders, not string formatting"
            )
'''
    return (f"tests/test_security_{slug}.py", code)


@default_registry.register_regression_test("JS-TLS-001")
def _reg_js_tls(finding: Finding) -> tuple[str, str]:
    slug = _safe_ident(finding.finding_id)
    code = f'''import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";

test("TLS certificate validation is enabled ({finding.finding_id})", () => {{
  const src = fs.readFileSync({finding.file_path!r}, "utf8");
  assert.equal(/rejectUnauthorized\\s*:\\s*false/.test(src), false);
}});
'''
    return (f"tests/security_{slug}.test.mjs", code)


@default_registry.register_regression_test("JS-CORS-001")
def _reg_js_cors(finding: Finding) -> tuple[str, str]:
    slug = _safe_ident(finding.finding_id)
    code = f'''import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";

test("CORS origin is allowlisted rather than wildcard/reflected ({finding.finding_id})", () => {{
  const src = fs.readFileSync({finding.file_path!r}, "utf8");
  const hasUncheckedReflection = /['"]Access-Control-Allow-Origin['"]\\s*,\\s*(?:['"]\\*['"]|req\\.headers\\.origin)/.test(src);
  const hasAllowlist = src.includes("_allowedOrigins") || src.includes("allowedOrigins");
  assert.equal(hasUncheckedReflection && !hasAllowlist, false);
}});
'''
    return (f"tests/security_{slug}.test.mjs", code)


@default_registry.register_regression_test("JS-PATH-001")
def _reg_js_path(finding: Finding) -> tuple[str, str]:
    slug = _safe_ident(finding.finding_id)
    code = f'''import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";

test("Path confinement check is enforced ({finding.finding_id})", () => {{
  const src = fs.readFileSync({finding.file_path!r}, "utf8");
  assert.equal(src.includes("path.resolve(") && src.includes(".startsWith("), true);
}});
'''
    return (f"tests/security_{slug}.test.mjs", code)


@default_registry.register_regression_test("CFG-DOCKER-001")
def _reg_docker_user(finding: Finding) -> tuple[str, str]:
    slug = _safe_ident(finding.finding_id)
    code = f'''"""Security regression test for {finding.finding_id} ({finding.cwe_id})."""

import re
from pathlib import Path


def test_dockerfile_uses_non_root_user():
    lines = Path({finding.file_path!r}).read_text(encoding="utf-8").splitlines()
    users = [
        m.group(1).strip()
        for ln in lines
        if (m := re.match(r"^\\s*USER\\s+([^\\s]+)", ln, re.IGNORECASE))
    ]
    assert users and users[-1] not in ("root", "0", "0:0")
'''
    return (f"tests/test_security_{slug}.py", code)


@default_registry.register_regression_test("CFG-DOCKER-002")
def _reg_docker_pin(finding: Finding) -> tuple[str, str]:
    slug = _safe_ident(finding.finding_id)
    code = f'''"""Security regression test for {finding.finding_id} ({finding.cwe_id})."""

import re
from pathlib import Path


def test_dockerfile_pins_base_image():
    lines = Path({finding.file_path!r}).read_text(encoding="utf-8").splitlines()
    for ln in lines:
        m = re.match(r"^\\s*FROM\\s+([^\\s]+)", ln, re.IGNORECASE)
        if m:
            img = m.group(1)
            assert ":" in img and not img.endswith(":latest"), f"Unpinned image: {{img}}"
'''
    return (f"tests/test_security_{slug}.py", code)


@default_registry.register_regression_test(category="dependency")
def _reg_dependency(finding: Finding) -> tuple[str, str]:
    slug = _safe_ident(finding.finding_id)
    pkg = str(finding.metadata.get("package", ""))
    fixed = str(finding.metadata.get("fixed_version", ""))
    if finding.file_path.endswith("package.json"):
        code = f'''import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";

test("Dependency {pkg} meets safe version >= {fixed} ({finding.finding_id})", () => {{
  const data = JSON.parse(fs.readFileSync({finding.file_path!r}, "utf8"));
  const deps = {{ ...(data.dependencies || {{}}), ...(data.devDependencies || {{}}) }};
  const ver = String(deps[{pkg!r}] || "").replace(/^[^0-9]+/, "");
  const toTuple = (v) => v.split(".").map((n) => parseInt(n, 10) || 0);
  const a = toTuple(ver);
  const b = toTuple({fixed!r});
  for (let i = 0; i < Math.max(a.length, b.length); i++) {{
    const x = a[i] || 0;
    const y = b[i] || 0;
    if (x !== y) {{
      assert.ok(x > y, `Expected {pkg} >= {fixed}, got ${{ver}}`);
      return;
    }}
  }}
}});
'''
        return (f"tests/security_{slug}.test.mjs", code)

    code = f'''"""Security regression test for {finding.finding_id} ({finding.cwe_id})."""

import re
from pathlib import Path


def test_dependency_meets_fixed_version():
    text = Path({finding.file_path!r}).read_text(encoding="utf-8")
    m = re.search(r"(?im)^\\s*{re.escape(pkg)}\\s*(?:==|>=|~=)\\s*([0-9][0-9.]*)", text)
    assert m, "Package {pkg} not found in {finding.file_path}"
    got = tuple(int(p) for p in m.group(1).split("."))
    want = tuple(int(p) for p in {fixed!r}.split("."))
    assert got >= want, f"Expected {pkg} >= {fixed}, got {{m.group(1)}}"
'''
    return (f"tests/test_security_{slug}.py", code)


@default_registry.register_regression_test("MEM-PY-001")
def _reg_mem_py_cache(finding: Finding) -> tuple[str, str]:
    slug = _safe_ident(finding.finding_id)
    cname = str(finding.metadata.get("container") or "cache")
    code = f'''"""Memory leak regression test for {finding.finding_id} ({finding.cwe_id})."""

import re
from pathlib import Path


def test_in_memory_cache_is_bounded():
    src = Path({finding.file_path!r}).read_text(encoding="utf-8")
    assert re.search(
        r"\\b{re.escape(cname)}\\.(?:pop|popitem|clear|remove)\\s*\\(|\\blen\\s*\\(\\s*{re.escape(cname)}\\s*\\)\\s*(?:>=|>)",
        src,
    ), "Cache '{cname}' must enforce bounded size / eviction to prevent CWE-401 memory leaks"
'''
    return (f"tests/test_security_{slug}.py", code)


@default_registry.register_regression_test("MEM-PY-002")
def _reg_mem_py_lru(finding: Finding) -> tuple[str, str]:
    slug = _safe_ident(finding.finding_id)
    code = f'''"""Memory leak regression test for {finding.finding_id} ({finding.cwe_id})."""

from pathlib import Path


def test_no_unbounded_method_cache():
    src = Path({finding.file_path!r}).read_text(encoding="utf-8")
    assert "maxsize=None" not in src and "@cache" not in src
'''
    return (f"tests/test_security_{slug}.py", code)


@default_registry.register_regression_test("MEM-PY-003")
def _reg_mem_py_fd(finding: Finding) -> tuple[str, str]:
    slug = _safe_ident(finding.finding_id)
    var_name = str(finding.metadata.get("variable") or "fh")
    code = f'''"""Resource leak regression test for {finding.finding_id} ({finding.cwe_id})."""

import ast
from pathlib import Path


def test_resource_handle_uses_context_manager():
    src = Path({finding.file_path!r}).read_text(encoding="utf-8")
    tree = ast.parse(src)
    with_calls = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.With, ast.AsyncWith)):
            for item in node.items:
                with_calls.add(id(item.context_expr))
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign) and isinstance(node.value, ast.Call):
            if id(node.value) in with_calls:
                continue
            if len(node.targets) == 1 and isinstance(node.targets[0], ast.Name) and node.targets[0].id == {var_name!r}:
                raise AssertionError("Handle '{var_name}' must be opened using a `with` context manager")
'''
    return (f"tests/test_security_{slug}.py", code)


@default_registry.register_regression_test("MEM-JS-001")
def _reg_mem_js_cache(finding: Finding) -> tuple[str, str]:
    slug = _safe_ident(finding.finding_id)
    cname = str(finding.metadata.get("container") or "cache")
    code = f'''import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";

test("Collection {cname} enforces bounded eviction ({finding.finding_id})", () => {{
  const src = fs.readFileSync({finding.file_path!r}, "utf8");
  const bounded = /\\b{re.escape(cname)}\\.(?:delete|clear|shift|pop|splice)\\s*\\(|\\b{re.escape(cname)}\\.(?:size|length)\\s*(?:>=|>)/.test(src);
  assert.ok(bounded, "Collection {cname} must bound its size to prevent memory leaks");
}});
'''
    return (f"tests/security_{slug}.test.mjs", code)


@default_registry.register_regression_test("MEM-JS-002")
def _reg_mem_js_listener(finding: Finding) -> tuple[str, str]:
    slug = _safe_ident(finding.finding_id)
    emitter = str(finding.metadata.get("emitter") or "emitter")
    code = f'''import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";

test("Event listener on {emitter} does not leak per request ({finding.finding_id})", () => {{
  const src = fs.readFileSync({finding.file_path!r}, "utf8");
  const safe = src.includes("{emitter}.once(") || src.includes("{emitter}.off(") || src.includes("{emitter}.removeListener(");
  assert.ok(safe, "Listener on {emitter} must use .once() or remove itself via .off()");
}});
'''
    return (f"tests/security_{slug}.test.mjs", code)


def generate_regression_test(
    finding: Finding,
    registry: PluginRegistry | None = None,
) -> tuple[str, str] | None:
    """Dispatch defensive regression test generation via the plugin registry."""
    reg = registry or default_registry
    gen = reg.get_regression_test_generator(finding)
    if gen is None:
        return None
    return gen(finding)
