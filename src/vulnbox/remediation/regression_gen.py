"""Defensive security regression test generator for Python and Node.js."""

from __future__ import annotations

import re

from vulnbox.models import Finding


def _safe_ident(raw: str) -> str:
    return re.sub(r"[^a-zA-Z0-9_]", "_", raw).lower()


def generate_regression_test(finding: Finding) -> tuple[str, str] | None:
    """Return (relative_test_path, test_source_code) for a defensive regression test.

    Tests assert secure invariants and are designed to fail before the patch and pass after.
    """
    slug = _safe_ident(finding.finding_id)

    if finding.rule_id == "PY-YAML-001":
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

    if finding.rule_id == "PY-TLS-001":
        code = f'''"""Security regression test for {finding.finding_id} ({finding.cwe_id})."""

from pathlib import Path


def test_tls_verification_enabled():
    src = Path({finding.file_path!r}).read_text(encoding="utf-8")
    assert "verify=False" not in src, "TLS verification must not be disabled"
'''
        return (f"tests/test_security_{slug}.py", code)

    if finding.rule_id == "PY-DEBUG-001":
        code = f'''"""Security regression test for {finding.finding_id} ({finding.cwe_id})."""

from pathlib import Path


def test_debug_mode_disabled():
    src = Path({finding.file_path!r}).read_text(encoding="utf-8")
    assert "debug=True" not in src, "Server debug mode must be disabled"
'''
        return (f"tests/test_security_{slug}.py", code)

    if finding.rule_id == "PY-HASH-001":
        code = f'''"""Security regression test for {finding.finding_id} ({finding.cwe_id})."""

from pathlib import Path


def test_no_weak_hash_algorithm():
    src = Path({finding.file_path!r}).read_text(encoding="utf-8")
    assert "hashlib.md5(" not in src and "hashlib.sha1(" not in src
'''
        return (f"tests/test_security_{slug}.py", code)

    if finding.rule_id == "PY-PATH-001":
        code = f'''"""Security regression test for {finding.finding_id} ({finding.cwe_id})."""

from pathlib import Path


def test_path_confinement_enforced():
    src = Path({finding.file_path!r}).read_text(encoding="utf-8")
    assert "is_relative_to" in src or ("resolve(" in src and "startswith(" in src), (
        "Path resolution must enforce base directory confinement"
    )
'''
        return (f"tests/test_security_{slug}.py", code)

    if finding.rule_id == "PY-SQL-001":
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

    if finding.rule_id == "JS-TLS-001":
        code = f'''import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";

test("TLS certificate validation is enabled ({finding.finding_id})", () => {{
  const src = fs.readFileSync({finding.file_path!r}, "utf8");
  assert.equal(/rejectUnauthorized\\s*:\\s*false/.test(src), false);
}});
'''
        return (f"tests/security_{slug}.test.mjs", code)

    if finding.rule_id == "JS-CORS-001":
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

    if finding.rule_id == "JS-PATH-001":
        code = f'''import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";

test("Path confinement check is enforced ({finding.finding_id})", () => {{
  const src = fs.readFileSync({finding.file_path!r}, "utf8");
  assert.equal(src.includes("path.resolve(") && src.includes(".startsWith("), true);
}});
'''
        return (f"tests/security_{slug}.test.mjs", code)

    if finding.rule_id == "CFG-DOCKER-001":
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

    if finding.rule_id == "CFG-DOCKER-002":
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

    if finding.category == "dependency":
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
        else:
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

    return None
