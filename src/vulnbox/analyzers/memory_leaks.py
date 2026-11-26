"""Static memory leak (CWE-401) and resource/handle leak (CWE-772) analyzer for Python & JS/TS."""

from __future__ import annotations

import ast
import re
from pathlib import Path
from typing import Any

from vulnbox.analyzers.base import extract_snippet, iter_source_files, make_finding_id
from vulnbox.callgraph.ts_utils import node_text, parse_source, walk_nodes
from vulnbox.models import Finding

CACHE_NAME_HINTS = (
    "cache",
    "store",
    "history",
    "sessions",
    "records",
    "items",
    "logs",
    "events",
    "buffers",
    "requests",
    "messages",
    "seen",
    "entries",
)
JS_EXTS = (".js", ".mjs", ".cjs", ".ts", ".tsx")
PY_RESOURCE_CALLS = frozenset({"open", "sqlite3.connect", "socket.socket"})


def _dotted(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = _dotted(node.value)
        return f"{parent}.{node.attr}" if parent else node.attr
    return ""


def _looks_like_cache_name(name: str) -> bool:
    low = name.lower()
    return any(hint in low for hint in CACHE_NAME_HINTS)


def _analyze_python_leaks(
    workspace_dir: Path,
    call_graph: Any | None = None,
) -> list[Finding]:
    findings: list[Finding] = []
    for py_file in iter_source_files(workspace_dir, (".py",)):
        try:
            source = py_file.read_text(encoding="utf-8", errors="ignore")
            tree = ast.parse(source)
        except (OSError, SyntaxError):
            continue
        rel = str(py_file.relative_to(workspace_dir))
        lines = source.splitlines()

        # --- MEM-PY-001: Unbounded module-level dict/list/set mutated in handlers/functions ---
        mod_containers: dict[str, tuple[int, str]] = {}
        for stmt in tree.body:
            target_name: str | None = None
            val: ast.AST | None = None
            if isinstance(stmt, ast.Assign) and len(stmt.targets) == 1 and isinstance(stmt.targets[0], ast.Name):
                target_name = stmt.targets[0].id
                val = stmt.value
            elif isinstance(stmt, ast.AnnAssign) and isinstance(stmt.target, ast.Name) and stmt.value is not None:
                target_name = stmt.target.id
                val = stmt.value
            if not target_name or val is None:
                continue
            # Skip ALL_CAPS constants unless explicitly named like a cache/store
            if target_name.isupper() and not _looks_like_cache_name(target_name):
                continue
            if isinstance(val, (ast.Dict, ast.List, ast.Set)):
                kind = type(val).__name__.lower()
                mod_containers[target_name] = (stmt.lineno, kind)
            elif isinstance(val, ast.Call):
                cname = _dotted(val.func)
                if cname in ("dict", "list", "set", "collections.defaultdict", "defaultdict"):
                    mod_containers[target_name] = (stmt.lineno, cname.rsplit(".", 1)[-1])

        for cname, (decl_line, kind) in mod_containers.items():
            # Check if module has eviction/size-bound operations on this container
            has_eviction = bool(
                re.search(
                    rf"\b{re.escape(cname)}\.(?:pop|popitem|clear|remove)\s*\("
                    rf"|\bdel\s+{re.escape(cname)}\b"
                    rf"|\blen\s*\(\s*{re.escape(cname)}\s*\)\s*(?:>=|>|==)",
                    source,
                )
            )
            if has_eviction:
                continue

            # Find mutations inside functions (especially route-reachable or cache-named)
            for node in ast.walk(tree):
                if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    continue
                is_route_reachable = (
                    call_graph is not None
                    and call_graph.find_route_for_location(rel, node.lineno) is not None
                )
                if not (_looks_like_cache_name(cname) or is_route_reachable):
                    continue

                mut_line: int | None = None
                for sub in ast.walk(node):
                    if isinstance(sub, ast.Assign):
                        for t in sub.targets:
                            if (
                                isinstance(t, ast.Subscript)
                                and isinstance(t.value, ast.Name)
                                and t.value.id == cname
                            ):
                                mut_line = getattr(sub, "lineno", node.lineno)
                                break
                    elif isinstance(sub, ast.Call) and isinstance(sub.func, ast.Attribute):
                        if (
                            isinstance(sub.func.value, ast.Name)
                            and sub.func.value.id == cname
                            and sub.func.attr in ("append", "extend", "add", "update", "setdefault")
                        ):
                            mut_line = getattr(sub, "lineno", node.lineno)
                    if mut_line is not None:
                        break

                if mut_line is not None:
                    route = call_graph.find_route_for_location(rel, mut_line) if call_graph else None
                    findings.append(
                        Finding(
                            finding_id=make_finding_id("MEM-PY-001", rel, mut_line),
                            rule_id="MEM-PY-001",
                            cwe_id="CWE-401",
                            title="Unbounded In-Memory Collection Growth (Memory Leak)",
                            category="memory_leak",
                            severity="high",
                            file_path=rel,
                            start_line=mut_line,
                            end_line=mut_line,
                            snippet=extract_snippet(lines, mut_line, mut_line),
                            message=(
                                f"Module-level {kind} '{cname}' (line {decl_line}) grows inside "
                                f"'{node.name}()' without any eviction, TTL, or maximum size cap."
                            ),
                            reachability="reachable" if route else "under_investigation",
                            recommended_fix=(
                                f"Bound '{cname}' with a fixed maximum size (e.g., OrderedDict/LRU eviction "
                                "or collections.deque(maxlen=256))."
                            ),
                            metadata={
                                "container": cname,
                                "container_kind": kind,
                                "decl_line": decl_line,
                                "function": node.name,
                                **({"route": route} if route else {}),
                            },
                        )
                    )
                    break

        # --- MEM-PY-002: Unbounded @lru_cache(maxsize=None) / @cache on method or route ---
        for node in ast.walk(tree):
            if isinstance(node, ast.ClassDef):
                for item in node.body:
                    if not isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        continue
                    has_self = bool(item.args.args and item.args.args[0].arg == "self")
                    if not has_self:
                        continue
                    for dec in item.decorator_list:
                        dname = _dotted(dec.func) if isinstance(dec, ast.Call) else _dotted(dec)
                        tail = dname.rsplit(".", 1)[-1]
                        is_unbounded = tail == "cache" or (
                            tail == "lru_cache"
                            and isinstance(dec, ast.Call)
                            and any(
                                kw.arg == "maxsize"
                                and isinstance(kw.value, ast.Constant)
                                and kw.value.value is None
                                for kw in dec.keywords
                            )
                        )
                        if is_unbounded:
                            dline = getattr(dec, "lineno", item.lineno)
                            findings.append(
                                Finding(
                                    finding_id=make_finding_id("MEM-PY-002", rel, dline),
                                    rule_id="MEM-PY-002",
                                    cwe_id="CWE-401",
                                    title="Unbounded Method Cache Retains Instance References",
                                    category="memory_leak",
                                    severity="medium",
                                    file_path=rel,
                                    start_line=dline,
                                    end_line=dline,
                                    snippet=extract_snippet(lines, dline, dline),
                                    message=(
                                        f"Unbounded @{tail} on instance method '{node.name}.{item.name}()' "
                                        "pins every 'self' instance in memory indefinitely."
                                    ),
                                    reachability="reachable",
                                    recommended_fix="Use a bounded @lru_cache(maxsize=256) on a static/module function or WeakKeyDictionary.",
                                )
                            )

        # --- MEM-PY-003: Unclosed file / DB / socket handle outside `with` ---
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            with_calls: set[int] = set()
            with_managed_vars: set[str] = set()
            for sub in ast.walk(node):
                if isinstance(sub, (ast.With, ast.AsyncWith)):
                    for item in sub.items:
                        with_calls.add(id(item.context_expr))
                        if isinstance(item.context_expr, ast.Name):
                            with_managed_vars.add(item.context_expr.id)

            # Collect returned variable names (factory functions intentionally return handles)
            returned_names: set[str] = set()
            for sub in ast.walk(node):
                if isinstance(sub, ast.Return) and isinstance(sub.value, ast.Name):
                    returned_names.add(sub.value.id)

            # Collect variables explicitly closed in a `finally:` block or unconditional close
            closed_vars: set[str] = set()
            for sub in ast.walk(node):
                if isinstance(sub, ast.Call) and isinstance(sub.func, ast.Attribute):
                    if sub.func.attr == "close" and isinstance(sub.func.value, ast.Name):
                        closed_vars.add(sub.func.value.id)

            for sub in ast.walk(node):
                if not isinstance(sub, ast.Assign) or not isinstance(sub.value, ast.Call):
                    continue
                if id(sub.value) in with_calls:
                    continue
                cname = _dotted(sub.value.func)
                if cname not in PY_RESOURCE_CALLS:
                    continue
                if len(sub.targets) != 1 or not isinstance(sub.targets[0], ast.Name):
                    continue
                var_name = sub.targets[0].id
                if (
                    var_name in returned_names
                    or var_name in closed_vars
                    or var_name in with_managed_vars
                ):
                    continue
                lineno = getattr(sub, "lineno", node.lineno)
                route = call_graph.find_route_for_location(rel, lineno) if call_graph else None
                findings.append(
                    Finding(
                        finding_id=make_finding_id("MEM-PY-003", rel, lineno),
                        rule_id="MEM-PY-003",
                        cwe_id="CWE-772",
                        title="Unclosed File / Socket / Database Handle (Resource Leak)",
                        category="resource_leak",
                        severity="high",
                        file_path=rel,
                        start_line=lineno,
                        end_line=lineno,
                        snippet=extract_snippet(lines, lineno, lineno),
                        message=(
                            f"Resource '{var_name} = {cname}(...)' in '{node.name}()' is opened outside "
                            "a `with` context manager and never closed, leaking OS file descriptors."
                        ),
                        reachability="reachable" if route else "under_investigation",
                        recommended_fix=f"Use `with {cname}(...) as {var_name}:` so the handle is always closed.",
                        metadata={
                            "variable": var_name,
                            "resource_call": cname,
                            "function": node.name,
                            **({"route": route} if route else {}),
                        },
                    )
                )

        # --- MEM-PY-004: Fire-and-forget asyncio.create_task() ---
        for node in ast.walk(tree):
            if isinstance(node, ast.Expr) and isinstance(node.value, ast.Call):
                if _dotted(node.value.func) in ("asyncio.create_task", "create_task"):
                    lineno = getattr(node, "lineno", 1)
                    findings.append(
                        Finding(
                            finding_id=make_finding_id("MEM-PY-004", rel, lineno),
                            rule_id="MEM-PY-004",
                            cwe_id="CWE-772",
                            title="Unreferenced asyncio.create_task() Background Task",
                            category="resource_leak",
                            severity="medium",
                            file_path=rel,
                            start_line=lineno,
                            end_line=lineno,
                            snippet=extract_snippet(lines, lineno, lineno),
                            message="Return value of asyncio.create_task() is discarded; tasks may be garbage-collected mid-flight or leak unhandled exceptions.",
                            reachability="reachable",
                            recommended_fix="Store task references in a tracked set and remove via task.add_done_callback(tasks.discard).",
                        )
                    )

    return findings


def _analyze_node_leaks(
    workspace_dir: Path,
    call_graph: Any | None = None,
) -> list[Finding]:
    findings: list[Finding] = []
    for js_file in iter_source_files(workspace_dir, JS_EXTS):
        if js_file.name.lower().endswith((".min.js", ".min.mjs", ".bundle.js")):
            continue
        try:
            source = js_file.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        tree, raw = parse_source(source, js_file.suffix)
        if tree is None:
            continue
        rel = str(js_file.relative_to(workspace_dir))
        lines = source.splitlines()

        # --- MEM-JS-001: Unbounded top-level Map / Set / Array / Object mutated in handlers ---
        top_containers: dict[str, tuple[int, str]] = {}
        for child in tree.root_node.named_children:
            if child.type in ("lexical_declaration", "variable_declaration"):
                for decl in walk_nodes(child):
                    if decl.type != "variable_declarator":
                        continue
                    nn = decl.child_by_field_name("name")
                    vn = decl.child_by_field_name("value")
                    if not nn or not vn or nn.type != "identifier":
                        continue
                    cname = node_text(nn, raw)
                    vtxt = node_text(vn, raw).strip()
                    if vtxt.startswith(("new Map(", "new Set(")):
                        kind = "Map" if "Map(" in vtxt else "Set"
                        top_containers[cname] = (decl.start_point[0] + 1, kind)
                    elif vn.type in ("array", "object") and _looks_like_cache_name(cname):
                        top_containers[cname] = (decl.start_point[0] + 1, vn.type)

        for cname, (decl_line, kind) in top_containers.items():
            has_eviction = bool(
                re.search(
                    rf"\b{re.escape(cname)}\.(?:delete|clear|shift|pop|splice)\s*\("
                    rf"|\bdelete\s+{re.escape(cname)}\b"
                    rf"|\b{re.escape(cname)}\.(?:size|length)\s*(?:>=|>|==)",
                    source,
                )
            )
            if has_eviction:
                continue

            for node in walk_nodes(tree.root_node):
                mut_line: int | None = None
                if node.type == "call_expression":
                    fn = node.child_by_field_name("function")
                    if fn and node_text(fn, raw) in (
                        f"{cname}.set",
                        f"{cname}.add",
                        f"{cname}.push",
                    ):
                        mut_line = node.start_point[0] + 1
                elif node.type == "assignment_expression":
                    left = node.child_by_field_name("left")
                    if left and left.type == "subscript_expression":
                        obj = left.child_by_field_name("object")
                        if obj and node_text(obj, raw) == cname:
                            mut_line = node.start_point[0] + 1
                if mut_line is not None:
                    # Only flag runtime mutations inside functions/methods/callbacks (skip one-time module init loops)
                    inside_fn = False
                    anc = node.parent
                    while anc is not None:
                        if anc.type in ("function_declaration", "function_expression", "arrow_function", "method_definition"):
                            inside_fn = True
                            break
                        anc = anc.parent
                    if not inside_fn:
                        continue
                    route = call_graph.find_route_for_location(rel, mut_line) if call_graph else None
                    findings.append(
                        Finding(
                            finding_id=make_finding_id("MEM-JS-001", rel, mut_line),
                            rule_id="MEM-JS-001",
                            cwe_id="CWE-401",
                            title="Unbounded In-Memory Collection Growth (Memory Leak)",
                            category="memory_leak",
                            severity="high",
                            file_path=rel,
                            start_line=mut_line,
                            end_line=mut_line,
                            snippet=extract_snippet(lines, mut_line, mut_line),
                            message=(
                                f"Module-level {kind} '{cname}' (line {decl_line}) grows without eviction, "
                                "TTL, or maximum capacity bound."
                            ),
                            reachability="reachable" if route else "under_investigation",
                            recommended_fix=(
                                f"Evict oldest entries from '{cname}' once it reaches a fixed cap (e.g., 256) "
                                "or use a bounded LRU cache."
                            ),
                            metadata={
                                "container": cname,
                                "container_kind": kind,
                                "decl_line": decl_line,
                                **({"route": route} if route else {}),
                            },
                        )
                    )
                    break

        # --- MEM-JS-002: Event listener added inside request handler / loop without removal ---
        for node in walk_nodes(tree.root_node):
            if node.type != "call_expression":
                continue
            fn = node.child_by_field_name("function")
            if fn is None or fn.type != "member_expression":
                continue
            prop = fn.child_by_field_name("property")
            obj = fn.child_by_field_name("object")
            if not prop or not obj:
                continue
            method = node_text(prop, raw)
            obj_name = node_text(obj, raw)
            if method not in ("on", "addListener"):
                continue
            # Skip HTTP request/response stream listeners (`req.on('data')`, `res.on('finish')`)
            if obj_name in ("req", "res", "request", "response", "stream", "socket"):
                continue

            # Check if enclosed inside a request callback or loop
            in_handler_or_loop = False
            enclosing_scope = None
            curr = node.parent
            while curr is not None:
                if curr.type in ("for_statement", "while_statement", "for_in_statement", "for_of_statement"):
                    in_handler_or_loop = True
                    enclosing_scope = curr
                    break
                if curr.type in ("arrow_function", "function_expression", "function_declaration"):
                    params = curr.child_by_field_name("parameters")
                    ptxt = node_text(params, raw) if params else ""
                    if "req" in ptxt or "res" in ptxt:
                        in_handler_or_loop = True
                        enclosing_scope = curr
                        break
                    # Or named handler called from a route
                    if curr.type == "function_declaration":
                        fnn = curr.child_by_field_name("name")
                        if fnn and call_graph and call_graph.find_route_for_location(rel, curr.start_point[0] + 1):
                            in_handler_or_loop = True
                            enclosing_scope = curr
                            break
                curr = curr.parent

            if not in_handler_or_loop or enclosing_scope is None:
                continue
            scope_txt = node_text(enclosing_scope, raw)
            if f"{obj_name}.off(" in scope_txt or f"{obj_name}.removeListener(" in scope_txt:
                continue
            # Skip short-lived local emitters created inside the same handler/loop (e.g. `const client = ...`)
            root_ident = obj_name.split(".", 1)[0]
            if re.search(rf"\b(?:const|let|var)\s+{re.escape(root_ident)}\b", scope_txt):
                continue

            lineno = node.start_point[0] + 1
            route = call_graph.find_route_for_location(rel, lineno) if call_graph else None
            findings.append(
                Finding(
                    finding_id=make_finding_id("MEM-JS-002", rel, lineno),
                    rule_id="MEM-JS-002",
                    cwe_id="CWE-401",
                    title="Unremoved Event Listener Inside Request Handler or Loop",
                    category="memory_leak",
                    severity="high",
                    file_path=rel,
                    start_line=lineno,
                    end_line=lineno,
                    snippet=extract_snippet(lines, lineno, lineno),
                    message=(
                        f"'{obj_name}.{method}(...)' registers a persistent listener per invocation "
                        "without a matching .off()/.removeListener(), leaking closures and buffers."
                    ),
                    reachability="reachable" if route else "under_investigation",
                    recommended_fix=f"Use {obj_name}.once(...) or deregister with {obj_name}.off(...) on response completion.",
                    metadata={
                        "emitter": obj_name,
                        "method": method,
                        **({"route": route} if route else {}),
                    },
                )
            )

        # --- MEM-JS-003: Uncaptured setInterval() ---
        is_browser_ui_script = (
            "/static/" in f"/{rel.replace(chr(92), '/')}"
            and any(tok in source for tok in ("$(document).ready", "document.addEventListener", "window.addEventListener", "$(function"))
        )
        for node in walk_nodes(tree.root_node):
            if node.type == "expression_statement" and node.named_children:
                child = node.named_children[0]
                if child.type == "call_expression":
                    fn = child.child_by_field_name("function")
                    if fn and node_text(fn, raw) == "setInterval":
                        if is_browser_ui_script:
                            continue
                        lineno = child.start_point[0] + 1
                        findings.append(
                            Finding(
                                finding_id=make_finding_id("MEM-JS-003", rel, lineno),
                                rule_id="MEM-JS-003",
                                cwe_id="CWE-772",
                                title="Uncaptured setInterval() Timer Leak",
                                category="resource_leak",
                                severity="medium",
                                file_path=rel,
                                start_line=lineno,
                                end_line=lineno,
                                snippet=extract_snippet(lines, lineno, lineno),
                                message="setInterval() return handle is discarded so clearInterval() can never be called.",
                                reachability="reachable",
                                recommended_fix="Store the timer handle and call clearInterval(timerId) during shutdown/cleanup.",
                            )
                        )

        # --- MEM-JS-004: Unclosed fs.createReadStream without cleanup/pipeline ---
        for node in walk_nodes(tree.root_node):
            if node.type != "call_expression":
                continue
            fn = node.child_by_field_name("function")
            if not fn or node_text(fn, raw) not in ("fs.createReadStream", "createReadStream"):
                continue
            curr = node.parent
            while curr is not None and curr.type not in ("arrow_function", "function_expression", "function_declaration", "program"):
                curr = curr.parent
            scope_txt = node_text(curr, raw) if curr else source
            if any(tok in scope_txt for tok in (".destroy(", ".close(", "pipeline(", ".pipe(")):
                continue
            lineno = node.start_point[0] + 1
            findings.append(
                Finding(
                    finding_id=make_finding_id("MEM-JS-004", rel, lineno),
                    rule_id="MEM-JS-004",
                    cwe_id="CWE-772",
                    title="Unclosed File Stream Handle (Resource Leak)",
                    category="resource_leak",
                    severity="medium",
                    file_path=rel,
                    start_line=lineno,
                    end_line=lineno,
                    snippet=extract_snippet(lines, lineno, lineno),
                    message="fs.createReadStream() lacks stream.destroy()/close() or stream.pipeline() error teardown.",
                    reachability="reachable",
                    recommended_fix="Use stream.pipeline() or attach error/close handlers calling stream.destroy().",
                )
            )

    return findings


class MemoryLeakAnalyzer:
    """Static analyzer for Python and JS/TS memory leaks (CWE-401) and resource leaks (CWE-772)."""

    name = "memory-leaks"

    def analyze(self, workspace_dir: Path, call_graph: Any | None = None) -> list[Finding]:
        return [
            *_analyze_python_leaks(workspace_dir, call_graph=call_graph),
            *_analyze_node_leaks(workspace_dir, call_graph=call_graph),
        ]
