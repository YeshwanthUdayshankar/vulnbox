"""Deterministic Tree-sitter AST JavaScript / TypeScript security analyzer."""

from __future__ import annotations

import re
from pathlib import Path

from vulnbox.analyzers.base import extract_snippet, iter_source_files, make_finding_id
from vulnbox.analyzers.taint import JsTaintTracker
from vulnbox.callgraph.ts_utils import node_text, parse_source, walk_nodes
from vulnbox.models import Finding

SQL_KW_RE = re.compile(r"\b(?:SELECT|INSERT|UPDATE|DELETE)\b", re.IGNORECASE)
JS_EXTS = (".js", ".mjs", ".cjs", ".ts", ".tsx")
MINIFIED_SUFFIXES = (".min.js", ".min.mjs", ".bundle.js")
_JS_SEC_RANDOM_HINTS = (
    "token",
    "secret",
    "password",
    "passwd",
    "nonce",
    "otp",
    "session",
    "csrf",
    "apikey",
    "api_key",
    "reset",
    "auth",
)


def _is_minified_vendor_file(path: Path) -> bool:
    low = path.name.lower()
    return low.endswith(MINIFIED_SUFFIXES)


def _strip_quotes(text: str) -> str:
    s = text.strip()
    if len(s) >= 2 and s[0] == s[-1] and s[0] in ("'", '"', "`"):
        return s[1:-1]
    return s


def _has_dynamic_arg(arg_node, raw: bytes) -> bool:
    if arg_node.type == "template_string":
        return any(ch.type == "template_substitution" for ch in arg_node.children)
    if arg_node.type == "binary_expression":
        return True
    if arg_node.type in ("string", "number", "true", "false", "null"):
        return False
    return True


class NodeSASTAnalyzer:
    """Runs deterministic Tree-sitter AST security analysis over JS and TS files."""

    name = "node-sast"

    def analyze(self, workspace_dir: Path) -> list[Finding]:
        findings: list[Finding] = []
        for js_file in iter_source_files(workspace_dir, JS_EXTS):
            if _is_minified_vendor_file(js_file):
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
            has_child_process = "child_process" in source
            has_jwt_verify = "jwt.verify(" in source
            taint = JsTaintTracker(tree.root_node, raw)

            has_fs_read = False
            has_path_confinement = (
                "path.resolve(" in source
                and (".startsWith(" in source or "path.relative(" in source)
            )
            path_join_lines: list[int] = []
            cors_wildcard_lines: list[int] = []
            has_cors_creds_header = False
            has_origin_allowlist = (
                "_allowedOrigins" in source
                or "allowedOrigins" in source
                or ".has(req.headers.origin)" in source
                or ".includes(req.headers.origin)" in source
            )
            cors_mw_emitted = False

            for node in walk_nodes(tree.root_node):
                lineno = node.start_point[0] + 1

                # Check NODE_TLS_REJECT_UNAUTHORIZED = '0', XSS innerHTML, and Prototype Pollution
                if node.type == "assignment_expression":
                    left = node.child_by_field_name("left")
                    right = node.child_by_field_name("right")
                    if left and right:
                        left_txt = node_text(left, raw)
                        right_txt = node_text(right, raw)
                        if (
                            "NODE_TLS_REJECT_UNAUTHORIZED" in left_txt
                            and _strip_quotes(right_txt) == "0"
                        ):
                            findings.append(
                                Finding(
                                    finding_id=make_finding_id("JS-TLS-001", rel, lineno),
                                    rule_id="JS-TLS-001",
                                    cwe_id="CWE-295",
                                    title="TLS Certificate Validation Disabled",
                                    category="sast",
                                    severity="medium",
                                    file_path=rel,
                                    start_line=lineno,
                                    end_line=lineno,
                                    snippet=extract_snippet(lines, lineno, lineno),
                                    message="NODE_TLS_REJECT_UNAUTHORIZED='0' disables TLS certificate verification globally.",
                                    reachability="reachable",
                                    recommended_fix="Remove NODE_TLS_REJECT_UNAUTHORIZED='0' and keep TLS validation enabled.",
                                )
                            )

                        # JS-XSS-001: .innerHTML / .outerHTML assigned dynamic value
                        if (
                            left.type == "member_expression"
                            and left_txt.endswith((".innerHTML", ".outerHTML"))
                            and _has_dynamic_arg(right, raw)
                            and "DOMPurify.sanitize" not in right_txt
                        ):
                            findings.append(
                                Finding(
                                    finding_id=make_finding_id("JS-XSS-001", rel, lineno),
                                    rule_id="JS-XSS-001",
                                    cwe_id="CWE-79",
                                    title="DOM Cross-Site Scripting (XSS) via innerHTML",
                                    category="sast",
                                    severity="high",
                                    file_path=rel,
                                    start_line=lineno,
                                    end_line=lineno,
                                    snippet=extract_snippet(lines, lineno, lineno),
                                    message=f"Dynamic data assigned to {left_txt} without HTML sanitization.",
                                    reachability="reachable",
                                    recommended_fix="Use textContent / DOM APIs or sanitize with DOMPurify.sanitize().",
                                )
                            )

                        # JS-PROTO-001: Dynamic nested subscript assignment target[a][b] = val without __proto__ guard
                        if left.type == "subscript_expression":
                            obj_n = left.child_by_field_name("object")
                            idx_n = left.child_by_field_name("index")
                            if (
                                obj_n is not None
                                and obj_n.type == "subscript_expression"
                                and idx_n is not None
                                and _has_dynamic_arg(idx_n, raw)
                            ):
                                curr = node.parent
                                while curr is not None and curr.type not in (
                                    "function_declaration",
                                    "function_expression",
                                    "arrow_function",
                                    "method_definition",
                                    "program",
                                ):
                                    curr = curr.parent
                                fn_scope = node_text(curr, raw) if curr else source
                                if "__proto__" not in fn_scope and "Object.create(null)" not in fn_scope:
                                    findings.append(
                                        Finding(
                                            finding_id=make_finding_id("JS-PROTO-001", rel, lineno),
                                            rule_id="JS-PROTO-001",
                                            cwe_id="CWE-1321",
                                            title="Potential Prototype Pollution in Dynamic Property Assignment",
                                            category="sast",
                                            severity="high",
                                            file_path=rel,
                                            start_line=lineno,
                                            end_line=lineno,
                                            snippet=extract_snippet(lines, lineno, lineno),
                                            message="Nested dynamic bracket assignment allows '__proto__'/'constructor' prototype pollution.",
                                            reachability="reachable",
                                            recommended_fix="Reject '__proto__', 'constructor', and 'prototype' keys or use a Map/Object.create(null).",
                                        )
                                    )

                # Check rejectUnauthorized: false
                if node.type == "pair":
                    key = node.child_by_field_name("key")
                    val = node.child_by_field_name("value")
                    if (
                        key
                        and val
                        and _strip_quotes(node_text(key, raw)) == "rejectUnauthorized"
                        and node_text(val, raw).strip() == "false"
                    ):
                        findings.append(
                            Finding(
                                finding_id=make_finding_id("JS-TLS-001", rel, lineno),
                                rule_id="JS-TLS-001",
                                cwe_id="CWE-295",
                                title="TLS Certificate Validation Disabled",
                                category="sast",
                                severity="medium",
                                file_path=rel,
                                start_line=lineno,
                                end_line=lineno,
                                snippet=extract_snippet(lines, lineno, lineno),
                                message="TLS certificate validation is explicitly disabled (rejectUnauthorized: false).",
                                reachability="reachable",
                                recommended_fix="Set rejectUnauthorized: true and remove NODE_TLS_REJECT_UNAUTHORIZED='0'.",
                            )
                        )

                # Check new Function(...)
                if node.type == "new_expression":
                    ctor = node.child_by_field_name("constructor")
                    if ctor and node_text(ctor, raw) == "Function":
                        findings.append(
                            Finding(
                                finding_id=make_finding_id("JS-EVAL-001", rel, lineno),
                                rule_id="JS-EVAL-001",
                                cwe_id="CWE-95",
                                title="Dynamic Code Evaluation",
                                category="sast",
                                severity="high",
                                file_path=rel,
                                start_line=lineno,
                                end_line=lineno,
                                snippet=extract_snippet(lines, lineno, lineno),
                                message="Use of new Function() risks arbitrary code execution.",
                                reachability="reachable",
                                recommended_fix="Replace dynamic evaluation with JSON.parse() or explicit dispatch logic.",
                            )
                        )

                if node.type != "call_expression":
                    continue

                fn_node = node.child_by_field_name("function")
                args_node = node.child_by_field_name("arguments")
                if fn_node is None:
                    continue
                fn_txt = node_text(fn_node, raw)
                arg_nodes = list(args_node.named_children) if args_node else []
                tail = fn_txt.rsplit(".", 1)[-1]

                # JS-EVAL-001: eval(...)
                if fn_txt == "eval":
                    findings.append(
                        Finding(
                            finding_id=make_finding_id("JS-EVAL-001", rel, lineno),
                            rule_id="JS-EVAL-001",
                            cwe_id="CWE-95",
                            title="Dynamic Code Evaluation",
                            category="sast",
                            severity="high",
                            file_path=rel,
                            start_line=lineno,
                            end_line=lineno,
                            snippet=extract_snippet(lines, lineno, lineno),
                            message="Use of eval() risks arbitrary code execution.",
                            reachability="reachable",
                            recommended_fix="Replace dynamic evaluation with JSON.parse() or explicit dispatch logic.",
                        )
                    )

                # JS-CMD-001: child_process exec / execSync with dynamic template or concatenation
                if tail in ("exec", "execSync") and arg_nodes:
                    first = arg_nodes[0]
                    first_txt = node_text(first, raw)
                    receiver = fn_txt.rsplit(".", 1)[0] if "." in fn_txt else ""
                    non_shell_receivers = {"r", "db", "knex", "pool", "conn", "connection", "stmt", "re", "regex"}
                    shell_receivers = {"", "cp", "child_process", "childprocess", "shell"}
                    is_child_process_call = (
                        tail == "execSync"
                        or has_child_process
                        or receiver.lower() in shell_receivers
                    )
                    is_sql_orm = (
                        receiver.lower() in non_shell_receivers
                        or bool(re.match(r"""^[`'"\s]*(?:SELECT|INSERT|UPDATE|DELETE|CREATE|DROP|ALTER|PRAGMA)\b""", first_txt, re.IGNORECASE))
                    )
                    if (
                        is_child_process_call
                        and not is_sql_orm
                        and first.type in ("template_string", "binary_expression")
                        and _has_dynamic_arg(first, raw)
                    ):
                        findings.append(
                            Finding(
                                finding_id=make_finding_id("JS-CMD-001", rel, lineno),
                                rule_id="JS-CMD-001",
                                cwe_id="CWE-78",
                                title="Shell Command Interpolation in child_process",
                                category="sast",
                                severity="critical",
                                file_path=rel,
                                start_line=lineno,
                                end_line=lineno,
                                snippet=extract_snippet(lines, lineno, lineno),
                                message="Dynamic input is interpolated into exec()/execSync() shell execution.",
                                reachability="reachable",
                                recommended_fix="Use execFile() or execFileSync() with an explicit argument array.",
                            )
                        )

                # JS-SQL-001: .query(`SELECT ... ${x}`) / .execute(...)
                if tail in ("query", "execute") and arg_nodes:
                    first = arg_nodes[0]
                    first_txt = node_text(first, raw)
                    if (
                        first.type in ("template_string", "binary_expression")
                        and _has_dynamic_arg(first, raw)
                        and SQL_KW_RE.search(first_txt)
                    ):
                        findings.append(
                            Finding(
                                finding_id=make_finding_id("JS-SQL-001", rel, lineno),
                                rule_id="JS-SQL-001",
                                cwe_id="CWE-89",
                                title="SQL Query Template Interpolation",
                                category="sast",
                                severity="high",
                                file_path=rel,
                                start_line=lineno,
                                end_line=lineno,
                                snippet=extract_snippet(lines, lineno, lineno),
                                message="SQL query uses template literal or string concatenation interpolation.",
                                reachability="reachable",
                                recommended_fix="Use parameterized placeholders ($1, ?) with a values array.",
                            )
                        )

                # Track fs reads & dynamic path.join for JS-PATH-001
                if fn_txt in ("fs.readFile", "fs.readFileSync", "readFile", "readFileSync", "res.sendFile"):
                    has_fs_read = True
                if fn_txt == "path.join" and len(arg_nodes) >= 2:
                    if any(_has_dynamic_arg(a, raw) for a in arg_nodes[1:]):
                        path_join_lines.append(lineno)

                # JS-CORS-001: cors({ origin: '*'|true, credentials: true })
                if fn_txt == "cors" and arg_nodes and not cors_mw_emitted:
                    arg_txt = node_text(arg_nodes[0], raw)
                    if re.search(r"origin\s*:\s*(?:['\"]\*['\"]|true)", arg_txt) and re.search(
                        r"credentials\s*:\s*true", arg_txt
                    ):
                        cors_mw_emitted = True
                        findings.append(
                            Finding(
                                finding_id=make_finding_id("JS-CORS-001", rel, lineno),
                                rule_id="JS-CORS-001",
                                cwe_id="CWE-942",
                                title="Permissive CORS Origin Combined with Credentials",
                                category="sast",
                                severity="high",
                                file_path=rel,
                                start_line=lineno,
                                end_line=lineno,
                                snippet=extract_snippet(lines, lineno, lineno),
                                message="Wildcard or reflected CORS origin is enabled alongside credentials: true.",
                                reachability="reachable",
                                recommended_fix="Restrict CORS origin to an explicit allowlist of trusted origins.",
                            )
                        )

                # JS-CORS-001: setHeader('Access-Control-Allow-Origin', ...)
                if tail in ("setHeader", "header", "set") and len(arg_nodes) >= 2:
                    hname = _strip_quotes(node_text(arg_nodes[0], raw)).lower()
                    hval = node_text(arg_nodes[1], raw).strip()
                    if hname == "access-control-allow-origin" and (
                        _strip_quotes(hval) == "*"
                        or "req.headers.origin" in hval
                        or hval == "origin"
                    ):
                        cors_wildcard_lines.append(lineno)
                    elif hname == "access-control-allow-credentials" and _strip_quotes(hval).lower() == "true":
                        has_cors_creds_header = True

                # JS-SSRF-001: Tainted URL passed to fetch / axios / http.get / https.get / got
                if fn_txt in ("fetch", "globalThis.fetch", "got", "http.get", "https.get", "http.request", "https.request") or fn_txt.startswith("axios."):
                    if arg_nodes and _has_dynamic_arg(arg_nodes[0], raw):
                        ssrf_src = taint.is_tainted(arg_nodes[0], "ssrf")
                        if ssrf_src:
                            findings.append(
                                Finding(
                                    finding_id=make_finding_id("JS-SSRF-001", rel, lineno),
                                    rule_id="JS-SSRF-001",
                                    cwe_id="CWE-918",
                                    title="Server-Side Request Forgery (SSRF)",
                                    category="sast",
                                    severity="high",
                                    file_path=rel,
                                    start_line=lineno,
                                    end_line=lineno,
                                    snippet=extract_snippet(lines, lineno, lineno),
                                    message=f"{fn_txt}() fetches a user-controlled URL (source: {ssrf_src}) without host allowlisting.",
                                    reachability="reachable",
                                    recommended_fix="Validate protocol (https:) and enforce an explicit hostname allowlist rejecting private/metadata IPs.",
                                    metadata={"taint_source": ssrf_src},
                                )
                            )

                # JS-JWT-001: jwt.decode() without verify or algorithms: ['none']
                if fn_txt == "jwt.decode" and not has_jwt_verify:
                    findings.append(
                        Finding(
                            finding_id=make_finding_id("JS-JWT-001", rel, lineno),
                            rule_id="JS-JWT-001",
                            cwe_id="CWE-347",
                            title="Unverified JWT Decode",
                            category="sast",
                            severity="high",
                            file_path=rel,
                            start_line=lineno,
                            end_line=lineno,
                            snippet=extract_snippet(lines, lineno, lineno),
                            message="jwt.decode() parses JWT claims without verifying the cryptographic signature.",
                            reachability="reachable",
                            recommended_fix="Use jwt.verify(token, secret, { algorithms: ['HS256'] }) instead of jwt.decode().",
                        )
                    )
                elif fn_txt == "jwt.verify" and len(arg_nodes) >= 3:
                    opts_txt = node_text(arg_nodes[2], raw).lower()
                    if re.search(r"""algorithms\s*:\s*\[\s*['"]none['"]""", opts_txt):
                        findings.append(
                            Finding(
                                finding_id=make_finding_id("JS-JWT-001", rel, lineno),
                                rule_id="JS-JWT-001",
                                cwe_id="CWE-347",
                                title="JWT Verification Allows alg=none",
                                category="sast",
                                severity="critical",
                                file_path=rel,
                                start_line=lineno,
                                end_line=lineno,
                                snippet=extract_snippet(lines, lineno, lineno),
                                message="jwt.verify() allows the unsigned 'none' algorithm.",
                                reachability="reachable",
                                recommended_fix="Restrict algorithms to strong algorithms such as ['HS256'] or ['RS256'].",
                            )
                        )

                # JS-SECRET-001: Hardcoded Express session({ secret: "..." }) or jwt.sign(p, "...")
                if fn_txt == "session" and arg_nodes:
                    stxt = node_text(arg_nodes[0], raw)
                    m_sec = re.search(r"""secret\s*:\s*['"]([^'"]{6,})['"]""", stxt)
                    if m_sec and "redacted_by_vulnbox" not in m_sec.group(1).lower():
                        findings.append(
                            Finding(
                                finding_id=make_finding_id("JS-SECRET-001", rel, lineno),
                                rule_id="JS-SECRET-001",
                                cwe_id="CWE-798",
                                title="Hardcoded Express Session Secret",
                                category="sast",
                                severity="high",
                                file_path=rel,
                                start_line=lineno,
                                end_line=lineno,
                                snippet=extract_snippet(lines, lineno, lineno),
                                message="Hardcoded session secret literal allows offline session cookie forgery.",
                                reachability="reachable",
                                recommended_fix="Read the session secret from process.env.SESSION_SECRET.",
                            )
                        )
                elif fn_txt == "jwt.sign" and len(arg_nodes) >= 2 and arg_nodes[1].type == "string":
                    lit = _strip_quotes(node_text(arg_nodes[1], raw))
                    if len(lit) >= 6 and "redacted_by_vulnbox" not in lit.lower():
                        findings.append(
                            Finding(
                                finding_id=make_finding_id("JS-SECRET-001", rel, lineno),
                                rule_id="JS-SECRET-001",
                                cwe_id="CWE-798",
                                title="Hardcoded JWT Signing Secret",
                                category="sast",
                                severity="high",
                                file_path=rel,
                                start_line=lineno,
                                end_line=lineno,
                                snippet=extract_snippet(lines, lineno, lineno),
                                message="Hardcoded string literal passed to jwt.sign() enables token forgery.",
                                reachability="reachable",
                                recommended_fix="Load the JWT signing key from process.env.JWT_SECRET.",
                            )
                        )

                # JS-RAND-001: Math.random() used in security token/secret contexts
                if fn_txt == "Math.random":
                    ctx_line = (lines[lineno - 1] if 1 <= lineno <= len(lines) else "").lower()
                    if any(h in ctx_line for h in _JS_SEC_RANDOM_HINTS):
                        findings.append(
                            Finding(
                                finding_id=make_finding_id("JS-RAND-001", rel, lineno),
                                rule_id="JS-RAND-001",
                                cwe_id="CWE-338",
                                title="Insecure Math.random() Used for Security Token",
                                category="sast",
                                severity="medium",
                                file_path=rel,
                                start_line=lineno,
                                end_line=lineno,
                                snippet=extract_snippet(lines, lineno, lineno),
                                message="Math.random() is not cryptographically secure for tokens, nonces, or passwords.",
                                reachability="reachable",
                                recommended_fix="Use crypto.randomBytes(32).toString('hex') or crypto.randomUUID().",
                            )
                        )

                # JS-XSS-001: document.write(dynamic) or res.send(tainted HTML)
                if fn_txt == "document.write" and arg_nodes and _has_dynamic_arg(arg_nodes[0], raw):
                    findings.append(
                        Finding(
                            finding_id=make_finding_id("JS-XSS-001", rel, lineno),
                            rule_id="JS-XSS-001",
                            cwe_id="CWE-79",
                            title="DOM XSS via document.write()",
                            category="sast",
                            severity="high",
                            file_path=rel,
                            start_line=lineno,
                            end_line=lineno,
                            snippet=extract_snippet(lines, lineno, lineno),
                            message="Dynamic content written to document.write() risks cross-site scripting.",
                            reachability="reachable",
                            recommended_fix="Avoid document.write(); render text nodes via textContent.",
                        )
                    )
                elif fn_txt in ("res.send", "res.end") and arg_nodes:
                    arg_txt = node_text(arg_nodes[0], raw)
                    if ("<" in arg_txt and ">" in arg_txt) and taint.is_tainted(arg_nodes[0], "xss"):
                        findings.append(
                            Finding(
                                finding_id=make_finding_id("JS-XSS-001", rel, lineno),
                                rule_id="JS-XSS-001",
                                cwe_id="CWE-79",
                                title="Reflected XSS in Unescaped HTTP Response",
                                category="sast",
                                severity="high",
                                file_path=rel,
                                start_line=lineno,
                                end_line=lineno,
                                snippet=extract_snippet(lines, lineno, lineno),
                                message=f"{fn_txt}() interpolates untrusted request input directly into HTML.",
                                reachability="reachable",
                                recommended_fix="HTML-escape untrusted values or return JSON with Content-Type: application/json.",
                            )
                        )

                # JS-NOSQL-001: Mongo/Mongoose $where or raw req.body/req.query passed to .find()/.findOne()
                if tail in ("find", "findOne", "updateOne", "deleteOne") and arg_nodes:
                    q_txt = node_text(arg_nodes[0], raw)
                    is_where = "$where" in q_txt and _has_dynamic_arg(arg_nodes[0], raw)
                    is_raw_req = q_txt.strip() in ("req.body", "req.query", "request.body", "request.query")
                    if is_where or is_raw_req:
                        findings.append(
                            Finding(
                                finding_id=make_finding_id("JS-NOSQL-001", rel, lineno),
                                rule_id="JS-NOSQL-001",
                                cwe_id="CWE-943",
                                title="NoSQL Query Injection",
                                category="sast",
                                severity="high",
                                file_path=rel,
                                start_line=lineno,
                                end_line=lineno,
                                snippet=extract_snippet(lines, lineno, lineno),
                                message="Unsanitized request object or dynamic $where expression passed to NoSQL query.",
                                reachability="reachable",
                                recommended_fix="Explicitly pick and type-check scalar fields (String(req.body.username)) and disallow $where.",
                            )
                        )

                # JS-REDIR-001: Open redirect via res.redirect(tainted)
                if fn_txt == "res.redirect" and arg_nodes:
                    target_arg = arg_nodes[1] if len(arg_nodes) >= 2 else arg_nodes[0]
                    if _has_dynamic_arg(target_arg, raw):
                        redir_src = taint.is_tainted(target_arg, "redirect")
                        if redir_src:
                            findings.append(
                                Finding(
                                    finding_id=make_finding_id("JS-REDIR-001", rel, lineno),
                                    rule_id="JS-REDIR-001",
                                    cwe_id="CWE-601",
                                    title="Open Redirect via User-Controlled Target",
                                    category="sast",
                                    severity="medium",
                                    file_path=rel,
                                    start_line=lineno,
                                    end_line=lineno,
                                    snippet=extract_snippet(lines, lineno, lineno),
                                    message=f"res.redirect() redirects to user-controlled input (source: {redir_src}).",
                                    reachability="reachable",
                                    recommended_fix="Validate target starts with '/' (not '//') or matches an explicit host allowlist.",
                                    metadata={"taint_source": redir_src},
                                )
                            )

            if not has_path_confinement and has_fs_read and path_join_lines:
                first_line = path_join_lines[0]
                findings.append(
                    Finding(
                        finding_id=make_finding_id("JS-PATH-001", rel, first_line),
                        rule_id="JS-PATH-001",
                        cwe_id="CWE-22",
                        title="Unconstrained path.join Before File Read",
                        category="sast",
                        severity="high",
                        file_path=rel,
                        start_line=first_line,
                        end_line=first_line,
                        snippet=extract_snippet(lines, first_line, first_line),
                        message="File path built with path.join() is read without verifying it remains inside the allowed root directory.",
                        reachability="reachable",
                        recommended_fix="Resolve both root and target paths with path.resolve() and verify resolvedPath.startsWith(rootDir + path.sep).",
                    )
                )

            if not cors_mw_emitted and cors_wildcard_lines and has_cors_creds_header and not has_origin_allowlist:
                first_line = cors_wildcard_lines[0]
                findings.append(
                    Finding(
                        finding_id=make_finding_id("JS-CORS-001", rel, first_line),
                        rule_id="JS-CORS-001",
                        cwe_id="CWE-942",
                        title="Permissive CORS Header Combined with Credentials",
                        category="sast",
                        severity="high",
                        file_path=rel,
                        start_line=first_line,
                        end_line=first_line,
                        snippet=extract_snippet(lines, first_line, first_line),
                        message="Access-Control-Allow-Origin reflects arbitrary/wildcard origin while Access-Control-Allow-Credentials is true.",
                        reachability="reachable",
                        recommended_fix="Check the Origin header against an explicit allowlist before setting Access-Control-Allow-Origin.",
                    )
                )

        return findings
