"""Deterministic Tree-sitter AST JavaScript / TypeScript security analyzer."""

from __future__ import annotations

import re
from pathlib import Path

from vulnbox.analyzers.base import extract_snippet, iter_source_files, make_finding_id
from vulnbox.callgraph.ts_utils import node_text, parse_source, walk_nodes
from vulnbox.models import Finding

SQL_KW_RE = re.compile(r"\b(?:SELECT|INSERT|UPDATE|DELETE)\b", re.IGNORECASE)
JS_EXTS = (".js", ".mjs", ".cjs", ".ts", ".tsx")


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
            try:
                source = js_file.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            tree, raw = parse_source(source, js_file.suffix)
            if tree is None:
                continue
            rel = str(js_file.relative_to(workspace_dir))
            lines = source.splitlines()

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

                # Check NODE_TLS_REJECT_UNAUTHORIZED = '0'
                if node.type == "assignment_expression":
                    left = node.child_by_field_name("left")
                    right = node.child_by_field_name("right")
                    if (
                        left
                        and right
                        and "NODE_TLS_REJECT_UNAUTHORIZED" in node_text(left, raw)
                        and _strip_quotes(node_text(right, raw)) == "0"
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

                # JS-CMD-001: exec / execSync with dynamic template or concatenation
                if tail in ("exec", "execSync") and arg_nodes:
                    first = arg_nodes[0]
                    if first.type in ("template_string", "binary_expression") and _has_dynamic_arg(first, raw):
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
