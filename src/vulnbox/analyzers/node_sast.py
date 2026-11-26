"""Deterministic JavaScript / TypeScript security analyzer."""

from __future__ import annotations

import re
from pathlib import Path

from vulnbox.analyzers.base import extract_snippet, iter_source_files, make_finding_id
from vulnbox.models import Finding

CMD_EXEC_RE = re.compile(r"\b(?:exec|execSync)\s*\(\s*(?:`[^`]*\$\{|[^)]*\+)")
EVAL_RE = re.compile(r"\b(?:eval\s*\(|new\s+Function\s*\()")
SQL_TEMPLATE_RE = re.compile(
    r"\.(?:query|execute)\s*\(\s*`[^`]*(?:SELECT|INSERT|UPDATE|DELETE)[^`]*\$\{",
    re.IGNORECASE,
)
PATH_JOIN_RE = re.compile(r"\bpath\.join\s*\(")
FS_READ_RE = re.compile(r"\b(?:fs\.readFile(?:Sync)?|readFile(?:Sync)?|res\.sendFile)\s*\(")
TLS_REJECT_FALSE_RE = re.compile(
    r"rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['\"]0['\"]"
)
CORS_WILDCARD_HEADER_RE = re.compile(
    r"""['"]Access-Control-Allow-Origin['"]\s*,\s*(?:['"]\*['"]|req\.headers\.origin|origin)"""
)
CORS_CREDS_HEADER_RE = re.compile(
    r"""['"]Access-Control-Allow-Credentials['"]\s*,\s*['"]true['"]"""
)
CORS_MW_RE = re.compile(
    r"cors\s*\(\s*\{[^}]*origin\s*:\s*(?:['\"]\*['\"]|true)[^}]*credentials\s*:\s*true",
    re.DOTALL,
)


class NodeSASTAnalyzer:
    """Runs deterministic security pattern analysis over JavaScript and TypeScript files."""

    name = "node-sast"

    def analyze(self, workspace_dir: Path) -> list[Finding]:
        findings: list[Finding] = []
        for js_file in iter_source_files(workspace_dir, (".js", ".mjs", ".cjs", ".ts")):
            try:
                source = js_file.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            rel = str(js_file.relative_to(workspace_dir))
            lines = source.splitlines()

            for idx, line in enumerate(lines, start=1):
                if CMD_EXEC_RE.search(line):
                    findings.append(
                        Finding(
                            finding_id=make_finding_id("JS-CMD-001", rel, idx),
                            rule_id="JS-CMD-001",
                            cwe_id="CWE-78",
                            title="Shell Command Interpolation in child_process",
                            category="sast",
                            severity="critical",
                            file_path=rel,
                            start_line=idx,
                            end_line=idx,
                            snippet=extract_snippet(lines, idx, idx),
                            message="Dynamic input is interpolated into exec()/execSync() shell execution.",
                            reachability="reachable",
                            recommended_fix="Use execFile() or execFileSync() with an explicit argument array.",
                        )
                    )

                if EVAL_RE.search(line):
                    findings.append(
                        Finding(
                            finding_id=make_finding_id("JS-EVAL-001", rel, idx),
                            rule_id="JS-EVAL-001",
                            cwe_id="CWE-95",
                            title="Dynamic Code Evaluation",
                            category="sast",
                            severity="high",
                            file_path=rel,
                            start_line=idx,
                            end_line=idx,
                            snippet=extract_snippet(lines, idx, idx),
                            message="Use of eval() or new Function() risks arbitrary code execution.",
                            reachability="reachable",
                            recommended_fix="Replace dynamic evaluation with JSON.parse() or explicit dispatch logic.",
                        )
                    )

                if SQL_TEMPLATE_RE.search(line):
                    findings.append(
                        Finding(
                            finding_id=make_finding_id("JS-SQL-001", rel, idx),
                            rule_id="JS-SQL-001",
                            cwe_id="CWE-89",
                            title="SQL Query Template Interpolation",
                            category="sast",
                            severity="high",
                            file_path=rel,
                            start_line=idx,
                            end_line=idx,
                            snippet=extract_snippet(lines, idx, idx),
                            message="SQL query uses template literal interpolation.",
                            reachability="reachable",
                            recommended_fix="Use parameterized placeholders ($1, ?) with a values array.",
                        )
                    )

                if TLS_REJECT_FALSE_RE.search(line):
                    findings.append(
                        Finding(
                            finding_id=make_finding_id("JS-TLS-001", rel, idx),
                            rule_id="JS-TLS-001",
                            cwe_id="CWE-295",
                            title="TLS Certificate Validation Disabled",
                            category="sast",
                            severity="medium",
                            file_path=rel,
                            start_line=idx,
                            end_line=idx,
                            snippet=extract_snippet(lines, idx, idx),
                            message="TLS certificate validation is explicitly disabled.",
                            reachability="reachable",
                            recommended_fix="Set rejectUnauthorized: true and remove NODE_TLS_REJECT_UNAUTHORIZED='0'.",
                        )
                    )

            # File-level path confinement check (JS-PATH-001)
            has_confinement = (
                "path.resolve(" in source
                and (".startsWith(" in source or "path.relative(" in source)
            )
            if not has_confinement and FS_READ_RE.search(source):
                static_join_re = re.compile(r"""\bpath\.join\s*\([^,]+,\s*['"][^'"]+['"]\s*\)""")
                for idx, line in enumerate(lines, start=1):
                    if PATH_JOIN_RE.search(line) and not static_join_re.search(line):
                        findings.append(
                            Finding(
                                finding_id=make_finding_id("JS-PATH-001", rel, idx),
                                rule_id="JS-PATH-001",
                                cwe_id="CWE-22",
                                title="Unconstrained path.join Before File Read",
                                category="sast",
                                severity="high",
                                file_path=rel,
                                start_line=idx,
                                end_line=idx,
                                snippet=extract_snippet(lines, idx, idx),
                                message="File path built with path.join() is read without verifying it remains inside the allowed root directory.",
                                reachability="reachable",
                                recommended_fix="Resolve both root and target paths with path.resolve() and verify resolvedPath.startsWith(rootDir + path.sep).",
                            )
                        )
                        break

            # Permissive CORS with credentials check (JS-CORS-001)
            cors_match = CORS_MW_RE.search(source)
            if cors_match:
                line_no = source[: cors_match.start()].count("\n") + 1
                findings.append(
                    Finding(
                        finding_id=make_finding_id("JS-CORS-001", rel, line_no),
                        rule_id="JS-CORS-001",
                        cwe_id="CWE-942",
                        title="Permissive CORS Origin Combined with Credentials",
                        category="sast",
                        severity="high",
                        file_path=rel,
                        start_line=line_no,
                        end_line=line_no,
                        snippet=extract_snippet(lines, line_no, line_no),
                        message="Wildcard or reflected CORS origin is enabled alongside credentials: true.",
                        reachability="reachable",
                        recommended_fix="Restrict CORS origin to an explicit allowlist of trusted origins.",
                    )
                )
            elif CORS_WILDCARD_HEADER_RE.search(source) and CORS_CREDS_HEADER_RE.search(source):
                has_origin_allowlist = (
                    "_allowedOrigins" in source
                    or "allowedOrigins" in source
                    or ".has(req.headers.origin)" in source
                    or ".includes(req.headers.origin)" in source
                )
                if not has_origin_allowlist:
                    for idx, line in enumerate(lines, start=1):
                        if CORS_WILDCARD_HEADER_RE.search(line):
                            findings.append(
                                Finding(
                                    finding_id=make_finding_id("JS-CORS-001", rel, idx),
                                    rule_id="JS-CORS-001",
                                    cwe_id="CWE-942",
                                    title="Permissive CORS Header Combined with Credentials",
                                    category="sast",
                                    severity="high",
                                    file_path=rel,
                                    start_line=idx,
                                    end_line=idx,
                                    snippet=extract_snippet(lines, idx, idx),
                                    message="Access-Control-Allow-Origin reflects arbitrary/wildcard origin while Access-Control-Allow-Credentials is true.",
                                    reachability="reachable",
                                    recommended_fix="Check the Origin header against an explicit allowlist before setting Access-Control-Allow-Origin.",
                                )
                            )
                            break

        return findings
