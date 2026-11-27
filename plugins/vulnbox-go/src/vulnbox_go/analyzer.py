"""Deterministic Go SAST security analyzer plugin for VulnBox.

Detects high-signal Go vulnerability classes:
  - GO-CMD-001 (CWE-78): Shell command execution via exec.Command("sh"|"bash", "-c", dynamic)
  - GO-SQL-001 (CWE-89): SQL query built via fmt.Sprintf / string concatenation
  - GO-TLS-001 (CWE-295): tls.Config{InsecureSkipVerify: true}
  - GO-PATH-001 (CWE-22): filepath.Join() + os.ReadFile()/os.Open() without prefix confinement
  - GO-SSRF-001 (CWE-918): http.Get() / http.NewRequest() fed from r.URL.Query() / r.FormValue()
"""

from __future__ import annotations

import re
from pathlib import Path

from vulnbox.analyzers.base import extract_snippet, iter_source_files, make_finding_id
from vulnbox.models import Finding
from vulnbox.registry import AnalysisContext

_GO_SHELL_CMD_RE = re.compile(
    r"""exec\.Command(?:Context)?\s*\([^)]*["'](?:sh|bash|/bin/sh|/bin/bash)["']\s*,\s*["']-c["']\s*,\s*([^)]+)\)"""
)
_GO_SQL_FMT_RE = re.compile(
    r"""\.(?:Query|QueryRow|Exec)(?:Context)?\s*\([^)]*(?:fmt\.Sprintf\s*\(\s*["'`][^"'`]*(?:SELECT|INSERT|UPDATE|DELETE)|["'`][^"'`]*(?:SELECT|INSERT|UPDATE|DELETE)[^"'`]*["'`]\s*\+)""",
    re.IGNORECASE,
)
_GO_TLS_SKIP_RE = re.compile(r"""InsecureSkipVerify\s*:\s*true\b""")
_GO_SSRF_RE = re.compile(
    r"""http\.(?:Get|Post|Head|NewRequest)\s*\([^)]*(?:r\.URL\.Query\(\)\.Get|r\.FormValue|targetURL|userURL)""",
)
_GO_PATH_JOIN_RE = re.compile(r"""filepath\.Join\s*\(""")
_GO_FILE_READ_RE = re.compile(r"""(?:os|ioutil)\.(?:ReadFile|Open)\s*\(""")


class GoSASTAnalyzer:
    """Static security analyzer for Go source files (skipping *_test.go and vendor/)."""

    name = "go-sast"

    def analyze(self, workspace_dir: Path) -> list[Finding]:
        findings: list[Finding] = []
        for go_file in iter_source_files(workspace_dir, (".go",)):
            if go_file.name.endswith("_test.go"):
                continue
            try:
                source = go_file.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            rel = str(go_file.relative_to(workspace_dir))
            lines = source.splitlines()

            for lineno, line in enumerate(lines, start=1):
                stripped = line.strip()
                if stripped.startswith("//"):
                    continue

                m_cmd = _GO_SHELL_CMD_RE.search(line)
                if m_cmd and not re.match(r"""^["'`][^"'`]*["'`]$""", m_cmd.group(1).strip()):
                    findings.append(
                        Finding(
                            finding_id=make_finding_id("GO-CMD-001", rel, lineno),
                            rule_id="GO-CMD-001",
                            cwe_id="CWE-78",
                            title="Go Shell Command Injection via exec.Command",
                            category="sast",
                            severity="critical",
                            file_path=rel,
                            start_line=lineno,
                            end_line=lineno,
                            snippet=extract_snippet(lines, lineno, lineno),
                            message="Dynamic input passed to exec.Command('sh', '-c', ...) allows shell command injection.",
                            reachability="reachable",
                            recommended_fix="Invoke the target binary directly via exec.Command(bin, arg1, arg2) without a shell.",
                        )
                    )

                if _GO_SQL_FMT_RE.search(line):
                    findings.append(
                        Finding(
                            finding_id=make_finding_id("GO-SQL-001", rel, lineno),
                            rule_id="GO-SQL-001",
                            cwe_id="CWE-89",
                            title="Go SQL Query String Interpolation",
                            category="sast",
                            severity="high",
                            file_path=rel,
                            start_line=lineno,
                            end_line=lineno,
                            snippet=extract_snippet(lines, lineno, lineno),
                            message="SQL query constructed with fmt.Sprintf() or string concatenation instead of placeholders.",
                            reachability="reachable",
                            recommended_fix="Use parameterized queries: db.Query('SELECT ... WHERE id = $1', id).",
                        )
                    )

                if _GO_TLS_SKIP_RE.search(line):
                    findings.append(
                        Finding(
                            finding_id=make_finding_id("GO-TLS-001", rel, lineno),
                            rule_id="GO-TLS-001",
                            cwe_id="CWE-295",
                            title="Go TLS Certificate Verification Disabled",
                            category="sast",
                            severity="medium",
                            file_path=rel,
                            start_line=lineno,
                            end_line=lineno,
                            snippet=extract_snippet(lines, lineno, lineno),
                            message="tls.Config sets InsecureSkipVerify: true, disabling TLS certificate validation.",
                            reachability="reachable",
                            recommended_fix="Remove InsecureSkipVerify: true or provide a custom RootCAs cert pool.",
                        )
                    )

                if _GO_SSRF_RE.search(line):
                    findings.append(
                        Finding(
                            finding_id=make_finding_id("GO-SSRF-001", rel, lineno),
                            rule_id="GO-SSRF-001",
                            cwe_id="CWE-918",
                            title="Go Server-Side Request Forgery (SSRF)",
                            category="sast",
                            severity="high",
                            file_path=rel,
                            start_line=lineno,
                            end_line=lineno,
                            snippet=extract_snippet(lines, lineno, lineno),
                            message="User-controlled HTTP request input passed directly to net/http client.",
                            reachability="reachable",
                            recommended_fix="Validate URL scheme/host against an allowlist and block private/metadata IP ranges in a custom DialContext.",
                        )
                    )

            # File-level check for unconstrained filepath.Join + os.ReadFile / os.Open
            if _GO_PATH_JOIN_RE.search(source) and _GO_FILE_READ_RE.search(source):
                has_confine = "strings.HasPrefix(" in source and (
                    "filepath.Abs(" in source or "filepath.Rel(" in source
                )
                if not has_confine:
                    for lineno, line in enumerate(lines, start=1):
                        if _GO_PATH_JOIN_RE.search(line) and not line.strip().startswith("//"):
                            findings.append(
                                Finding(
                                    finding_id=make_finding_id("GO-PATH-001", rel, lineno),
                                    rule_id="GO-PATH-001",
                                    cwe_id="CWE-22",
                                    title="Go Unconstrained filepath.Join Before File Read",
                                    category="sast",
                                    severity="high",
                                    file_path=rel,
                                    start_line=lineno,
                                    end_line=lineno,
                                    snippet=extract_snippet(lines, lineno, lineno),
                                    message="filepath.Join() result is read without verifying the resolved path stays inside the allowed root.",
                                    reachability="reachable",
                                    recommended_fix="Resolve with filepath.Abs() and verify strings.HasPrefix(target, baseDir + string(os.PathSeparator)).",
                                )
                            )
                            break

        return findings


class GoSASTPlugin:
    """VulnBox AnalyzerPlugin adapter for GoSASTAnalyzer."""

    name = "go-sast"

    def run(self, ctx: AnalysisContext) -> list[Finding]:
        return GoSASTAnalyzer().analyze(ctx.workspace_dir)
