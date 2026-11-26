"""Configuration, Dockerfile, and secret-hygiene analyzer."""

from __future__ import annotations

import re
from pathlib import Path

from vulnbox.analyzers.base import SKIP_DIRS, extract_snippet, make_finding_id
from vulnbox.models import Finding, ScrubSummary

FROM_RE = re.compile(r"^\s*FROM\s+([^\s]+)", re.IGNORECASE)
USER_RE = re.compile(r"^\s*USER\s+([^\s]+)", re.IGNORECASE)
ENV_SECRET_RE = re.compile(
    r"^\s*(?:ENV|ARG)\s+([A-Z0-9_]*(?:SECRET|PASSWORD|TOKEN|API_KEY|PRIVATE_KEY)[A-Z0-9_]*)\s*[=\s]+(.+)",
    re.IGNORECASE,
)
ADD_URL_RE = re.compile(r"^\s*ADD\s+https?://", re.IGNORECASE)
CHMOD_777_RE = re.compile(r"\bchmod\s+(?:-R\s+)?0?777\b|0o777")


class ConfigHygieneAnalyzer:
    """Checks Dockerfiles, permissions, and secret hygiene in a repository."""

    name = "config-hygiene"

    def analyze(
        self,
        workspace_dir: Path,
        scrub_summary: ScrubSummary | None = None,
    ) -> list[Finding]:
        findings: list[Finding] = []

        # 1. Inspect Dockerfiles
        for path in sorted(workspace_dir.rglob("*")):
            if not path.is_file():
                continue
            rel = path.relative_to(workspace_dir)
            if any(part in SKIP_DIRS for part in rel.parts):
                continue

            if path.name == "Dockerfile" or path.name.startswith("Dockerfile."):
                findings.extend(self._analyze_dockerfile(path, str(rel)))
            elif path.suffix.lower() in (".sh", ".py", ".js", ".mjs", ".yml", ".yaml"):
                findings.extend(self._analyze_permissions(path, str(rel)))

        # 2. Report committed secret files / redacted tokens detected during scrubbing
        if scrub_summary:
            for rel_file in scrub_summary.files_scrubbed:
                fname = Path(rel_file).name
                if fname.lower().startswith(".env") or fname.lower().endswith((".pem", ".key")):
                    findings.append(
                        Finding(
                            finding_id=make_finding_id("CFG-SECRET-001", rel_file, 1),
                            rule_id="CFG-SECRET-001",
                            cwe_id="CWE-798",
                            title="Sensitive Environment or Key File Present in Repository",
                            category="secret",
                            severity="high",
                            file_path=rel_file,
                            start_line=1,
                            end_line=1,
                            snippet=f"{rel_file} (scrubbed before sandbox execution)",
                            message=f"Sensitive file '{rel_file}' was present in the repository and scrubbed before sandbox execution.",
                            reachability="not_applicable",
                            recommended_fix="Remove real secret files from version control, add them to .gitignore, and provide a sanitized .env.example instead.",
                        )
                    )
                else:
                    findings.append(
                        Finding(
                            finding_id=make_finding_id("CFG-SECRET-002", rel_file, 1),
                            rule_id="CFG-SECRET-002",
                            cwe_id="CWE-798",
                            title="Hardcoded Credential Token Detected in Source",
                            category="secret",
                            severity="critical",
                            file_path=rel_file,
                            start_line=1,
                            end_line=1,
                            snippet=f"{rel_file} (token redacted by VulnBox scrubber)",
                            message=f"High-confidence credential token detected in '{rel_file}' and redacted inside the sandbox.",
                            reachability="not_applicable",
                            recommended_fix="Rotate the exposed credential immediately and load it from a secret manager or runtime environment variable.",
                        )
                    )

        return findings

    def _analyze_dockerfile(self, path: Path, rel: str) -> list[Finding]:
        findings: list[Finding] = []
        try:
            lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
        except OSError:
            return findings

        last_user: str | None = None
        last_user_line = 1

        for idx, line in enumerate(lines, start=1):
            from_m = FROM_RE.match(line)
            if from_m:
                image = from_m.group(1)
                if ":" not in image or image.endswith(":latest"):
                    findings.append(
                        Finding(
                            finding_id=make_finding_id("CFG-DOCKER-002", rel, idx),
                            rule_id="CFG-DOCKER-002",
                            cwe_id="CWE-829",
                            title="Unpinned Container Base Image Tag",
                            category="config",
                            severity="medium",
                            file_path=rel,
                            start_line=idx,
                            end_line=idx,
                            snippet=extract_snippet(lines, idx, idx),
                            message=f"Base image '{image}' is unpinned or uses ':latest'.",
                            recommended_fix="Pin the base image to an explicit minor version tag or immutable SHA256 digest.",
                            metadata={"image": image},
                        )
                    )

            user_m = USER_RE.match(line)
            if user_m:
                last_user = user_m.group(1).strip()
                last_user_line = idx

            if ENV_SECRET_RE.match(line):
                findings.append(
                    Finding(
                        finding_id=make_finding_id("CFG-DOCKER-003", rel, idx),
                        rule_id="CFG-DOCKER-003",
                        cwe_id="CWE-798",
                        title="Secret Exposed in Dockerfile ENV/ARG",
                        category="config",
                        severity="high",
                        file_path=rel,
                        start_line=idx,
                        end_line=idx,
                        snippet=extract_snippet(lines, idx, idx),
                        message="Secrets passed via ENV or ARG are baked into container image metadata/layers.",
                        recommended_fix="Inject secrets at runtime via environment variables or Docker BuildKit --mount=type=secret.",
                    )
                )

            if ADD_URL_RE.match(line):
                findings.append(
                    Finding(
                        finding_id=make_finding_id("CFG-DOCKER-004", rel, idx),
                        rule_id="CFG-DOCKER-004",
                        cwe_id="CWE-494",
                        title="Remote Fetch via Dockerfile ADD",
                        category="config",
                        severity="medium",
                        file_path=rel,
                        start_line=idx,
                        end_line=idx,
                        snippet=extract_snippet(lines, idx, idx),
                        message="ADD with remote URLs bypasses checksum verification.",
                        recommended_fix="Use curl/wget with checksum verification inside a RUN step or COPY local artifacts.",
                    )
                )

        if last_user is None or last_user in ("root", "0", "0:0"):
            line_ref = last_user_line if last_user is not None else len(lines) or 1
            findings.append(
                Finding(
                    finding_id=make_finding_id("CFG-DOCKER-001", rel, line_ref),
                    rule_id="CFG-DOCKER-001",
                    cwe_id="CWE-250",
                    title="Container Runs as Root User",
                    category="config",
                    severity="high",
                    file_path=rel,
                    start_line=line_ref,
                    end_line=line_ref,
                    snippet=extract_snippet(lines, line_ref, line_ref),
                    message="Dockerfile does not switch to a non-root USER.",
                    recommended_fix="Create a non-root user and add 'USER appuser' before CMD/ENTRYPOINT.",
                )
            )

        return findings

    def _analyze_permissions(self, path: Path, rel: str) -> list[Finding]:
        findings: list[Finding] = []
        try:
            lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
        except OSError:
            return findings
        for idx, line in enumerate(lines, start=1):
            if CHMOD_777_RE.search(line):
                findings.append(
                    Finding(
                        finding_id=make_finding_id("CFG-PERM-001", rel, idx),
                        rule_id="CFG-PERM-001",
                        cwe_id="CWE-732",
                        title="World-Writable File Permissions (777)",
                        category="config",
                        severity="medium",
                        file_path=rel,
                        start_line=idx,
                        end_line=idx,
                        snippet=extract_snippet(lines, idx, idx),
                        message="Setting world-writable permissions (777/0o777) weakens filesystem isolation.",
                        recommended_fix="Use least-privilege permissions such as 0o750 or 0o640.",
                    )
                )
        return findings
