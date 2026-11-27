"""CI gating (--fail-on), stable finding baselines, and inline suppression parsing."""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any

from vulnbox.models import Finding

SEVERITY_RANK: dict[str, int] = {
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}

# Supports: `# vulnbox: ignore[PY-SQL-001, PY-PATH-001]` or `// vulnbox: ignore[JS-XSS-001]` or `ignore[*]`
INLINE_IGNORE_RE = re.compile(
    r"(?:#|//)\s*vulnbox\s*:\s*ignore\s*\[\s*([^\]]+)\s*\]",
    re.IGNORECASE,
)


def compute_finding_fingerprint(finding: Finding) -> str:
    """Compute a line-number-independent SHA-256 fingerprint for CI baselines & SARIF tracking."""
    norm_lines: list[str] = []
    for raw_line in (finding.snippet or "").splitlines():
        # Strip leading `123: ` line number prefixes emitted by extract_snippet()
        cleaned = re.sub(r"^\s*\d+:\s?", "", raw_line).strip()
        if cleaned:
            norm_lines.append(cleaned)
    norm_code = "\n".join(norm_lines) if norm_lines else finding.title
    payload = f"{finding.rule_id}|{finding.file_path}|{norm_code}"
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:24]


def _rules_ignored_on_line(line: str) -> set[str]:
    m = INLINE_IGNORE_RE.search(line)
    if not m:
        return set()
    return {tok.strip().upper() for tok in m.group(1).split(",") if tok.strip()}


def apply_inline_suppressions(
    findings: list[Finding],
    workspace_dir: Path,
) -> tuple[list[Finding], list[dict[str, Any]]]:
    """Filter findings suppressed via `# vulnbox: ignore[RULE-ID]` or `// vulnbox: ignore[RULE-ID]`."""
    file_cache: dict[str, list[str]] = {}
    active: list[Finding] = []
    suppressed: list[dict[str, Any]] = []

    for f in findings:
        rel = f.file_path
        if rel not in file_cache:
            fpath = workspace_dir / rel
            try:
                file_cache[rel] = (
                    fpath.read_text(encoding="utf-8", errors="ignore").splitlines()
                    if fpath.is_file()
                    else []
                )
            except OSError:
                file_cache[rel] = []

        lines = file_cache[rel]
        ignored_rules: set[str] = set()
        for check_line in (f.start_line, f.start_line - 1):
            if 1 <= check_line <= len(lines):
                ignored_rules.update(_rules_ignored_on_line(lines[check_line - 1]))

        if "*" in ignored_rules or f.rule_id.upper() in ignored_rules:
            suppressed.append(
                {
                    "finding_id": f.finding_id,
                    "rule_id": f.rule_id,
                    "file_path": f.file_path,
                    "line": f.start_line,
                    "reason": "inline_suppression",
                }
            )
        else:
            active.append(f)

    return active, suppressed


def load_baseline(baseline_path: Path) -> set[str]:
    """Load finding fingerprints from a VulnBox baseline JSON file."""
    data = json.loads(baseline_path.read_text(encoding="utf-8"))
    if isinstance(data, list):
        return {str(x) for x in data}
    entries = data.get("fingerprints") or data.get("findings") or []
    fps: set[str] = set()
    for item in entries:
        if isinstance(item, str):
            fps.add(item)
        elif isinstance(item, dict) and item.get("fingerprint"):
            fps.add(str(item["fingerprint"]))
    return fps


def write_baseline(findings: list[Finding], baseline_path: Path) -> Path:
    """Write a deterministic baseline JSON file containing all current finding fingerprints."""
    baseline_path.parent.mkdir(parents=True, exist_ok=True)
    records = [
        {
            "fingerprint": compute_finding_fingerprint(f),
            "rule_id": f.rule_id,
            "severity": f.severity,
            "file_path": f.file_path,
            "start_line": f.start_line,
            "title": f.title,
        }
        for f in findings
    ]
    payload = {
        "schema_version": 1,
        "count": len(records),
        "fingerprints": [r["fingerprint"] for r in records],
        "findings": records,
    }
    baseline_path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    return baseline_path


def filter_by_baseline(
    findings: list[Finding],
    baseline_fingerprints: set[str],
) -> tuple[list[Finding], int]:
    """Return `(new_findings, baselined_count)` excluding already-accepted fingerprints."""
    kept: list[Finding] = []
    baselined = 0
    for f in findings:
        fp = compute_finding_fingerprint(f)
        if fp in baseline_fingerprints:
            baselined += 1
        else:
            kept.append(f)
    return kept, baselined


def should_fail_ci(findings: list[Finding], fail_on: str | None) -> bool:
    """Return True if any finding meets or exceeds the configured `--fail-on` severity."""
    if not fail_on:
        return False
    threshold = SEVERITY_RANK.get(fail_on.strip().lower())
    if threshold is None:
        raise ValueError(
            f"Unsupported --fail-on severity {fail_on!r}. Choose from: low, medium, high, critical."
        )
    return any(SEVERITY_RANK.get(f.severity, 0) >= threshold for f in findings)
