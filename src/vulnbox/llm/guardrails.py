"""Deterministic security and anti-hallucination guardrails for LLM-assisted remediation."""

from __future__ import annotations

import ast
import re
import shlex
from pathlib import Path

from pydantic import BaseModel

from vulnbox.models import DynamicProbeSpec, Finding, GuardrailEvent, LLMPatchProposal
from vulnbox.scrubber import SECRET_TOKEN_PATTERNS


class GuardrailPolicy(BaseModel):
    """Configurable budgets and strict boundaries for LLM inputs and outputs."""

    max_prompt_chars: int = 24_000
    max_diff_files: int = 2
    max_diff_changed_lines: int = 80
    max_probe_body_bytes: int = 2048
    max_retries: int = 2


PROMPT_INJECTION_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    (
        "ignore_instructions",
        re.compile(r"ignore\s+(?:all\s+)?(?:previous|prior|above)\s+instructions", re.IGNORECASE),
    ),
    (
        "false_positive_override",
        re.compile(
            r"(?:mark|classify|treat)\s+(?:this|it)\s+as\s+(?:safe|false\s+positive|not\s+affected)",
            re.IGNORECASE,
        ),
    ),
    (
        "system_prompt_spoof",
        re.compile(r"<\s*/?\s*system\s*>|\bSYSTEM\s+OVERRIDE\b", re.IGNORECASE),
    ),
]

PROTECTED_PATH_PREFIXES = (
    ".git/",
    ".github/",
    ".agents/",
    "node_modules/",
    ".venv/",
)

PROTECTED_FILENAMES = {
    ".env",
    ".npmrc",
    ".pypirc",
    "id_rsa",
    "id_ed25519",
}

TEST_TAMPERING_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("pytest_skip", re.compile(r"pytest\.mark\.skip|pytest\.skip\(")),
    ("unittest_skip", re.compile(r"@unittest\.skip")),
    ("js_test_skip", re.compile(r"\b(?:test|it|describe)\.skip\(")),
    ("linter_bypass", re.compile(r"#\s*nosec\b|//\s*eslint-disable")),
]

DANGEROUS_DIFF_ADDITIONS: list[tuple[str, re.Pattern[str]]] = [
    ("python_shell_true", re.compile(r"\bshell\s*=\s*True\b")),
    ("python_eval_exec", re.compile(r"\b(?:eval|exec)\s*\(")),
    ("python_verify_false", re.compile(r"\bverify\s*=\s*False\b")),
    ("python_unsafe_yaml", re.compile(r"\byaml\.(?:unsafe_load|full_load)\s*\(")),
    ("js_reject_unauth_false", re.compile(r"rejectUnauthorized\s*:\s*false")),
    ("world_writable_perm", re.compile(r"\bchmod\s+0?777\b|0o777")),
]

# Strictly block offensive/destructive probe payloads (command execution, RCE tags, SQL destructive ops, SSRF metadata)
DISALLOWED_PROBE_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("external_url_in_path", re.compile(r"https?://|file://|ftp://", re.IGNORECASE)),
    ("cloud_metadata_host", re.compile(r"169\.254\.169\.254|metadata\.google\.internal", re.IGNORECASE)),
    ("yaml_rce_tag", re.compile(r"!!python/object/(?:apply|new|reduce)", re.IGNORECASE)),
    ("shell_metachar_exec", re.compile(r"\$\(|`[^`]+`|;\s*(?:rm|curl|wget|bash|sh|nc)\b|\|\s*(?:sh|bash)\b", re.IGNORECASE)),
    ("destructive_sql", re.compile(r"\b(?:DROP\s+TABLE|DELETE\s+FROM|UNION\s+SELECT)\b", re.IGNORECASE)),
]

DISALLOWED_REGRESSION_TEST_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("subprocess_exec", re.compile(r"\b(?:subprocess\.|os\.system|child_process)\b")),
    ("destructive_fs", re.compile(r"\b(?:shutil\.rmtree|fs\.rmSync|rm\s+-rf)\b")),
    ("outbound_network", re.compile(r"https?://(?!127\.0\.0\.1|localhost)", re.IGNORECASE)),
]


def detect_prompt_injection(
    source_text: str,
    file_path: str,
    finding_id: str | None = None,
) -> list[GuardrailEvent]:
    """Detect prompt-injection attempts inside untrusted repository text.

    Does not drop the finding (AST dominance); emits warning events and allows safe framing.
    """
    events: list[GuardrailEvent] = []
    for label, pattern in PROMPT_INJECTION_PATTERNS:
        if pattern.search(source_text):
            events.append(
                GuardrailEvent(
                    gate="prompt_injection_detector",
                    decision="warn",
                    finding_id=finding_id,
                    reason=(
                        f"Suspicious prompt-injection pattern ({label}) detected inside "
                        f"untrusted repository file '{file_path}'; isolated inside XML data boundaries."
                    ),
                    details={"file_path": file_path, "pattern": label},
                )
            )
    return events


def frame_untrusted_code(file_path: str, source_text: str, max_chars: int = 12_000) -> str:
    """Wrap repository source code in explicit untrusted XML data delimiters."""
    safe_text = source_text[:max_chars]
    # Prevent tag-breakout attempts inside untrusted code
    safe_text = safe_text.replace("</untrusted_repo_file>", "&lt;/untrusted_repo_file&gt;")
    return f'<untrusted_repo_file path="{file_path}">\n{safe_text}\n</untrusted_repo_file>'


def check_outbound_prompt(
    prompt: str,
    policy: GuardrailPolicy,
    finding_id: str | None = None,
) -> GuardrailEvent:
    """Block outbound LLM requests containing raw secret tokens or exceeding budget."""
    if len(prompt) > policy.max_prompt_chars:
        return GuardrailEvent(
            gate="outbound_prompt_budget",
            decision="block",
            finding_id=finding_id,
            reason=f"Prompt length ({len(prompt)} chars) exceeds policy limit ({policy.max_prompt_chars}).",
            details={"length": len(prompt), "limit": policy.max_prompt_chars},
        )

    for label, pattern in SECRET_TOKEN_PATTERNS:
        if pattern.search(prompt):
            return GuardrailEvent(
                gate="outbound_secret_leak_guard",
                decision="block",
                finding_id=finding_id,
                reason=f"Blocked outbound LLM prompt containing unredacted secret pattern ({label}).",
                details={"pattern": label},
            )

    return GuardrailEvent(
        gate="outbound_prompt_guard",
        decision="allow",
        finding_id=finding_id,
        reason="Outbound prompt passed secret-leakage and size budget checks.",
        details={"length": len(prompt)},
    )


def _extract_diff_files_and_lines(unified_diff: str) -> tuple[list[str], list[str], list[str]]:
    """Extract target file paths, added lines, and removed lines from a unified diff."""
    files: list[str] = []
    added: list[str] = []
    removed: list[str] = []
    for line in unified_diff.splitlines():
        if line.startswith("+++ "):
            raw = line[4:].strip().split("\t", 1)[0]
            rel = raw[2:] if raw.startswith("b/") else raw
            files.append(rel)
        elif line.startswith("+") and not line.startswith("+++"):
            added.append(line[1:])
        elif line.startswith("-") and not line.startswith("---"):
            removed.append(line[1:])
    return files, added, removed


def _is_test_file(rel_path: str) -> bool:
    p = Path(rel_path)
    parts = set(p.parts)
    name = p.name.lower()
    return (
        "tests" in parts
        or "__tests__" in parts
        or name.startswith("test_")
        or name.endswith(("_test.py", ".test.js", ".test.mjs", ".test.ts", ".spec.js", ".spec.ts"))
    )


def validate_llm_diff(
    unified_diff: str,
    finding: Finding,
    workspace_dir: Path,
    policy: GuardrailPolicy,
) -> GuardrailEvent:
    """Enforce path safety, anti-test-tampering, diff size limits, and sink safety."""
    files, added, removed = _extract_diff_files_and_lines(unified_diff)
    if not files:
        return GuardrailEvent(
            gate="diff_safety_gate",
            decision="block",
            finding_id=finding.finding_id,
            reason="LLM diff contains no valid +++ file headers.",
        )

    if len(files) > policy.max_diff_files:
        return GuardrailEvent(
            gate="diff_safety_gate",
            decision="block",
            finding_id=finding.finding_id,
            reason=f"LLM diff modifies {len(files)} files (max allowed: {policy.max_diff_files}).",
            details={"files": files},
        )

    changed_count = len(added) + len(removed)
    if changed_count > policy.max_diff_changed_lines:
        return GuardrailEvent(
            gate="diff_safety_gate",
            decision="block",
            finding_id=finding.finding_id,
            reason=(
                f"LLM diff changes {changed_count} lines "
                f"(max allowed: {policy.max_diff_changed_lines})."
            ),
            details={"changed_lines": changed_count},
        )

    ws_resolved = workspace_dir.resolve()
    for rel in files:
        if rel.startswith("/") or ".." in Path(rel).parts:
            return GuardrailEvent(
                gate="diff_safety_gate",
                decision="block",
                finding_id=finding.finding_id,
                reason=f"Blocked unsafe patch path outside workspace: '{rel}'.",
                details={"path": rel},
            )
        if any(rel.startswith(prefix) for prefix in PROTECTED_PATH_PREFIXES):
            return GuardrailEvent(
                gate="diff_safety_gate",
                decision="block",
                finding_id=finding.finding_id,
                reason=f"Blocked modification to protected path: '{rel}'.",
                details={"path": rel},
            )
        if Path(rel).name.lower() in PROTECTED_FILENAMES:
            return GuardrailEvent(
                gate="diff_safety_gate",
                decision="block",
                finding_id=finding.finding_id,
                reason=f"Blocked modification to sensitive file: '{rel}'.",
                details={"path": rel},
            )
        if _is_test_file(rel):
            return GuardrailEvent(
                gate="anti_test_tampering_gate",
                decision="block",
                finding_id=finding.finding_id,
                reason=f"Blocked LLM patch attempting to edit existing test file '{rel}'.",
                details={"path": rel},
            )
        target_abs = (ws_resolved / rel).resolve()
        if not target_abs.is_relative_to(ws_resolved) or not target_abs.is_file():
            return GuardrailEvent(
                gate="diff_safety_gate",
                decision="block",
                finding_id=finding.finding_id,
                reason=f"Patch target does not exist inside sandbox workspace: '{rel}'.",
                details={"path": rel},
            )

    added_blob = "\n".join(added)
    for label, pattern in TEST_TAMPERING_PATTERNS:
        if pattern.search(added_blob):
            return GuardrailEvent(
                gate="anti_test_tampering_gate",
                decision="block",
                finding_id=finding.finding_id,
                reason=f"Blocked test/linter suppression pattern ({label}) in LLM diff.",
                details={"pattern": label},
            )

    for label, pattern in DANGEROUS_DIFF_ADDITIONS:
        if pattern.search(added_blob):
            return GuardrailEvent(
                gate="diff_safety_gate",
                decision="block",
                finding_id=finding.finding_id,
                reason=f"Blocked dangerous security sink ({label}) introduced in LLM diff.",
                details={"pattern": label},
            )

    return GuardrailEvent(
        gate="diff_safety_gate",
        decision="allow",
        finding_id=finding.finding_id,
        reason=f"LLM diff passed safety checks ({len(files)} file(s), {changed_count} changed lines).",
        details={"files": files, "changed_lines": changed_count},
    )


def validate_llm_probe(
    spec: DynamicProbeSpec,
    policy: GuardrailPolicy,
    finding_id: str | None = None,
) -> GuardrailEvent:
    """Ensure LLM-synthesized dynamic probes are strictly loopback and non-destructive."""
    if not spec.path.startswith("/"):
        return GuardrailEvent(
            gate="probe_safety_gate",
            decision="block",
            finding_id=finding_id,
            reason=f"Probe path must be a relative loopback path starting with '/': '{spec.path}'.",
        )

    if spec.body and len(spec.body.encode("utf-8")) > policy.max_probe_body_bytes:
        return GuardrailEvent(
            gate="probe_safety_gate",
            decision="block",
            finding_id=finding_id,
            reason=f"Probe body exceeds max allowed size ({policy.max_probe_body_bytes} bytes).",
        )

    if spec.setup_marker_file:
        mp = Path(spec.setup_marker_file)
        if mp.is_absolute() or ".." in mp.parts:
            return GuardrailEvent(
                gate="probe_safety_gate",
                decision="block",
                finding_id=finding_id,
                reason=f"Unsafe probe setup_marker_file path: '{spec.setup_marker_file}'.",
            )

    combined = "\n".join(
        [
            spec.path,
            spec.body or "",
            *[f"{k}: {v}" for k, v in spec.headers.items()],
        ]
    )
    for label, pattern in DISALLOWED_PROBE_PATTERNS:
        if pattern.search(combined):
            return GuardrailEvent(
                gate="probe_safety_gate",
                decision="block",
                finding_id=finding_id,
                reason=f"Blocked unsafe or non-defensive probe payload pattern ({label}).",
                details={"pattern": label, "probe_id": spec.probe_id},
            )

    return GuardrailEvent(
        gate="probe_safety_gate",
        decision="allow",
        finding_id=finding_id,
        reason=f"LLM probe '{spec.probe_id}' passed loopback and non-destructive payload checks.",
        details={"probe_id": spec.probe_id, "method": spec.method, "path": spec.path},
    )


def validate_llm_regression_test(
    test_path: str,
    test_code: str,
    finding_id: str | None = None,
) -> GuardrailEvent:
    """Validate LLM-generated defensive regression tests before sandbox execution."""
    p = Path(test_path)
    if p.is_absolute() or ".." in p.parts or not str(p).startswith("tests/"):
        return GuardrailEvent(
            gate="regression_test_safety_gate",
            decision="block",
            finding_id=finding_id,
            reason=f"Regression test path must stay under 'tests/': '{test_path}'.",
        )

    if not (p.name.startswith("test_security_") and p.suffix == ".py") and not (
        p.name.startswith("security_") and p.name.endswith(".test.mjs")
    ):
        return GuardrailEvent(
            gate="regression_test_safety_gate",
            decision="block",
            finding_id=finding_id,
            reason=(
                f"Regression test filename '{p.name}' must match "
                "'test_security_*.py' or 'security_*.test.mjs'."
            ),
        )

    for label, pattern in DISALLOWED_REGRESSION_TEST_PATTERNS:
        if pattern.search(test_code):
            return GuardrailEvent(
                gate="regression_test_safety_gate",
                decision="block",
                finding_id=finding_id,
                reason=f"Blocked unsafe operation ({label}) in LLM regression test.",
                details={"pattern": label},
            )

    if p.suffix == ".py":
        try:
            ast.parse(test_code)
        except SyntaxError as exc:
            return GuardrailEvent(
                gate="regression_test_safety_gate",
                decision="block",
                finding_id=finding_id,
                reason=f"LLM Python regression test has invalid syntax: {exc}.",
            )

    return GuardrailEvent(
        gate="regression_test_safety_gate",
        decision="allow",
        finding_id=finding_id,
        reason=f"LLM regression test '{test_path}' passed syntax and safety checks.",
    )


ALLOWED_START_CMD_BINARIES = frozenset(
    {
        "python",
        "python3",
        "uvicorn",
        "gunicorn",
        "flask",
        "hypercorn",
        "daphne",
        "fastapi",
        "node",
        "npm",
        "npx",
        "yarn",
        "pnpm",
        "bun",
        "deno",
        "go",
    }
)
_SHELL_METACHAR_RE = re.compile(r"[;&|`$><\r\n]")
_DISALLOWED_INLINE_CODE_FLAGS = frozenset({"-c", "-e", "--eval", "-p", "--print"})


def validate_start_command(
    start_cmd: str,
    finding_id: str | None = None,
) -> GuardrailEvent:
    """Validate an agent-supplied server start_cmd against shell injection & arbitrary execution."""
    raw = start_cmd.strip()
    if not raw:
        return GuardrailEvent(
            gate="start_cmd_safety_gate",
            decision="block",
            finding_id=finding_id,
            reason="Empty start_cmd is not allowed.",
        )
    if _SHELL_METACHAR_RE.search(raw):
        return GuardrailEvent(
            gate="start_cmd_safety_gate",
            decision="block",
            finding_id=finding_id,
            reason="Blocked shell metacharacters or command chaining in start_cmd.",
            details={"start_cmd": raw[:120]},
        )
    try:
        tokens = shlex.split(raw)
    except ValueError as exc:
        return GuardrailEvent(
            gate="start_cmd_safety_gate",
            decision="block",
            finding_id=finding_id,
            reason=f"Malformed start_cmd quoting: {exc}.",
        )
    if not tokens:
        return GuardrailEvent(
            gate="start_cmd_safety_gate",
            decision="block",
            finding_id=finding_id,
            reason="Empty start_cmd after parsing.",
        )

    bin_name = Path(tokens[0]).name.lower()
    is_python_bin = bin_name in ("python", "python3") or bool(re.fullmatch(r"python3\.\d+", bin_name))
    if not is_python_bin and bin_name not in ALLOWED_START_CMD_BINARIES:
        return GuardrailEvent(
            gate="start_cmd_safety_gate",
            decision="block",
            finding_id=finding_id,
            reason=(
                f"Blocked unsupported start_cmd executable '{tokens[0]}'. "
                "Only standard Python/Node/Go app runners are permitted."
            ),
            details={"executable": tokens[0]},
        )

    for tok in tokens[1:]:
        if tok in _DISALLOWED_INLINE_CODE_FLAGS or tok.startswith(("--eval=", "-c")):
            return GuardrailEvent(
                gate="start_cmd_safety_gate",
                decision="block",
                finding_id=finding_id,
                reason=f"Blocked inline code execution flag '{tok}' in start_cmd.",
                details={"flag": tok},
            )

    return GuardrailEvent(
        gate="start_cmd_safety_gate",
        decision="allow",
        finding_id=finding_id,
        reason=f"start_cmd '{tokens[0]}' passed shell-injection and binary allowlist checks.",
    )


def validate_llm_proposal(
    proposal: LLMPatchProposal,
    finding: Finding,
    workspace_dir: Path,
    policy: GuardrailPolicy,
) -> tuple[bool, list[GuardrailEvent]]:
    """Run all output guardrails against a structured LLM patch proposal."""
    events: list[GuardrailEvent] = []

    diff_ev = validate_llm_diff(proposal.unified_diff or "", finding, workspace_dir, policy)
    events.append(diff_ev)

    if proposal.probe_spec is not None:
        probe_ev = validate_llm_probe(proposal.probe_spec, policy, finding_id=finding.finding_id)
        events.append(probe_ev)

    if proposal.regression_test_path and proposal.regression_test_code:
        reg_ev = validate_llm_regression_test(
            proposal.regression_test_path,
            proposal.regression_test_code,
            finding_id=finding.finding_id,
        )
        events.append(reg_ev)

    allowed = all(ev.decision != "block" for ev in events)
    return allowed, events
