"""Core Pydantic v2 schemas for VulnBox."""

from __future__ import annotations

import shlex
from typing import Any, Literal

from pydantic import BaseModel, Field

Ecosystem = Literal["python", "node", "mixed", "unknown"]
Severity = Literal["critical", "high", "medium", "low", "info"]
FindingCategory = Literal["sast", "dependency", "config", "secret"]
ReachabilityStatus = Literal[
    "reachable", "not_reachable", "under_investigation", "not_applicable"
]
PatchStrategy = Literal[
    "minimal_code_fix",
    "dependency_bump",
    "config_hardening",
    "agent_supplied",
    "llm_synthesized",
]
HttpMethod = Literal["GET", "POST", "PUT", "DELETE", "OPTIONS", "HEAD"]
GuardrailDecision = Literal["allow", "block", "warn"]


class RepoProfile(BaseModel):
    """Summary of detected stack, entrypoints, and test commands for a repo."""

    repo_path: str
    ecosystem: Ecosystem = "unknown"
    manifests: list[str] = Field(default_factory=list)
    dockerfiles: list[str] = Field(default_factory=list)
    frameworks: list[str] = Field(default_factory=list)
    test_commands: dict[str, str] = Field(default_factory=dict)
    start_command: str | None = None
    health_path: str = "/health"
    env_files: list[str] = Field(default_factory=list)


class ScrubSummary(BaseModel):
    """Record of files scrubbed and secrets redacted before sandbox execution."""

    sandbox_dir: str
    files_copied: int = 0
    files_scrubbed: list[str] = Field(default_factory=list)
    secrets_redacted: int = 0
    excluded_paths: list[str] = Field(default_factory=list)
    env_classifications: dict[str, str] = Field(default_factory=dict)


class Finding(BaseModel):
    """Normalized vulnerability or hygiene finding discovered in a repository."""

    finding_id: str
    rule_id: str
    cwe_id: str
    title: str
    category: FindingCategory
    severity: Severity
    file_path: str
    start_line: int = 1
    end_line: int = 1
    snippet: str = ""
    message: str
    reachability: ReachabilityStatus = "not_applicable"
    recommended_fix: str
    metadata: dict[str, Any] = Field(default_factory=dict)


class ProbeExpectation(BaseModel):
    """Assertions evaluated against an HTTP response during active probing."""

    status_codes: list[int] = Field(default_factory=list)
    body_contains: list[str] = Field(default_factory=list)
    body_not_contains: list[str] = Field(default_factory=list)
    headers_contain: dict[str, str] = Field(default_factory=dict)
    headers_not_contain: dict[str, str] = Field(default_factory=dict)

    def matches(
        self,
        status_code: int | None,
        headers: dict[str, str],
        body: str,
    ) -> bool:
        """Return True if all configured expectations match the HTTP response."""
        if status_code is None:
            return False
        if self.status_codes and status_code not in self.status_codes:
            return False
        for needle in self.body_contains:
            if needle not in body:
                return False
        for forbidden in self.body_not_contains:
            if forbidden in body:
                return False

        lowered_headers = {k.lower(): v for k, v in headers.items()}
        for h_name, expected_val in self.headers_contain.items():
            actual = lowered_headers.get(h_name.lower())
            if actual is None or expected_val.lower() not in actual.lower():
                return False
        for h_name, forbidden_val in self.headers_not_contain.items():
            actual = lowered_headers.get(h_name.lower())
            if actual is not None and (
                forbidden_val == "" or forbidden_val.lower() in actual.lower()
            ):
                return False
        return True


class DynamicProbeSpec(BaseModel):
    """Declarative loopback-only active HTTP probe used before and after patching."""

    probe_id: str
    finding_id: str | None = None
    rule_id: str | None = None
    description: str
    method: HttpMethod = "GET"
    path: str = "/"
    headers: dict[str, str] = Field(default_factory=dict)
    body: str | None = None
    setup_marker_file: str | None = None
    setup_marker_content: str = "VULNBOX_BOUNDARY_MARKER_9F3A"
    vulnerable_expectation: ProbeExpectation
    fixed_expectation: ProbeExpectation

    def to_curl(self, base_url: str) -> str:
        """Render a reproducible shell-safe curl command for this probe."""
        url = f"{base_url.rstrip('/')}{self.path}"
        parts = ["curl", "-sS", "-i", "-X", self.method]
        for key, value in self.headers.items():
            parts.extend(["-H", f"{key}: {value}"])
        if self.body is not None:
            parts.extend(["--data", self.body])
        parts.append(url)
        return " ".join(shlex.quote(p) for p in parts)


class DynamicProbeResult(BaseModel):
    """Captured result of running an active loopback probe."""

    probe_id: str
    curl_command: str
    status_code: int | None = None
    response_headers: dict[str, str] = Field(default_factory=dict)
    response_body_excerpt: str = ""
    matched_vulnerable: bool = False
    matched_fixed: bool = False
    error: str | None = None


class PatchCandidate(BaseModel):
    """Proposed remediation patch and associated verification hooks."""

    patch_id: str
    finding_id: str
    rule_id: str
    strategy: PatchStrategy = "minimal_code_fix"
    description: str
    unified_diff: str
    regression_test_path: str | None = None
    regression_test_code: str | None = None
    probe_spec: DynamicProbeSpec | None = None
    root_cause_explanation: str | None = None
    probe_explanation: str | None = None
    fix_explanation: str | None = None
    llm_attempts: int = 0


class GuardrailEvent(BaseModel):
    """Auditable record of a deterministic guardrail check during LLM/agent execution."""

    gate: str
    decision: GuardrailDecision
    finding_id: str | None = None
    reason: str
    details: dict[str, Any] = Field(default_factory=dict)


class LLMEdit(BaseModel):
    """Exact search-and-replace edit proposed by an LLM (converted deterministically to unified diff)."""

    file_path: str = Field(min_length=1)
    target: str = Field(min_length=1)
    replacement: str


class LLMPatchProposal(BaseModel):
    """Strict structured JSON schema required from any LLM remediation response."""

    root_cause_explanation: str = Field(min_length=5, max_length=2000)
    probe_explanation: str | None = Field(default=None, max_length=2000)
    fix_explanation: str = Field(min_length=5, max_length=2000)
    unified_diff: str | None = None
    edits: list[LLMEdit] = Field(default_factory=list)
    regression_test_path: str | None = None
    regression_test_code: str | None = None
    probe_spec: DynamicProbeSpec | None = None


class VerificationResult(BaseModel):
    """Outcome of dual-verifying a patch inside an isolated sandbox."""

    patch_id: str
    finding_id: str
    sandbox_backend: str
    baseline_tests_passed: bool
    patch_applied: bool
    finding_resolved: bool
    no_new_findings: bool
    dynamic_probe_before: DynamicProbeResult | None = None
    dynamic_probe_after: DynamicProbeResult | None = None
    dynamic_confirmed_and_fixed: bool | None = None
    regression_test_failed_before: bool | None = None
    regression_test_passed_after: bool | None = None
    existing_tests_passed_after: bool
    verified: bool
    summary: str = ""
    logs: dict[str, str] = Field(default_factory=dict)


class AuditReport(BaseModel):
    """Complete output of a VulnBox scan or remediation run."""

    tool_version: str
    timestamp: str
    sandbox_backend: str
    profile: RepoProfile
    scrub_summary: ScrubSummary
    findings: list[Finding] = Field(default_factory=list)
    patches: list[PatchCandidate] = Field(default_factory=list)
    verifications: list[VerificationResult] = Field(default_factory=list)
    llm_enabled: bool = False
    llm_model: str | None = None
    guardrail_events: list[GuardrailEvent] = Field(default_factory=list)
