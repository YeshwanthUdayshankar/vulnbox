"""Core Pydantic v2 schemas for VulnBox."""

from __future__ import annotations

import shlex
from typing import Any, Literal

from pydantic import BaseModel, Field

Ecosystem = Literal["python", "node", "mixed", "unknown"]
Severity = Literal["critical", "high", "medium", "low", "info"]
FindingCategory = Literal[
    "sast", "dependency", "config", "secret", "memory_leak", "resource_leak"
]
ReachabilityStatus = Literal[
    "reachable", "not_reachable", "under_investigation", "not_applicable"
]
EdgeProvenance = Literal[
    "static_exact",
    "framework_introspected",
    "runtime_observed",
    "unresolved",
]
CallNodeLanguage = Literal["python", "javascript", "typescript", "native"]
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


class CallNode(BaseModel):
    """Function, method, or route handler node in the hybrid call graph."""

    node_id: str
    file_path: str
    symbol: str
    line: int = 1
    language: CallNodeLanguage = "python"
    is_entrypoint: bool = False
    route: str | None = None


class CallEdge(BaseModel):
    """Directed caller -> callee edge tagged with analysis provenance."""

    caller: str
    callee: str
    file_path: str
    line: int = 1
    provenance: EdgeProvenance = "static_exact"


class UnresolvedCallSite(BaseModel):
    """Call site whose target could not be statically resolved (e.g., getattr, subscript)."""

    caller: str
    file_path: str
    line: int
    expression: str
    reason: str


class CallGraphSummary(BaseModel):
    """Serializable summary of the hybrid call graph for reports and UI."""

    total_nodes: int = 0
    total_edges: int = 0
    edges_by_provenance: dict[str, int] = Field(default_factory=dict)
    entrypoints: list[str] = Field(default_factory=list)
    unresolved_sites: list[UnresolvedCallSite] = Field(default_factory=list)
    runtime_resolved_count: int = 0


class MemorySample(BaseModel):
    """Single point-in-time memory & handle measurement inside the sandbox."""

    iteration: int
    heap_bytes: int
    rss_bytes: int = 0
    open_fds: int = 0
    gc_uncollectable: int = 0


class AllocationHotspot(BaseModel):
    """Top growing allocation site attributed by tracemalloc or V8 HeapProfiler."""

    location: str
    size_diff_bytes: int
    count_diff: int = 0
    traceback_excerpt: str = ""


class MemoryLeakProbeSpec(BaseModel):
    """Declarative loopback stress-probe specification for memory & FD leak verification."""

    probe_id: str
    finding_id: str | None = None
    rule_id: str | None = None
    description: str
    method: HttpMethod = "GET"
    path: str = "/"
    headers: dict[str, str] = Field(default_factory=dict)
    body: str | None = None
    vary_query_param: str | None = None
    warmup_requests: int = 10
    measure_requests: int = 60
    sample_interval: int = 15
    min_bytes_per_request: int = 1024
    min_r_squared: float = 0.70
    max_allowed_fd_delta: int = 5


class MemoryLeakProbeResult(BaseModel):
    """Captured result of running an active memory & FD leak stress probe."""

    probe_id: str
    endpoint: str
    profiler_name: str = ""
    skipped: bool = False
    skip_reason: str | None = None
    samples: list[MemorySample] = Field(default_factory=list)
    bytes_per_request_slope: float = 0.0
    r_squared: float = 0.0
    total_heap_growth_bytes: int = 0
    rss_growth_bytes: int = 0
    fd_delta: int = 0
    gc_garbage_delta: int = 0
    top_allocations: list[AllocationHotspot] = Field(default_factory=list)
    retainer_summary: str = ""
    leak_detected: bool = False
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
    memory_probe_spec: MemoryLeakProbeSpec | None = None
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
    memory_probe_before: MemoryLeakProbeResult | None = None
    memory_probe_after: MemoryLeakProbeResult | None = None
    memory_leak_confirmed_and_fixed: bool | None = None
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
    call_graph_summary: CallGraphSummary | None = None
    memory_probes: list[MemoryLeakProbeResult] = Field(default_factory=list)
    llm_enabled: bool = False
    llm_model: str | None = None
    guardrail_events: list[GuardrailEvent] = Field(default_factory=list)
