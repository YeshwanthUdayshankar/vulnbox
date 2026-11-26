"""Optional guarded LLM remediation & probe synthesis package."""

from vulnbox.llm.agent import synthesize_and_verify_patch
from vulnbox.llm.client import LLMConfig, OpenAICompatLLMClient
from vulnbox.llm.guardrails import (
    GuardrailPolicy,
    check_outbound_prompt,
    detect_prompt_injection,
    frame_untrusted_code,
    validate_llm_diff,
    validate_llm_probe,
    validate_llm_proposal,
    validate_llm_regression_test,
)

__all__ = [
    "GuardrailPolicy",
    "LLMConfig",
    "OpenAICompatLLMClient",
    "check_outbound_prompt",
    "detect_prompt_injection",
    "frame_untrusted_code",
    "synthesize_and_verify_patch",
    "validate_llm_diff",
    "validate_llm_probe",
    "validate_llm_proposal",
    "validate_llm_regression_test",
]
