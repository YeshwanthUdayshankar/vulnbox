"""Remediation pipeline exports."""

from vulnbox.remediation.dynamic_probe import (
    infer_probe_for_finding,
    load_probe_specs,
    run_dynamic_probe,
    validate_loopback_url,
)
from vulnbox.remediation.memory_probe import (
    infer_memory_probe_for_finding,
    run_memory_leak_probe,
)
from vulnbox.remediation.patcher import (
    apply_unified_diff,
    generate_patch_for_finding,
    make_unified_diff,
)
from vulnbox.remediation.regression_gen import generate_regression_test
from vulnbox.remediation.verifier import verify_patch

__all__ = [
    "apply_unified_diff",
    "generate_patch_for_finding",
    "generate_regression_test",
    "infer_memory_probe_for_finding",
    "infer_probe_for_finding",
    "load_probe_specs",
    "make_unified_diff",
    "run_dynamic_probe",
    "run_memory_leak_probe",
    "validate_loopback_url",
    "verify_patch",
]
