"""SARIF 2.1.0 emitter and deterministic schema validator."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import jsonschema

from vulnbox.models import AuditReport, Severity

SARIF_SCHEMA_URL = "https://json.schemastore.org/sarif-2.1.0.json"
LOCAL_SCHEMA_PATH = Path(__file__).resolve().parent.parent / "schemas" / "sarif_2_1_0.schema.json"


def _severity_to_sarif_level(severity: Severity) -> str:
    if severity in ("critical", "high"):
        return "error"
    if severity == "medium":
        return "warning"
    return "note"


def build_sarif(report: AuditReport) -> dict[str, Any]:
    """Convert an AuditReport into a SARIF 2.1.0 JSON dictionary."""
    ver_by_finding = {v.finding_id: v for v in report.verifications}
    rules_map: dict[str, dict[str, Any]] = {}
    results: list[dict[str, Any]] = []

    for f in report.findings:
        if f.rule_id not in rules_map:
            rules_map[f.rule_id] = {
                "id": f.rule_id,
                "shortDescription": {"text": f.title},
                "help": {"text": f.recommended_fix},
                "properties": {
                    "cwe": f.cwe_id,
                    "category": f.category,
                    "tags": ["security", f.cwe_id, f.category],
                },
            }

        ver = ver_by_finding.get(f.finding_id)
        props: dict[str, Any] = {
            "findingId": f.finding_id,
            "cwe": f.cwe_id,
            "severity": f.severity,
            "category": f.category,
            "reachability": f.reachability,
            "recommendedFix": f.recommended_fix,
        }
        if f.metadata.get("call_path"):
            props["callPath"] = f.metadata["call_path"]
        if ver is not None:
            props["patchVerified"] = ver.verified
            props["patchId"] = ver.patch_id
            if ver.dynamic_probe_before is not None:
                props["activeProbeCurl"] = ver.dynamic_probe_before.curl_command
                props["activeProbeReproducedBefore"] = ver.dynamic_probe_before.matched_vulnerable
            if ver.dynamic_probe_after is not None:
                props["activeProbeFixedAfter"] = ver.dynamic_probe_after.matched_fixed
            if ver.dynamic_confirmed_and_fixed is not None:
                props["activeDynamicVerified"] = ver.dynamic_confirmed_and_fixed
            if ver.memory_probe_before is not None:
                props["memorySlopeBeforeBytesPerReq"] = ver.memory_probe_before.bytes_per_request_slope
                props["fdDeltaBefore"] = ver.memory_probe_before.fd_delta
            if ver.memory_probe_after is not None:
                props["memorySlopeAfterBytesPerReq"] = ver.memory_probe_after.bytes_per_request_slope
                props["fdDeltaAfter"] = ver.memory_probe_after.fd_delta
            if ver.memory_leak_confirmed_and_fixed is not None:
                props["memoryLeakConfirmedAndFixed"] = ver.memory_leak_confirmed_and_fixed

        results.append(
            {
                "ruleId": f.rule_id,
                "level": _severity_to_sarif_level(f.severity),
                "message": {"text": f.message},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": f.file_path},
                            "region": {
                                "startLine": max(1, f.start_line),
                                "endLine": max(1, f.end_line),
                            },
                        }
                    }
                ],
                "properties": props,
            }
        )

    return {
        "$schema": SARIF_SCHEMA_URL,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "VulnBox",
                        "version": report.tool_version,
                        "informationUri": "https://github.com/YeshwanthUdayshankar/vulnbox",
                        "rules": list(rules_map.values()),
                    }
                },
                "results": results,
            }
        ],
    }


def validate_sarif(sarif_doc: dict[str, Any]) -> None:
    """Validate a SARIF 2.1.0 dictionary against the bundled schema."""
    schema = json.loads(LOCAL_SCHEMA_PATH.read_text(encoding="utf-8"))
    jsonschema.validate(instance=sarif_doc, schema=schema)
