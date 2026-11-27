"""OpenVEX v0.2.0 and CycloneDX 1.5 VEX document emitters backed by call-graph reachability."""

from __future__ import annotations

import hashlib
from typing import Any

from vulnbox.models import AuditReport, Finding, VerificationResult


def _package_purl(finding: Finding) -> str:
    eco = str(finding.metadata.get("ecosystem") or "python").lower()
    pkg = str(finding.metadata.get("package") or "unknown").lower()
    ver = str(finding.metadata.get("installed_version") or "0.0.0").lstrip("^~>=<v")
    purl_type = "pypi" if eco == "python" else "npm"
    return f"pkg:{purl_type}/{pkg}@{ver}"


def _statement_state(
    finding: Finding, ver: VerificationResult | None
) -> tuple[str, str | None, str, str]:
    """Map VulnBox reachability + patch verification into OpenVEX & CycloneDX VEX states."""
    if ver is not None and ver.verified:
        fixed_ver = finding.metadata.get("fixed_version") or "patched version"
        return (
            "fixed",
            None,
            "resolved",
            f"Verified dependency upgrade to {fixed_ver} inside isolated sandbox.",
        )

    if finding.reachability == "not_reachable":
        return (
            "not_affected",
            "vulnerable_code_not_in_execute_path",
            "not_affected",
            f"VulnBox static/hybrid call-graph analysis verified that vulnerable symbols of "
            f"'{finding.metadata.get('package', 'package')}' are not imported or reachable from application entrypoints.",
        )

    if finding.reachability == "reachable":
        call_path = finding.metadata.get("call_path")
        path_note = f" Call path: {' -> '.join(call_path)}." if call_path else ""
        epss = finding.metadata.get("epss_score")
        kev = finding.metadata.get("cisa_kev")
        risk_bits: list[str] = []
        if kev:
            risk_bits.append("CISA KEV listed")
        if epss is not None:
            risk_bits.append(f"EPSS={epss}")
        risk_note = f" ({', '.join(risk_bits)})" if risk_bits else ""
        return (
            "affected",
            None,
            "exploitable",
            f"Vulnerable code path is reachable{risk_note}.{path_note}",
        )

    return (
        "under_investigation",
        None,
        "in_triage",
        "Package is imported; exact vulnerable symbol reachability requires deeper dynamic verification.",
    )


def build_openvex(report: AuditReport) -> dict[str, Any]:
    """Generate an OpenVEX v0.2.0 JSON-LD document for all dependency CVE findings."""
    ver_by_finding = {v.finding_id: v for v in report.verifications}
    doc_hash = hashlib.sha256(
        f"{report.profile.repo_path}:{report.timestamp}".encode()
    ).hexdigest()[:16]

    statements: list[dict[str, Any]] = []
    for f in report.findings:
        if f.category != "dependency":
            continue
        ver = ver_by_finding.get(f.finding_id)
        ov_status, ov_just, _cdx_state, detail = _statement_state(f, ver)
        adv_id = str(f.metadata.get("advisory_id") or f.rule_id.removeprefix("DEP-"))
        purl = _package_purl(f)

        stmt: dict[str, Any] = {
            "vulnerability": {
                "name": adv_id,
                "description": f.title,
            },
            "products": [{"@id": purl}],
            "status": ov_status,
            "status_notes": detail,
        }
        if ov_just is not None:
            stmt["justification"] = ov_just
            stmt["impact_statement"] = detail
        elif ov_status == "affected":
            stmt["action_statement"] = f.recommended_fix
            stmt["impact_statement"] = detail
        statements.append(stmt)

    return {
        "@context": "https://openvex.dev/ns/v0.2.0",
        "@id": f"https://vulnbox.local/vex/{doc_hash}",
        "author": f"VulnBox v{report.tool_version}",
        "timestamp": report.timestamp,
        "version": 1,
        "tooling": f"vulnbox/{report.tool_version}",
        "statements": statements,
    }


def build_cyclonedx_vex(report: AuditReport) -> dict[str, Any]:
    """Generate a CycloneDX 1.5 JSON VEX document enriched with reachability, EPSS, and KEV."""
    ver_by_finding = {v.finding_id: v for v in report.verifications}
    serial_hex = hashlib.sha256(
        f"cdx:{report.profile.repo_path}:{report.timestamp}".encode()
    ).hexdigest()[:32]
    serial_uuid = (
        f"{serial_hex[:8]}-{serial_hex[8:12]}-4{serial_hex[13:16]}-"
        f"a{serial_hex[17:20]}-{serial_hex[20:32]}"
    )

    vulns: list[dict[str, Any]] = []
    for f in report.findings:
        if f.category != "dependency":
            continue
        ver = ver_by_finding.get(f.finding_id)
        _ov_status, _ov_just, cdx_state, detail = _statement_state(f, ver)
        adv_id = str(f.metadata.get("advisory_id") or f.rule_id.removeprefix("DEP-"))
        purl = _package_purl(f)

        analysis: dict[str, Any] = {
            "state": cdx_state,
            "detail": detail,
        }
        if cdx_state == "not_affected":
            analysis["justification"] = "code_not_reachable"
        elif cdx_state == "exploitable":
            analysis["response"] = ["update"]

        ratings: list[dict[str, Any]] = [{"severity": f.severity}]
        if f.metadata.get("epss_score") is not None:
            ratings.append(
                {
                    "method": "other",
                    "score": float(f.metadata["epss_score"]),
                    "source": {"name": "FIRST EPSS"},
                }
            )

        vuln_obj: dict[str, Any] = {
            "id": adv_id,
            "description": f.message,
            "recommendation": f.recommended_fix,
            "ratings": ratings,
            "analysis": analysis,
            "affects": [{"ref": purl}],
        }
        if f.metadata.get("cisa_kev"):
            vuln_obj["properties"] = [{"name": "cisa:kev", "value": "true"}]
        vulns.append(vuln_obj)

    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": f"urn:uuid:{serial_uuid}",
        "version": 1,
        "metadata": {
            "timestamp": report.timestamp,
            "tools": [
                {
                    "vendor": "VulnBox",
                    "name": "vulnbox",
                    "version": report.tool_version,
                }
            ],
        },
        "vulnerabilities": vulns,
    }
