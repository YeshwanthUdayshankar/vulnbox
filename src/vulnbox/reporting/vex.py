"""OpenVEX v0.2.0 and CycloneDX 1.5 VEX document emitters backed by call-graph reachability."""

from __future__ import annotations

import hashlib
from typing import Any

from vulnbox.models import AuditReport, Finding, VerificationResult


def _is_exact_version_known(finding: Finding) -> bool:
    """Return True iff the finding's package version comes from a lockfile or Go toolchain pin."""
    version_source = str(finding.metadata.get("version_source") or "").lower()
    confidence = str(finding.metadata.get("confidence") or "").lower()
    return (
        version_source not in ("manifest_range", "go_directive_lower_bound")
        and confidence != "low"
    )


def _package_purl(finding: Finding, *, use_fixed_version: bool = False) -> tuple[str, str, str]:
    """Return `(purl, package_name, version)` for a dependency finding.

    - When `use_fixed_version=True` (verified `"fixed"` / `"resolved"` statements),
      attaches the VEX statement to the patched version's PURL rather than the vulnerable one.
    - When the installed version is only a loose manifest range or Go minimum-language lower
      bound (`not _is_exact_version_known(finding)`), omits `@version` (`pkg:pypi/requests`)
      so downstream consumers are not told an unverified version is installed.
    """
    eco = str(finding.metadata.get("ecosystem") or "python").lower()
    pkg = str(finding.metadata.get("package") or "unknown")
    if eco != "go":
        pkg = pkg.lower()
    if eco == "python":
        purl_type = "pypi"
    elif eco == "go":
        purl_type = "golang"
    else:
        purl_type = "npm"

    if not use_fixed_version and not _is_exact_version_known(finding):
        return f"pkg:{purl_type}/{pkg}", pkg, ""

    raw_ver = (
        finding.metadata.get("fixed_version")
        if use_fixed_version and finding.metadata.get("fixed_version")
        else finding.metadata.get("installed_version")
    )
    ver = str(raw_ver or "").lstrip("^~>=<v")
    if not ver:
        return f"pkg:{purl_type}/{pkg}", pkg, ""
    return f"pkg:{purl_type}/{pkg}@{ver}", pkg, ver


def _statement_state(
    finding: Finding, ver: VerificationResult | None
) -> tuple[str, str | None, str, str, bool]:
    """Map VulnBox reachability + patch verification into OpenVEX & CycloneDX VEX states.

    Returns `(openvex_status, openvex_justification, cdx_state, detail, use_fixed_purl)`.

    Soundness rules:
    1. Exact-version gate: if `version_source` is `manifest_range` or `go_directive_lower_bound`
       (or `confidence == "low"`), always emit `under_investigation` / `in_triage`; never claim
       `affected`, `not_affected`, or `fixed` without a lockfile or `toolchain goX.Y.Z` pin.
    2. Reverse-dependent gate: emit `not_affected` (`vulnerable_code_not_in_execute_path`) ONLY
       when the package is directly imported using non-vulnerable symbols AND the folder's
       lockfile dependency graph proves zero other dependencies depend on it
       (`reachability == "not_reachable"`, `reachability_basis == "imported_safe_symbols_no_dependents"`,
       and empty `reverse_dependents`). Unimported packages and packages with dependents remain
       `under_investigation` / `in_triage`.
    """
    if not _is_exact_version_known(finding):
        version_source = str(finding.metadata.get("version_source") or "").lower()
        src_desc = (
            "minimum `go` language directive (not a pinned `toolchain goX.Y.Z`)"
            if version_source == "go_directive_lower_bound"
            else "loose manifest range rather than a lockfile pin"
        )
        return (
            "under_investigation",
            None,
            "in_triage",
            f"Exact installed version of '{finding.metadata.get('package', 'package')}' is unknown "
            f"(derived from {src_desc}); provide a lockfile or `toolchain` directive before making "
            "a definitive affected/not_affected/fixed VEX claim.",
            False,
        )

    if ver is not None and ver.verified:
        fixed_ver = finding.metadata.get("fixed_version") or "patched version"
        return (
            "fixed",
            None,
            "resolved",
            f"Verified dependency upgrade to {fixed_ver} inside isolated sandbox.",
            True,
        )

    basis = str(finding.metadata.get("reachability_basis") or "")
    rev_deps = finding.metadata.get("reverse_dependents") or []
    has_direct_proof = (
        finding.reachability == "not_reachable"
        and basis in ("imported_safe_symbols_no_dependents", "imported_safe_symbols_only")
        and not rev_deps
    )
    if has_direct_proof:
        return (
            "not_affected",
            "vulnerable_code_not_in_execute_path",
            "not_affected",
            f"VulnBox AST/lockfile analysis confirmed '{finding.metadata.get('package', 'package')}' "
            f"has no reverse dependents in the lockfile and is directly imported using only non-vulnerable APIs.",
            False,
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
            False,
        )

    if basis == "imported_safe_symbols_but_has_dependents":
        dep_list_str = f" ({', '.join(rev_deps[:5])})" if rev_deps else ""
        triage_msg = (
            f"Application code does not invoke vulnerable symbols directly, but other dependencies{dep_list_str} "
            "may call the vulnerable code transitively; cannot prove not_affected without full transitive call graph."
        )
    elif basis == "not_directly_imported":
        triage_msg = (
            "Package is not directly imported in application source, but may be invoked transitively "
            "or via an indirect import alias; requires transitive/runtime verification before marking not_affected."
        )
    else:
        triage_msg = (
            "Package is imported; exact vulnerable symbol reachability requires deeper dynamic verification."
        )
    return (
        "under_investigation",
        None,
        "in_triage",
        triage_msg,
        False,
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
        ov_status, ov_just, _cdx_state, detail, use_fixed = _statement_state(f, ver)
        adv_id = str(f.metadata.get("advisory_id") or f.rule_id.removeprefix("DEP-"))
        purl, _pkg, _ver = _package_purl(f, use_fixed_version=use_fixed)

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
    """Generate a CycloneDX 1.5 JSON VEX document enriched with components BOM, reachability, EPSS, and KEV."""
    ver_by_finding = {v.finding_id: v for v in report.verifications}
    serial_hex = hashlib.sha256(
        f"cdx:{report.profile.repo_path}:{report.timestamp}".encode()
    ).hexdigest()[:32]
    serial_uuid = (
        f"{serial_hex[:8]}-{serial_hex[8:12]}-4{serial_hex[13:16]}-"
        f"a{serial_hex[17:20]}-{serial_hex[20:32]}"
    )

    components_by_ref: dict[str, dict[str, Any]] = {}
    vulns: list[dict[str, Any]] = []
    for f in report.findings:
        if f.category != "dependency":
            continue
        ver = ver_by_finding.get(f.finding_id)
        _ov_status, _ov_just, cdx_state, detail, use_fixed = _statement_state(f, ver)
        adv_id = str(f.metadata.get("advisory_id") or f.rule_id.removeprefix("DEP-"))
        purl, pkg, pkg_ver = _package_purl(f, use_fixed_version=use_fixed)

        if purl not in components_by_ref:
            comp: dict[str, Any] = {
                "type": "library",
                "bom-ref": purl,
                "name": pkg,
                "purl": purl,
            }
            if pkg_ver:
                comp["version"] = pkg_ver
            components_by_ref[purl] = comp

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
        "components": list(components_by_ref.values()),
        "vulnerabilities": vulns,
    }
