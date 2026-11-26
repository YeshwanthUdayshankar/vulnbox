"""Output artifact bundle writer (Markdown + SARIF 2.1.0 + unified diffs + regression tests)."""

from __future__ import annotations

import json
from pathlib import Path

from vulnbox.models import AuditReport
from vulnbox.reporting.markdown import render_markdown_report
from vulnbox.reporting.sarif import build_sarif, validate_sarif


def write_report_bundle(report: AuditReport, out_dir: Path) -> dict[str, Path]:
    """Write report.md, validated findings.sarif.json, manifest.json, patches/, and regression_tests/."""
    root = Path(out_dir).resolve()
    root.mkdir(parents=True, exist_ok=True)
    patches_dir = root / "patches"
    reg_dir = root / "regression_tests"
    patches_dir.mkdir(exist_ok=True)
    reg_dir.mkdir(exist_ok=True)

    written: dict[str, Path] = {}

    # 1. SARIF 2.1.0 (deterministically schema-validated before writing)
    sarif_doc = build_sarif(report)
    validate_sarif(sarif_doc)
    sarif_path = root / "findings.sarif.json"
    sarif_path.write_text(json.dumps(sarif_doc, indent=2) + "\n", encoding="utf-8")
    written["sarif"] = sarif_path

    # 2. Markdown report
    md_path = root / "report.md"
    md_path.write_text(render_markdown_report(report), encoding="utf-8")
    written["markdown"] = md_path

    # 3. Full JSON manifest
    manifest_path = root / "manifest.json"
    manifest_path.write_text(report.model_dump_json(indent=2) + "\n", encoding="utf-8")
    written["manifest"] = manifest_path

    # 4. Patches & regression tests
    for patch in report.patches:
        pfile = patches_dir / f"{patch.finding_id}.patch"
        pfile.write_text(patch.unified_diff, encoding="utf-8")
        written[f"patch:{patch.finding_id}"] = pfile

        if patch.regression_test_path and patch.regression_test_code:
            tname = Path(patch.regression_test_path).name
            tfile = reg_dir / tname
            tfile.write_text(patch.regression_test_code, encoding="utf-8")
            written[f"test:{patch.finding_id}"] = tfile

    return written
