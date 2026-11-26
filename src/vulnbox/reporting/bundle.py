"""Registry-backed report bundle writer (SARIF 2.1.0, Markdown, JSON manifest, diffs, tests)."""

from __future__ import annotations

import json
from pathlib import Path

from vulnbox.models import AuditReport
from vulnbox.registry import PluginRegistry, default_registry
from vulnbox.reporting.markdown import render_markdown_report
from vulnbox.reporting.sarif import build_sarif, validate_sarif


class SarifReporter:
    name = "sarif"

    def write(self, report: AuditReport, out_dir: Path) -> Path:
        sarif_doc = build_sarif(report)
        validate_sarif(sarif_doc)
        path = out_dir / "findings.sarif.json"
        path.write_text(json.dumps(sarif_doc, indent=2) + "\n", encoding="utf-8")
        return path


class MarkdownReporter:
    name = "markdown"

    def write(self, report: AuditReport, out_dir: Path) -> Path:
        path = out_dir / "report.md"
        path.write_text(render_markdown_report(report), encoding="utf-8")
        return path


class JsonManifestReporter:
    name = "manifest"

    def write(self, report: AuditReport, out_dir: Path) -> Path:
        path = out_dir / "manifest.json"
        path.write_text(report.model_dump_json(indent=2) + "\n", encoding="utf-8")
        return path


def register_builtin_reporters(registry: PluginRegistry = default_registry) -> None:
    registry.register_reporter(SarifReporter())
    registry.register_reporter(MarkdownReporter())
    registry.register_reporter(JsonManifestReporter())


register_builtin_reporters(default_registry)


def write_report_bundle(
    report: AuditReport,
    out_dir: Path,
    registry: PluginRegistry | None = None,
) -> dict[str, Path]:
    """Write all registered reporter outputs plus verified patches and regression tests."""
    reg = registry or default_registry
    if reg is default_registry:
        reg.load_entry_point_plugins()

    root = Path(out_dir).resolve()
    root.mkdir(parents=True, exist_ok=True)
    patches_dir = root / "patches"
    reg_dir = root / "regression_tests"
    patches_dir.mkdir(exist_ok=True)
    reg_dir.mkdir(exist_ok=True)

    written: dict[str, Path] = {}
    for reporter in reg.list_reporters():
        written[reporter.name] = reporter.write(report, root)

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
