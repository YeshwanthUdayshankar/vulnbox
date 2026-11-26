"""Tests for monorepo discovery, curl|bash rule, and smart .env severity triage."""

from __future__ import annotations

import json
from pathlib import Path

from vulnbox.analyzers import run_all_analyzers
from vulnbox.profiler import profile_repo
from vulnbox.scrubber import cleanup_workspace, create_scrubbed_workspace


def test_monorepo_nested_manifests_and_curl_pipe_bash_and_env_triage(tmp_path: Path):
    (tmp_path / "backend" / "app").mkdir(parents=True)
    (tmp_path / "frontend").mkdir(parents=True)

    (tmp_path / "backend" / "pyproject.toml").write_text(
        '[project]\nname = "api"\ndependencies = ["fastapi>=0.115.0", "PyYAML==5.3.1"]\n',
        encoding="utf-8",
    )
    (tmp_path / "backend" / "app" / "main.py").write_text(
        "from fastapi import FastAPI\napp = FastAPI()\n",
        encoding="utf-8",
    )
    (tmp_path / "frontend" / "package.json").write_text(
        json.dumps({"name": "web", "dependencies": {"react": "^19.0.0", "lodash": "4.17.20"}}),
        encoding="utf-8",
    )
    (tmp_path / "frontend" / "Dockerfile.playwright").write_text(
        "FROM mcr.microsoft.com/playwright:v1.50.0\n"
        "RUN curl -fsSL https://bun.sh/install | bash\n"
        "USER pwuser\n",
        encoding="utf-8",
    )
    # 3 distinct .env risk levels
    (tmp_path / ".env").write_text(
        "SECRET_KEY=changethis\nPOSTGRES_PASSWORD=changethis\n",
        encoding="utf-8",
    )
    (tmp_path / "frontend" / ".env").write_text(
        "VITE_API_URL=http://localhost:8000\nMAILPIT_HOST=http://localhost:8025\n",
        encoding="utf-8",
    )
    (tmp_path / "backend" / ".env").write_text(
        "SECRET_KEY=prod_real_secret_value_999\n",
        encoding="utf-8",
    )

    prof = profile_repo(tmp_path)
    assert prof.ecosystem == "mixed"
    assert "backend/pyproject.toml" in prof.manifests
    assert "frontend/package.json" in prof.manifests
    assert "fastapi" in prof.frameworks
    assert "react" in prof.frameworks

    scrub = create_scrubbed_workspace(tmp_path)
    ws = Path(scrub.sandbox_dir)
    try:
        findings = run_all_analyzers(ws, scrub_summary=scrub)
        by_rule_file = {(f.rule_id, f.file_path): f for f in findings}

        # CFG-DOCKER-005 catches curl | bash
        assert ("CFG-DOCKER-005", "frontend/Dockerfile.playwright") in by_rule_file

        # Nested monorepo dependency CVEs detected
        assert ("DEP-CVE-2020-14343", "backend/pyproject.toml") in by_rule_file
        assert ("DEP-CVE-2021-23337", "frontend/package.json") in by_rule_file

        # Smart .env severity triage
        assert by_rule_file[("CFG-SECRET-001", "frontend/.env")].severity == "low"
        assert by_rule_file[("CFG-SECRET-001", ".env")].severity == "medium"
        assert by_rule_file[("CFG-SECRET-001", "backend/.env")].severity == "high"
    finally:
        cleanup_workspace(ws)


def test_real_world_precision_multistage_docker_yarn_test_dir_and_static_shell(tmp_path: Path):
    # 1. Vendored .yarn release must be ignored
    (tmp_path / ".yarn" / "releases").mkdir(parents=True)
    (tmp_path / ".yarn" / "releases" / "yarn-4.0.cjs").write_text("eval(x); new Function(y);\n", encoding="utf-8")

    # 2. Singular `pkg/test/` helper dir must be skipped
    (tmp_path / "pkg" / "test").mkdir(parents=True)
    (tmp_path / "pkg" / "test" / "helper.py").write_text(
        "import os\ndef f(x):\n    return open(os.path.join('/tmp', x)).read()\n",
        encoding="utf-8",
    )

    # 3. Docker multi-stage AS alias + ARG default should not trigger CFG-DOCKER-002
    (tmp_path / "Dockerfile").write_text(
        "ARG BASE_IMAGE=python:3.12-slim\n"
        "FROM ${BASE_IMAGE} AS base\n"
        "FROM base AS builder\n"
        "FROM base\n"
        "USER appuser\n",
        encoding="utf-8",
    )

    # 4. Static literal vs dynamic subprocess(..., shell=True)
    (tmp_path / "build_hook.py").write_text(
        "import subprocess\n"
        "def build(user_arg):\n"
        "    subprocess.check_output('yarn build', shell=True)\n"
        "    subprocess.check_output(f'yarn {user_arg}', shell=True)\n",
        encoding="utf-8",
    )

    findings = run_all_analyzers(tmp_path)
    assert not any(".yarn" in f.file_path for f in findings)
    assert not any("pkg/test" in f.file_path for f in findings)
    assert not any(f.rule_id == "CFG-DOCKER-002" for f in findings)

    cmd_findings = sorted(
        [f for f in findings if f.rule_id == "PY-CMD-001"],
        key=lambda f: f.start_line,
    )
    assert len(cmd_findings) == 2
    assert cmd_findings[0].severity == "low"
    assert cmd_findings[1].severity == "critical"


def test_node_and_scrubber_precision_orm_exec_local_emitters_npmrc_and_i18n(tmp_path: Path):
    # 1. Benign .npmrc without auth tokens should NOT trigger CFG-SECRET-002
    (tmp_path / ".npmrc").write_text("legacy-peer-deps=true\n", encoding="utf-8")

    # 2. i18n locale JSON with placeholder token example should NOT trigger CFG-SECRET-002
    (tmp_path / "src" / "lang").mkdir(parents=True)
    (tmp_path / "src" / "lang" / "en.json").write_text(
        json.dumps({"apiKeyHint": "Example OpenAI key: sk-1234567890abcdefghij1234"}),
        encoding="utf-8",
    )

    # 3. Module-init loop (not in a function) should NOT trigger MEM-JS-001
    (tmp_path / "src" / "i18n.js").write_text(
        "const messages = {};\n"
        "for (const k of ['en']) { messages[k] = { ok: true }; }\n",
        encoding="utf-8",
    )

    # 4. ORM R.exec SQL + short-lived local client.on should NOT trigger JS-CMD-001 / MEM-JS-002
    (tmp_path / "server.js").write_text(
        "async function handle(req, res, slots) {\n"
        "  await R.exec(`DELETE FROM items WHERE id NOT IN (${slots})`);\n"
        "  const client = createClient();\n"
        "  client.on('connect', () => res.end('ok'));\n"
        "}\n",
        encoding="utf-8",
    )

    scrub = create_scrubbed_workspace(tmp_path)
    ws = Path(scrub.sandbox_dir)
    try:
        findings = run_all_analyzers(ws, scrub_summary=scrub)
        assert not findings, f"Expected 0 false positives, got: {findings}"
    finally:
        cleanup_workspace(ws)
