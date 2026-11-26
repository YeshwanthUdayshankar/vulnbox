"""Pre-sandbox secret scrubbing and ephemeral workspace cloning."""

from __future__ import annotations

import os
import re
import shutil
import tempfile
from pathlib import Path

from vulnbox.models import ScrubSummary

EXCLUDED_DIRS = {
    ".git",
    ".venv",
    "venv",
    "__pycache__",
    ".pytest_cache",
    ".ruff_cache",
    "vulnbox-out",
}

SENSITIVE_FILENAME_PATTERNS = (
    re.compile(r"^\.env(\..+)?$", re.IGNORECASE),
    re.compile(r"\.(pem|key|p12|pfx|jks)$", re.IGNORECASE),
    re.compile(r"^id_(rsa|ed25519|ecdsa)(\.pub)?$", re.IGNORECASE),
    re.compile(r"^(\.npmrc|\.pypirc|credentials\.json|service[-_]account.*\.json)$", re.IGNORECASE),
)

SECRET_TOKEN_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("AWS_ACCESS_KEY", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("GITHUB_TOKEN", re.compile(r"gh[pousr]_[A-Za-z0-9_]{20,}")),
    ("OPENAI_KEY", re.compile(r"sk-[A-Za-z0-9]{20,}")),
    (
        "PRIVATE_KEY_BLOCK",
        re.compile(
            r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----"
        ),
    ),
]

ENV_LINE_RE = re.compile(r"^(\s*(?:export\s+)?[A-Za-z_][A-Za-z0-9_]*\s*=\s*)(.+)$")


def _is_sensitive_filename(name: str) -> bool:
    if name.lower().endswith((".example", ".sample", ".template")):
        return False
    return any(p.search(name) for p in SENSITIVE_FILENAME_PATTERNS)


def _scrub_env_content(content: str) -> tuple[str, int]:
    """Preserve env variable names while replacing real values with safe placeholders."""
    redacted = 0
    out_lines: list[str] = []
    for line in content.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            out_lines.append(line)
            continue
        match = ENV_LINE_RE.match(line)
        if match:
            prefix = match.group(1)
            key_name = prefix.replace("export", "").strip().rstrip("=").strip()
            out_lines.append(f"{prefix}REDACTED_BY_VULNBOX_{key_name}")
            redacted += 1
        else:
            out_lines.append(line)
    return "\n".join(out_lines) + ("\n" if content.endswith("\n") else ""), redacted


def _scrub_text_tokens(content: str) -> tuple[str, int]:
    """Redact high-confidence live secret tokens inside source/config text."""
    total = 0
    updated = content
    for label, pattern in SECRET_TOKEN_PATTERNS:
        updated, count = pattern.subn(f"REDACTED_BY_VULNBOX_{label}", updated)
        total += count
    return updated, total


def create_scrubbed_workspace(
    repo_path: str | Path,
    dest_dir: str | Path | None = None,
) -> ScrubSummary:
    """Copy a repository to an ephemeral directory and scrub secrets/credentials.

    The source repository is strictly read-only and never modified.
    """
    src_root = Path(repo_path).resolve()
    if not src_root.is_dir():
        raise FileNotFoundError(f"Repository directory not found: {src_root}")

    if dest_dir is None:
        workspace = Path(tempfile.mkdtemp(prefix="vulnbox-ws-")).resolve()
    else:
        workspace = Path(dest_dir).resolve()
        workspace.mkdir(parents=True, exist_ok=True)

    files_copied = 0
    files_scrubbed: list[str] = []
    secrets_redacted = 0
    excluded_paths: list[str] = []

    for dirpath, dirnames, filenames in os.walk(src_root):
        rel_dir = Path(dirpath).relative_to(src_root)

        kept_dirs: list[str] = []
        for d in sorted(dirnames):
            if d in EXCLUDED_DIRS:
                excluded_paths.append(str(rel_dir / d) if str(rel_dir) != "." else d)
            else:
                kept_dirs.append(d)
        dirnames[:] = kept_dirs

        target_dir = workspace / rel_dir
        target_dir.mkdir(parents=True, exist_ok=True)

        for fname in sorted(filenames):
            src_file = Path(dirpath) / fname
            rel_file = str(rel_dir / fname) if str(rel_dir) != "." else fname
            dst_file = target_dir / fname

            if src_file.is_symlink():
                excluded_paths.append(rel_file)
                continue

            if _is_sensitive_filename(fname):
                files_scrubbed.append(rel_file)
                if fname.lower().startswith(".env"):
                    try:
                        raw = src_file.read_text(encoding="utf-8", errors="ignore")
                        cleaned, count = _scrub_env_content(raw)
                        dst_file.write_text(cleaned, encoding="utf-8")
                        secrets_redacted += max(count, 1)
                    except OSError:
                        dst_file.write_text("# REDACTED_BY_VULNBOX\n", encoding="utf-8")
                        secrets_redacted += 1
                else:
                    dst_file.write_text("REDACTED_BY_VULNBOX_SENSITIVE_FILE\n", encoding="utf-8")
                    secrets_redacted += 1
                files_copied += 1
                continue

            # Copy normal file; scrub inline secret tokens for text files under 2 MB
            try:
                size = src_file.stat().st_size
                if size <= 2 * 1024 * 1024:
                    raw_bytes = src_file.read_bytes()
                    if b"\x00" not in raw_bytes:
                        text = raw_bytes.decode("utf-8", errors="ignore")
                        cleaned, count = _scrub_text_tokens(text)
                        if count > 0:
                            dst_file.write_text(cleaned, encoding="utf-8")
                            files_scrubbed.append(rel_file)
                            secrets_redacted += count
                            files_copied += 1
                            continue
                shutil.copy2(src_file, dst_file)
                files_copied += 1
            except OSError:
                excluded_paths.append(rel_file)

    return ScrubSummary(
        sandbox_dir=str(workspace),
        files_copied=files_copied,
        files_scrubbed=sorted(set(files_scrubbed)),
        secrets_redacted=secrets_redacted,
        excluded_paths=sorted(set(excluded_paths)),
    )


def cleanup_workspace(workspace_dir: str | Path) -> None:
    """Safely remove an ephemeral sandbox workspace."""
    path = Path(workspace_dir).resolve()
    if path.exists() and path.is_dir():
        shutil.rmtree(path, ignore_errors=True)
