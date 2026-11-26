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
    re.compile(r"^(credentials\.json|service[-_]account.*\.json)$", re.IGNORECASE),
)

RC_AUTH_PATTERNS = re.compile(
    r"(?:_authToken|_auth\b|_password|^\s*password\s*=|://[^/\s:@]+:[^/\s@]+@)",
    re.IGNORECASE | re.MULTILINE,
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

ENV_LINE_RE = re.compile(r"^(\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*)(.+)$")
SECRET_KEY_NAME_RE = re.compile(
    r"(?:SECRET|PASSWORD|PASSWD|TOKEN|API_KEY|PRIVATE_KEY|CREDENTIAL|AUTH|DSN|DATABASE_URL)",
    re.IGNORECASE,
)
PUBLIC_KEY_PREFIXES = ("VITE_", "NEXT_PUBLIC_", "REACT_APP_", "NUXT_PUBLIC_", "PUBLIC_")
PLACEHOLDER_VALUES = {
    "changethis",
    "changeme",
    "change_me",
    "replace_me",
    "your_secret_here",
    "example",
    "dummy",
    "placeholder",
}


def _format_preserving_dummy_value(key_name: str, raw_val: str, is_secret_key: bool) -> str:
    """Return a syntactically valid, zero-secret dummy value containing REDACTED_BY_VULNBOX_<KEY>.

    Every generated value preserves the `REDACTED_BY_VULNBOX_<KEY>` marker while matching
    DSN, URL, email, and minimum-length secret formats so frameworks like SQLAlchemy,
    Pydantic, Redis, and JWT verifiers boot cleanly inside the air-gapped sandbox.
    """
    marker = f"REDACTED_BY_VULNBOX_{key_name}"
    upper = key_name.upper()
    low_val = raw_val.lower()

    if low_val.startswith(("postgres://", "postgresql://")) or upper in ("POSTGRES_URL", "PG_URL"):
        return f"postgresql://vulnbox:{marker}@127.0.0.1:5432/vulnbox"
    if low_val.startswith("sqlite:") or upper in (
        "DATABASE_URL",
        "DB_URL",
        "SQLALCHEMY_DATABASE_URI",
    ):
        return f"sqlite:////tmp/{marker}.db"
    if low_val.startswith(("mysql://", "mysql+pymysql://")) or upper == "MYSQL_URL":
        return f"mysql://vulnbox:{marker}@127.0.0.1:3306/vulnbox"
    if low_val.startswith(("mongodb://", "mongodb+srv://")) or upper in ("MONGO_URL", "MONGODB_URI"):
        return f"mongodb://127.0.0.1:27017/{marker}"
    if low_val.startswith(("redis://", "rediss://")) or "REDIS_URL" in upper or "REDIS_URI" in upper:
        return f"redis://:{marker}@127.0.0.1:6379/0"
    if low_val.startswith(("smtp://", "smtps://")) or "SMTP_URL" in upper:
        return f"smtp://vulnbox:{marker}@127.0.0.1:1025"
    if low_val.startswith(("http://", "https://")) or upper.endswith(
        ("_URL", "_URI", "_ENDPOINT", "_ORIGIN", "_BASE_URL", "_API_URL")
    ):
        return f"http://127.0.0.1:18080/mock/{marker}"
    if ("@" in raw_val and "://" not in raw_val) or upper.endswith("_EMAIL"):
        return f"{marker}@vulnbox.invalid"
    if is_secret_key or any(
        tok in upper for tok in ("SECRET", "JWT", "SIGNING", "KEY", "SALT", "PEPPER", "TOKEN")
    ):
        return f"{marker}_0123456789abcdef0123456789abcdef"
    return marker


def parse_workspace_env_vars(workspace_dir: Path) -> dict[str, str]:
    """Read key=value entries from scrubbed `.env` files inside a sandbox workspace."""
    env_vars: dict[str, str] = {}
    for candidate in (".env", ".env.local", ".env.development"):
        env_file = workspace_dir / candidate
        if not env_file.is_file():
            continue
        try:
            content = env_file.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        for line in content.splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            match = ENV_LINE_RE.match(line)
            if match:
                k = match.group(2)
                v = match.group(3).strip().strip("\"'")
                env_vars[k] = v
    return env_vars


def _classify_and_scrub_env_content(content: str) -> tuple[str, int, str]:
    """Preserve env variable names, redact values with format-preserving dummies, and classify risk.

    Classification:
      - 'real_secret': secret-named key with non-placeholder value
      - 'template_placeholder': secret-named key whose value is a placeholder (e.g. changethis)
      - 'public_only': only public/non-secret config keys (e.g. VITE_API_URL, HOST, PORT)
    """
    redacted = 0
    has_real_secret = False
    has_placeholder_secret = False
    out_lines: list[str] = []

    for line in content.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            out_lines.append(line)
            continue
        match = ENV_LINE_RE.match(line)
        if match:
            prefix, key_name, raw_val = match.group(1), match.group(2), match.group(3).strip().strip("\"'")
            is_public_key = key_name.upper().startswith(PUBLIC_KEY_PREFIXES)
            is_secret_key = (not is_public_key) and bool(SECRET_KEY_NAME_RE.search(key_name))

            if is_secret_key:
                low_val = raw_val.lower()
                # Also recognize postgres://...:${POSTGRES_PASSWORD}@localhost as template ref
                if low_val in PLACEHOLDER_VALUES or "${" in raw_val or "changethis" in low_val:
                    has_placeholder_secret = True
                elif low_val not in ("", "false", "true", "none", "null"):
                    has_real_secret = True

            dummy_val = _format_preserving_dummy_value(key_name, raw_val, is_secret_key)
            out_lines.append(f"{prefix}{dummy_val}")
            redacted += 1
        else:
            out_lines.append(line)

    if has_real_secret:
        classification = "real_secret"
    elif has_placeholder_secret:
        classification = "template_placeholder"
    else:
        classification = "public_only"

    return "\n".join(out_lines) + ("\n" if content.endswith("\n") else ""), redacted, classification


def _is_sensitive_filename(name: str, src_file: Path | None = None) -> bool:
    low = name.lower()
    if low.endswith((".example", ".sample", ".template")):
        return False
    if low in (".npmrc", ".pypirc"):
        if src_file is None:
            return True
        try:
            content = src_file.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            return True
        return bool(RC_AUTH_PATTERNS.search(content))
    return any(p.search(name) for p in SENSITIVE_FILENAME_PATTERNS)


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
    env_classifications: dict[str, str] = {}

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

            if _is_sensitive_filename(fname, src_file):
                files_scrubbed.append(rel_file)
                if fname.lower().startswith(".env"):
                    try:
                        raw = src_file.read_text(encoding="utf-8", errors="ignore")
                        cleaned, count, cls = _classify_and_scrub_env_content(raw)
                        dst_file.write_text(cleaned, encoding="utf-8")
                        secrets_redacted += max(count, 1)
                        env_classifications[rel_file] = cls
                    except OSError:
                        dst_file.write_text("# REDACTED_BY_VULNBOX\n", encoding="utf-8")
                        secrets_redacted += 1
                        env_classifications[rel_file] = "real_secret"
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
        env_classifications=env_classifications,
    )


def cleanup_workspace(workspace_dir: str | Path) -> None:
    """Safely remove an ephemeral sandbox workspace."""
    path = Path(workspace_dir).resolve()
    if path.exists() and path.is_dir():
        shutil.rmtree(path, ignore_errors=True)


class ScrubbedWorkspace:
    """Context manager guaranteeing creation and cleanup of a scrubbed sandbox workspace."""

    def __init__(
        self,
        repo_path: str | Path,
        dest_dir: str | Path | None = None,
    ) -> None:
        self._repo_path = Path(repo_path)
        self._dest_dir = dest_dir
        self._summary: ScrubSummary | None = None

    @property
    def summary(self) -> ScrubSummary:
        if self._summary is None:
            raise RuntimeError("ScrubbedWorkspace has not been entered")
        return self._summary

    @property
    def path(self) -> Path:
        return Path(self.summary.sandbox_dir)

    def __enter__(self) -> ScrubbedWorkspace:
        self._summary = create_scrubbed_workspace(self._repo_path, dest_dir=self._dest_dir)
        return self

    def __exit__(self, *exc_info: object) -> None:
        if self._summary is not None:
            cleanup_workspace(self._summary.sandbox_dir)
