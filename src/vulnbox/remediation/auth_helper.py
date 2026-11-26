"""Authentication helpers and stdlib HS256 test-JWT minter for sandbox probes."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
from pathlib import Path
from typing import Any

from vulnbox.scrubber import parse_workspace_env_vars

DEFAULT_SANDBOX_JWT_SECRET = "REDACTED_BY_VULNBOX_JWT_SECRET_0123456789abcdef0123456789abcdef"
_JWT_SECRET_CANDIDATE_KEYS = (
    "JWT_SECRET",
    "JWT_SECRET_KEY",
    "AUTH_SECRET",
    "SECRET_KEY",
    "APP_SECRET",
    "TOKEN_SECRET",
)


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def mint_hs256_jwt(
    claims: dict[str, Any],
    secret: str,
    ttl_seconds: int = 3600,
) -> str:
    """Mint a valid HS256 JWT using pure Python stdlib (`hmac` + `hashlib`)."""
    now = int(time.time())
    payload = dict(claims)
    payload.setdefault("sub", "vulnbox-test-user")
    payload.setdefault("iat", now)
    payload.setdefault("exp", now + ttl_seconds)

    header_b64 = _b64url(json.dumps({"alg": "HS256", "typ": "JWT"}, separators=(",", ":")).encode())
    payload_b64 = _b64url(json.dumps(payload, separators=(",", ":")).encode())
    signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
    sig = hmac.new(secret.encode("utf-8"), signing_input, hashlib.sha256).digest()
    return f"{header_b64}.{payload_b64}.{_b64url(sig)}"


def find_sandbox_jwt_secret(workspace_dir: Path | None) -> str:
    """Discover the scrubbed dummy JWT secret in a sandbox workspace's `.env`."""
    if workspace_dir is None or not workspace_dir.is_dir():
        return DEFAULT_SANDBOX_JWT_SECRET
    env_vars = parse_workspace_env_vars(workspace_dir)
    for key in _JWT_SECRET_CANDIDATE_KEYS:
        val = env_vars.get(key)
        if val:
            return val
    return DEFAULT_SANDBOX_JWT_SECRET


def resolve_auth_headers(
    auth_header: str | None = None,
    auth_jwt_claims: str | dict[str, Any] | None = None,
    workspace_dir: Path | None = None,
) -> dict[str, str]:
    """Build probe authentication headers from `--auth-header` and/or `--auth-jwt-claims`."""
    headers: dict[str, str] = {}
    if auth_jwt_claims:
        if isinstance(auth_jwt_claims, str):
            claims_dict: dict[str, Any] = json.loads(auth_jwt_claims)
        else:
            claims_dict = dict(auth_jwt_claims)
        secret = find_sandbox_jwt_secret(workspace_dir)
        token = mint_hs256_jwt(claims_dict, secret=secret)
        headers["Authorization"] = f"Bearer {token}"

    if auth_header:
        if ":" in auth_header:
            k, v = auth_header.split(":", 1)
            headers[k.strip()] = v.strip()
        else:
            headers["Authorization"] = auth_header.strip()

    return headers
