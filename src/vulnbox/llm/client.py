"""Zero-dependency OpenAI-compatible HTTP LLM client + deterministic mock provider."""

from __future__ import annotations

import json
import os
import re
import urllib.error
import urllib.request
from collections.abc import Callable
from typing import Any
from urllib.parse import urlparse

from pydantic import BaseModel

BLOCKED_LLM_METADATA_HOSTS = frozenset(
    {
        "169.254.169.254",
        "169.254.170.2",
        "metadata.google.internal",
        "metadata.goog",
        "fd00:ec2::254",
    }
)


def validate_llm_base_url(url: str) -> None:
    """Reject non-HTTP(S) schemes (e.g. file://) and cloud metadata SSRF hosts."""
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise ValueError(
            f"Unsupported LLM base URL scheme {parsed.scheme!r}; only 'http' and 'https' are allowed."
        )
    host = (parsed.hostname or "").lower()
    if not host:
        raise ValueError(f"LLM base URL is missing a hostname: {url!r}")
    if host in BLOCKED_LLM_METADATA_HOSTS or host.startswith("169.254."):
        raise ValueError(f"Refusing LLM base URL pointing to link-local/metadata host: {host!r}")

PROVIDER_DEFAULTS: dict[str, tuple[str, str, str | None]] = {
    # provider: (base_url, default_model, api_key_env)
    "ollama": ("http://127.0.0.1:11434/v1", "qwen2.5-coder:7b", None),
    "openai": ("https://api.openai.com/v1", "gpt-4.1-mini", "OPENAI_API_KEY"),
    "gemini": (
        "https://generativelanguage.googleapis.com/v1beta/openai",
        "gemini-2.5-flash",
        "GEMINI_API_KEY",
    ),
    "custom": ("http://127.0.0.1:8000/v1", "default", "VULNBOX_LLM_API_KEY"),
    "mock": ("mock://local", "vulnbox-mock-v1", None),
}


class LLMConfig(BaseModel):
    """Runtime configuration for optional LLM-assisted remediation."""

    provider: str = "ollama"
    model: str | None = None
    base_url: str | None = None
    api_key: str | None = None
    timeout_sec: int = 60
    temperature: float = 0.0

    def resolved_base_url(self) -> str:
        if self.base_url:
            return self.base_url.rstrip("/")
        default_url, _, _ = PROVIDER_DEFAULTS.get(
            self.provider.lower(), PROVIDER_DEFAULTS["custom"]
        )
        return default_url.rstrip("/")

    def resolved_model(self) -> str:
        if self.model:
            return self.model
        _, default_model, _ = PROVIDER_DEFAULTS.get(
            self.provider.lower(), PROVIDER_DEFAULTS["custom"]
        )
        return default_model

    def resolved_api_key(self) -> str | None:
        if self.api_key:
            return self.api_key
        _, _, env_var = PROVIDER_DEFAULTS.get(
            self.provider.lower(), PROVIDER_DEFAULTS["custom"]
        )
        if env_var and os.environ.get(env_var):
            return os.environ[env_var]
        return os.environ.get("VULNBOX_LLM_API_KEY") or os.environ.get("OPENAI_API_KEY")


def _extract_json_object(raw_text: str) -> dict[str, Any]:
    """Strip optional markdown code fences and parse a strict JSON object."""
    cleaned = raw_text.strip()
    fence_match = re.search(r"```(?:json)?\s*(\{[\s\S]*\})\s*```", cleaned)
    if fence_match:
        cleaned = fence_match.group(1)
    else:
        first = cleaned.find("{")
        last = cleaned.rfind("}")
        if first != -1 and last != -1 and last > first:
            cleaned = cleaned[first : last + 1]
    parsed = json.loads(cleaned)
    if not isinstance(parsed, dict):
        raise ValueError("LLM response JSON must be an object")
    return parsed


class OpenAICompatLLMClient:
    """Calls any OpenAI-compatible /chat/completions endpoint using stdlib urllib."""

    def __init__(
        self,
        config: LLMConfig,
        mock_handler: Callable[[str, str, int], dict[str, Any]] | None = None,
    ) -> None:
        self.config = config
        self.mock_handler = mock_handler
        self._call_count = 0

    def complete_json(self, system_prompt: str, user_prompt: str) -> dict[str, Any]:
        """Request a structured JSON object response from the configured LLM."""
        self._call_count += 1

        if self.config.provider.lower() == "mock":
            if self.mock_handler is None:
                raise RuntimeError("Mock provider requires a mock_handler callback")
            return self.mock_handler(system_prompt, user_prompt, self._call_count)

        base_url = self.config.resolved_base_url()
        validate_llm_base_url(base_url)
        url = f"{base_url}/chat/completions"
        headers = {"Content-Type": "application/json"}
        api_key = self.config.resolved_api_key()
        if api_key:
            headers["Authorization"] = f"Bearer {api_key}"

        payload: dict[str, Any] = {
            "model": self.config.resolved_model(),
            "temperature": self.config.temperature,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            "response_format": {"type": "json_object"},
        }
        body = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(url, data=body, headers=headers, method="POST")

        try:
            with urllib.request.urlopen(req, timeout=self.config.timeout_sec) as resp:
                resp_data = json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            err_body = exc.read(500).decode("utf-8", errors="ignore")
            raise RuntimeError(f"LLM HTTP {exc.code} from {url}: {err_body}") from exc
        except urllib.error.URLError as exc:
            raise RuntimeError(f"Failed to connect to LLM endpoint {url}: {exc}") from exc

        choices = resp_data.get("choices") or []
        if not choices:
            raise RuntimeError("LLM returned no choices")
        content = choices[0].get("message", {}).get("content", "")
        if not isinstance(content, str) or not content.strip():
            raise RuntimeError("LLM returned empty message content")
        return _extract_json_object(content)
