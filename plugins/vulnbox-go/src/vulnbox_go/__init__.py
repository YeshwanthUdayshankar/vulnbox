"""Reference Go plugin pack for VulnBox (`vulnbox.plugins` entry point)."""

from __future__ import annotations

from vulnbox.registry import PluginRegistry
from vulnbox_go.analyzer import GoSASTAnalyzer, GoSASTPlugin


def register(registry: PluginRegistry) -> None:
    """Entry-point hook discovered automatically by VulnBox via `vulnbox.plugins`."""
    registry.register_analyzer(GoSASTPlugin())


__all__ = ["GoSASTAnalyzer", "GoSASTPlugin", "register"]
