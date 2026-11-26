"""Single source of truth for VulnBox package version."""

from __future__ import annotations

import importlib.metadata

try:
    __version__ = importlib.metadata.version("vulnbox")
except importlib.metadata.PackageNotFoundError:
    __version__ = "0.1.0"
