"""VulnBox: Sandboxed security verification, active probing, and dual-verified remediation."""

from vulnbox._version import __version__
from vulnbox.engine import VulnBoxEngine
from vulnbox.registry import AnalysisContext, PluginRegistry, default_registry
from vulnbox.scrubber import ScrubbedWorkspace

__all__ = [
    "AnalysisContext",
    "PluginRegistry",
    "ScrubbedWorkspace",
    "VulnBoxEngine",
    "__version__",
    "default_registry",
]
