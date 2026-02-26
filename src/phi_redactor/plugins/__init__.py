"""Plugin system for extensible PHI detection.

Plugins can register custom Presidio recognizers via:
- Python module paths
- Plugin directories
- Setuptools entry points (group: ``phi_redactor.plugins``)
"""

from phi_redactor.plugins.loader import PluginLoader, RecognizerPlugin

__all__ = ["PluginLoader", "RecognizerPlugin"]
