"""Plugin loader for extensible PHI detection."""
from __future__ import annotations

import importlib
import importlib.util
import logging
import sys
from pathlib import Path
from typing import Protocol

from presidio_analyzer import PatternRecognizer

logger = logging.getLogger(__name__)


class RecognizerPlugin(Protocol):
    """Protocol that all recognizer plugins must implement."""

    name: str
    version: str

    def get_recognizers(self) -> list[PatternRecognizer]:
        """Return a list of Presidio recognizers provided by this plugin."""
        ...


class PluginLoader:
    """Discovers and loads recognizer plugins from a directory or entry points."""

    def __init__(self) -> None:
        self._plugins: list[RecognizerPlugin] = []

    def load_from_module(self, module_name: str) -> None:
        """Load a plugin from a Python module path."""
        try:
            module = importlib.import_module(module_name)
            plugin = getattr(module, "plugin", None)
            if plugin is None:
                logger.warning("Module %s has no 'plugin' attribute", module_name)
                return
            self._plugins.append(plugin)
            logger.info("Loaded plugin: %s v%s", plugin.name, plugin.version)
        except Exception:
            logger.exception("Failed to load plugin from %s", module_name)

    def load_from_directory(self, directory: str | Path) -> None:
        """Load all .py plugin files from a directory."""
        plugin_dir = Path(directory)
        if not plugin_dir.is_dir():
            logger.warning("Plugin directory does not exist: %s", plugin_dir)
            return

        for py_file in sorted(plugin_dir.glob("*.py")):
            if py_file.name.startswith("_"):
                continue
            module_name = py_file.stem
            spec = importlib.util.spec_from_file_location(module_name, py_file)
            if spec and spec.loader:
                module = importlib.util.module_from_spec(spec)
                sys.modules[module_name] = module
                try:
                    spec.loader.exec_module(module)
                    plugin = getattr(module, "plugin", None)
                    if plugin:
                        self._plugins.append(plugin)
                        logger.info("Loaded plugin from file: %s", py_file.name)
                except Exception:
                    logger.exception("Failed to load plugin from %s", py_file)

    def load_from_entry_points(self, group: str = "phi_redactor.plugins") -> None:
        """Load plugins registered via setuptools entry points."""
        try:
            from importlib.metadata import entry_points

            eps = entry_points()
            plugin_eps = (
                eps.get(group, [])
                if isinstance(eps, dict)
                else eps.select(group=group)
            )
            for ep in plugin_eps:
                try:
                    plugin = ep.load()
                    self._plugins.append(plugin)
                    logger.info("Loaded entry point plugin: %s", ep.name)
                except Exception:
                    logger.exception("Failed to load entry point: %s", ep.name)
        except Exception:
            logger.debug("Entry point loading not available")

    @property
    def plugins(self) -> list[RecognizerPlugin]:
        """Return a copy of the loaded plugins list."""
        return list(self._plugins)

    def get_all_recognizers(self) -> list[PatternRecognizer]:
        """Collect recognizers from all loaded plugins."""
        recognizers: list[PatternRecognizer] = []
        for plugin in self._plugins:
            try:
                recognizers.extend(plugin.get_recognizers())
            except Exception:
                logger.exception(
                    "Failed to get recognizers from plugin %s", plugin.name
                )
        return recognizers
