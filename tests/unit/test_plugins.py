"""Unit tests for the plugin system."""
from __future__ import annotations

from pathlib import Path

import pytest

from phi_redactor.plugins.loader import PluginLoader


class TestPluginLoader:
    def test_load_example_plugin(self) -> None:
        loader = PluginLoader()
        loader.load_from_module("phi_redactor.plugins.example_plugin")
        assert len(loader.plugins) == 1
        assert loader.plugins[0].name == "example-custom-id"

    def test_get_recognizers_from_example(self) -> None:
        loader = PluginLoader()
        loader.load_from_module("phi_redactor.plugins.example_plugin")
        recognizers = loader.get_all_recognizers()
        assert len(recognizers) >= 1
        entities = [e for r in recognizers for e in r.supported_entities]
        assert "CUSTOM_ID" in entities

    def test_load_nonexistent_module(self) -> None:
        loader = PluginLoader()
        loader.load_from_module("nonexistent.module.xyz")
        assert len(loader.plugins) == 0

    def test_load_from_nonexistent_directory(self, tmp_dir: Path) -> None:
        loader = PluginLoader()
        loader.load_from_directory(tmp_dir / "does_not_exist")
        assert len(loader.plugins) == 0

    def test_empty_plugins_returns_empty_recognizers(self) -> None:
        loader = PluginLoader()
        assert loader.get_all_recognizers() == []

    def test_load_from_directory(self, tmp_dir: Path) -> None:
        """Test loading a plugin from a directory of .py files."""
        plugin_file = tmp_dir / "test_plug.py"
        plugin_file.write_text(
            'from dataclasses import dataclass\n'
            'from presidio_analyzer import PatternRecognizer\n'
            '\n'
            '@dataclass\n'
            'class _P:\n'
            '    name: str = "dir-plugin"\n'
            '    version: str = "0.0.1"\n'
            '    def get_recognizers(self) -> list[PatternRecognizer]:\n'
            '        return []\n'
            '\n'
            'plugin = _P()\n'
        )
        loader = PluginLoader()
        loader.load_from_directory(tmp_dir)
        assert len(loader.plugins) == 1
        assert loader.plugins[0].name == "dir-plugin"

    def test_load_from_entry_points_no_crash(self) -> None:
        """Entry-point loading should not raise even if no plugins are installed."""
        loader = PluginLoader()
        loader.load_from_entry_points()
        # Should not raise; may return 0 plugins
        assert isinstance(loader.plugins, list)
