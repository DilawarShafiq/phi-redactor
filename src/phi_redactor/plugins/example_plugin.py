"""Example plugin demonstrating the phi-redactor plugin interface.

To use: load this module via PluginLoader.load_from_module()
"""
from __future__ import annotations

from dataclasses import dataclass

from presidio_analyzer import Pattern, PatternRecognizer


class CustomIDRecognizer(PatternRecognizer):
    """Example recognizer for a custom internal ID format."""

    PATTERNS = [
        Pattern("custom_id", r"CUST-[A-Z]{2}\d{6}", 0.8),
    ]
    CONTEXT = ["customer", "id", "identifier", "reference"]

    def __init__(self, **kwargs) -> None:
        super().__init__(
            supported_entity="CUSTOM_ID",
            patterns=self.PATTERNS,
            context=self.CONTEXT,
            supported_language="en",
            **kwargs,
        )


@dataclass
class ExamplePlugin:
    """Example plugin that provides a single custom ID recognizer."""

    name: str = "example-custom-id"
    version: str = "0.1.0"

    def get_recognizers(self) -> list[PatternRecognizer]:
        """Return the list of recognizers provided by this plugin."""
        return [CustomIDRecognizer()]


# Module-level plugin instance (required by PluginLoader)
plugin = ExamplePlugin()
