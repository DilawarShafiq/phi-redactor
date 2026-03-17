"""phi-redactor Custom Recognizer SDK.

Provides everything a plugin author needs to extend phi-redactor's PHI
detection with custom entity recognizers — without forking the project.

Quick start
-----------

1. Install phi-redactor::

    pip install phi-redactor

2. Create a plugin module (e.g. ``my_plugin.py``)::

    from phi_redactor.sdk import PatternRecognizer, Pattern, RecognizerPlugin, plugin_class

    class EmployeeIDRecognizer(PatternRecognizer):
        PATTERNS = [Pattern("employee_id", r"EMP-\\d{6}", 0.85)]
        CONTEXT = ["employee", "staff", "id"]

        def __init__(self, **kwargs):
            super().__init__(
                supported_entity="EMPLOYEE_ID",
                patterns=self.PATTERNS,
                context=self.CONTEXT,
                supported_language="en",
                **kwargs,
            )

    @plugin_class
    class MyPlugin:
        name = "my-employee-id-plugin"
        version = "1.0.0"

        def get_recognizers(self):
            return [EmployeeIDRecognizer()]

    plugin = MyPlugin()

3. Register it via setuptools entry points in your ``pyproject.toml``::

    [project.entry-points."phi_redactor.plugins"]
    my-plugin = "my_plugin:plugin"

   Or load it at runtime::

    phi-redactor serve --plugins-dir ./my_plugins/

4. Or load it programmatically::

    from phi_redactor.plugins.loader import PluginLoader
    loader = PluginLoader()
    loader.load_from_module("my_plugin")

SDK contents
------------

The following names are re-exported for plugin authors:

* :class:`PatternRecognizer` — Presidio base class for regex/pattern recognizers
* :class:`Pattern` — Presidio pattern descriptor (regex + confidence score)
* :class:`EntityRecognizer` — Presidio base class for all recognizer types
* :class:`RecognizerResult` — Presidio result type (start, end, score, entity_type)
* :class:`RecognizerPlugin` — Protocol that every plugin must satisfy
* :class:`PluginLoader` — Runtime plugin loader (module, directory, entry_points)
* :func:`plugin_class` — Identity decorator for documenting plugin classes
"""

from __future__ import annotations

from presidio_analyzer import EntityRecognizer, Pattern, PatternRecognizer, RecognizerResult

from phi_redactor.plugins.loader import PluginLoader, RecognizerPlugin

__all__ = [
    "EntityRecognizer",
    "Pattern",
    "PatternRecognizer",
    "PluginLoader",
    "RecognizerPlugin",
    "RecognizerResult",
    "plugin_class",
]


def plugin_class(cls):  # type: ignore[no-untyped-def]
    """Identity decorator that marks a class as a phi-redactor plugin.

    Using this decorator is optional — it serves as documentation and
    makes the intent explicit when reading plugin source code.

    Example::

        @plugin_class
        class MyPlugin:
            name = "my-plugin"
            version = "1.0.0"

            def get_recognizers(self):
                return [MyRecognizer()]
    """
    return cls
