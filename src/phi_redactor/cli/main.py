"""CLI entry point for phi-redactor.

The ``cli`` Click group is the root command.  Sub-commands (``serve``,
``redact``, ``version``) are registered via lazy imports to avoid circular
dependencies and speed up ``--help``.

Configuration precedence (highest first):
    1. CLI flags (``--port``, ``--verbose``, etc.)
    2. Environment variables (``PHI_REDACTOR_*``)
    3. ``.env`` file
    4. Built-in defaults
"""

from __future__ import annotations

import importlib
from typing import Any

import click


class _LazyGroup(click.Group):
    """Click group that lazily loads sub-commands from a mapping.

    This avoids importing heavy dependencies (uvicorn, spaCy, etc.)
    until the user actually invokes the relevant sub-command.
    """

    _lazy_commands: dict[str, str]

    def __init__(self, *args: Any, lazy_commands: dict[str, str] | None = None, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._lazy_commands = lazy_commands or {}

    def list_commands(self, ctx: click.Context) -> list[str]:
        """Return sorted list of all registered and lazy command names."""
        base = super().list_commands(ctx)
        lazy = sorted(self._lazy_commands.keys())
        return sorted(set(base + lazy))

    def get_command(self, ctx: click.Context, cmd_name: str) -> click.Command | None:
        """Resolve a command, lazily importing if necessary."""
        # Try eagerly-registered commands first
        cmd = super().get_command(ctx, cmd_name)
        if cmd is not None:
            return cmd
        # Lazy load
        if cmd_name in self._lazy_commands:
            module_path = self._lazy_commands[cmd_name]
            mod = importlib.import_module(module_path)
            return mod.cli_command  # type: ignore[no-any-return]
        return None


@click.group(
    cls=_LazyGroup,
    lazy_commands={
        "serve": "phi_redactor.cli.serve",
        "redact": "phi_redactor.cli.redact",
        "report": "phi_redactor.cli.report",
        "sessions": "phi_redactor.cli.sessions",
        "config": "phi_redactor.cli.config",
        "plugins": "phi_redactor.cli.plugins",
    },
)
@click.option(
    "--config",
    type=click.Path(exists=False),
    default=None,
    help="Path to config YAML file.",
)
@click.option("--verbose", is_flag=True, help="Enable debug logging.")
@click.option("--json-output", is_flag=True, help="Output in JSON format.")
@click.pass_context
def cli(ctx: click.Context, config: str | None, verbose: bool, json_output: bool) -> None:
    """phi-redactor: HIPAA-native PHI redaction proxy for AI/LLM interactions."""
    ctx.ensure_object(dict)
    ctx.obj["verbose"] = verbose
    ctx.obj["json_output"] = json_output

    from phi_redactor.config import PhiRedactorConfig

    if config:
        # Future: parse YAML config file and pass values into PhiRedactorConfig.
        # For now we rely on env-var / .env resolution from pydantic-settings.
        cfg = PhiRedactorConfig()
    else:
        cfg = PhiRedactorConfig()

    if verbose:
        cfg.log_level = "DEBUG"

    ctx.obj["config"] = cfg


@cli.command()
def version() -> None:
    """Show phi-redactor version."""
    from phi_redactor import __version__

    click.echo(f"phi-redactor v{__version__}")
