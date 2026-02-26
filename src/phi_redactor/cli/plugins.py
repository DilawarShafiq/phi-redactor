"""CLI commands for plugin management."""
from __future__ import annotations

import click


@click.group("plugins")
def plugins_group() -> None:
    """Manage PHI detection plugins."""


@plugins_group.command("list")
@click.option("--directory", "-d", default=None, help="Plugin directory to scan.")
def list_plugins(directory: str | None) -> None:
    """List loaded plugins and their recognizers."""
    from phi_redactor.plugins import PluginLoader

    loader = PluginLoader()
    loader.load_from_entry_points()

    if directory:
        loader.load_from_directory(directory)

    plugins = loader.plugins
    if not plugins:
        click.echo("No plugins loaded.")
        return

    for p in plugins:
        click.echo(f"  {p.name} v{p.version}")
        for r in p.get_recognizers():
            click.echo(f"    - {r.supported_entities}")


@plugins_group.command("validate")
@click.argument("module_name")
def validate_plugin(module_name: str) -> None:
    """Validate a plugin module can be loaded."""
    from phi_redactor.plugins import PluginLoader

    loader = PluginLoader()
    loader.load_from_module(module_name)

    if loader.plugins:
        p = loader.plugins[0]
        recognizers = p.get_recognizers()
        click.secho(f"Valid plugin: {p.name} v{p.version}", fg="green")
        click.echo(f"  Provides {len(recognizers)} recognizer(s)")
    else:
        click.secho(f"Failed to load plugin: {module_name}", fg="red")


# Expose the group as cli_command for lazy loading from main.py
cli_command = plugins_group
