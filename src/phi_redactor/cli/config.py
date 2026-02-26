"""CLI commands for configuration management.

Usage::

    phi-redactor config show
    phi-redactor config providers
"""

from __future__ import annotations

import click


@click.group("config")
def cli_command() -> None:
    """Inspect and manage phi-redactor configuration."""


@cli_command.command("show")
@click.pass_context
def show_config(ctx: click.Context) -> None:
    """Display all current configuration values."""
    config = ctx.obj["config"]

    click.secho("=" * 55, fg="cyan")
    click.secho("  PHI Redactor - Configuration", fg="cyan", bold=True)
    click.secho("=" * 55, fg="cyan")
    click.echo()

    fields = {
        "host": config.host,
        "port": config.port,
        "default_provider": config.default_provider,
        "sensitivity": config.sensitivity,
        "vault_path": str(config.vault_path),
        "audit_path": str(config.audit_path),
        "plugins_dir": str(config.plugins_dir),
        "session_idle_timeout": f"{config.session_idle_timeout}s",
        "session_max_lifetime": f"{config.session_max_lifetime}s",
        "log_level": config.log_level,
        "dashboard_enabled": config.dashboard_enabled,
        "vault_passphrase": "***" if config.vault_passphrase else "(auto-generated)",
    }

    max_key_len = max(len(k) for k in fields)
    for key, value in fields.items():
        click.echo(f"  {key:<{max_key_len}}  {value}")

    click.echo()
    click.secho("=" * 55, fg="cyan")


@cli_command.command("providers")
@click.pass_context
def list_providers(ctx: click.Context) -> None:
    """List configured providers with their status."""
    config = ctx.obj["config"]

    # Known providers and their configuration status
    _KNOWN_PROVIDERS = {
        "openai": {
            "env_var": "OPENAI_API_KEY",
            "description": "OpenAI (GPT-4, GPT-3.5, etc.)",
        },
        "anthropic": {
            "env_var": "ANTHROPIC_API_KEY",
            "description": "Anthropic (Claude models)",
        },
        "google": {
            "env_var": "GOOGLE_API_KEY",
            "description": "Google (Gemini models)",
        },
        "azure": {
            "env_var": "AZURE_OPENAI_API_KEY",
            "description": "Azure OpenAI Service",
        },
    }

    import os

    click.secho("=" * 60, fg="cyan")
    click.secho("  PHI Redactor - Providers", fg="cyan", bold=True)
    click.secho("=" * 60, fg="cyan")
    click.echo()
    click.echo(f"  Default provider: {config.default_provider}")
    click.echo()
    click.secho("  Available Providers:", bold=True)
    click.echo()

    for name, info in _KNOWN_PROVIDERS.items():
        is_default = name == config.default_provider
        has_key = bool(os.environ.get(info["env_var"]))
        key_status = "KEY SET" if has_key else "no key"
        key_color = "green" if has_key else "yellow"
        default_marker = " [default]" if is_default else ""

        click.echo(
            f"  {'*' if is_default else ' '} {name:<12}"
            f" {info['description']:<35}"
            f" "
        )
        click.secho(
            f"    {key_status}{default_marker}",
            fg=key_color,
        )

    click.echo()
    click.secho("=" * 60, fg="cyan")
