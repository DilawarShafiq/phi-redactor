"""Serve command -- starts the PHI redaction proxy server.

This module defines the ``serve`` sub-command.  It is lazily loaded by
the root CLI group to avoid pulling in ``uvicorn`` and ``fastapi`` until
the user actually runs ``phi-redactor serve``.
"""

from __future__ import annotations

import click


@click.command("serve")
@click.option("--port", type=int, default=None, help="Proxy port (default: 8080).")
@click.option("--host", type=str, default=None, help="Bind host (default: 0.0.0.0).")
@click.option(
    "--provider",
    type=click.Choice(["openai", "anthropic"], case_sensitive=False),
    default=None,
    help="Default upstream LLM provider.",
)
@click.option(
    "--sensitivity",
    type=float,
    default=None,
    help="Detection sensitivity 0.0-1.0.",
)
@click.option("--dashboard", is_flag=True, help="Enable web dashboard.")
@click.pass_context
def serve(
    ctx: click.Context,
    port: int | None,
    host: str | None,
    provider: str | None,
    sensitivity: float | None,
    dashboard: bool,
) -> None:
    """Start the PHI redaction proxy server."""
    import uvicorn

    from phi_redactor.config import PhiRedactorConfig, setup_logging
    from phi_redactor.proxy.app import create_app

    config: PhiRedactorConfig = ctx.obj["config"]

    # Override config with explicit CLI flags
    if port is not None:
        config.port = port
    if host is not None:
        config.host = host
    if provider is not None:
        config.default_provider = provider
    if sensitivity is not None:
        config.sensitivity = sensitivity
    if dashboard:
        config.dashboard_enabled = True

    setup_logging(config)

    # --- Startup banner ---------------------------------------------------
    separator = "=" * 60
    click.echo(separator)
    click.echo("  phi-redactor -- PHI Redaction Proxy for AI/LLM")
    click.echo(separator)
    click.echo(f"  Proxy:       http://{config.host}:{config.port}")
    click.echo(f"  Provider:    {config.default_provider}")
    click.echo(f"  Sensitivity: {config.sensitivity}")
    click.echo(f"  Vault:       {config.vault_path}")
    click.echo(f"  Audit:       {config.audit_path}")
    click.echo("")
    click.echo(f"  OpenAI:      http://{config.host}:{config.port}/openai/v1")
    click.echo(f"  Anthropic:   http://{config.host}:{config.port}/anthropic/v1")
    click.echo(f"  Redact:      http://{config.host}:{config.port}/api/v1/redact")
    click.echo(f"  Health:      http://{config.host}:{config.port}/api/v1/health")
    if config.dashboard_enabled:
        click.echo(f"  Dashboard:   http://{config.host}:{config.port}/dashboard")
    click.echo(separator)
    click.echo("")

    app = create_app(config)

    uvicorn.run(
        app,
        host=config.host,
        port=config.port,
        log_level=config.log_level.lower(),
    )


# Attribute consumed by _LazyGroup.get_command()
cli_command = serve
