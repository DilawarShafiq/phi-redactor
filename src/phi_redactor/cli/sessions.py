"""CLI commands for session management.

Usage::

    phi-redactor sessions list
    phi-redactor sessions inspect <session_id>
    phi-redactor sessions close <session_id>
    phi-redactor sessions cleanup
"""

from __future__ import annotations

import click


@click.group("sessions")
def cli_command() -> None:
    """Manage PHI redaction sessions."""


@cli_command.command("list")
@click.pass_context
def list_sessions(ctx: click.Context) -> None:
    """List active and expired sessions with counts."""
    from phi_redactor.vault.store import PhiVault

    config = ctx.obj["config"]
    vault = PhiVault(db_path=str(config.vault_path))

    try:
        total = vault.get_session_count()
        entries = vault.get_mapping_count()

        click.secho("=" * 50, fg="cyan")
        click.secho("  PHI Redactor - Sessions", fg="cyan", bold=True)
        click.secho("=" * 50, fg="cyan")
        click.echo()
        click.echo(f"  Total sessions:        {total}")
        click.echo(f"  Total vault entries:   {entries}")
        click.echo()
        click.secho("=" * 50, fg="cyan")
    finally:
        vault.close()


@cli_command.command("inspect")
@click.argument("session_id")
@click.pass_context
def inspect_session(ctx: click.Context, session_id: str) -> None:
    """Show session detail and anonymized mapping statistics."""
    from phi_redactor.vault.store import PhiVault

    config = ctx.obj["config"]
    vault = PhiVault(db_path=str(config.vault_path))

    try:
        mapping_count = vault.get_mapping_count(session_id)
        stats = vault.export_anonymized(session_id)

        click.secho("=" * 50, fg="cyan")
        click.secho(f"  Session: {session_id[:8]}...", fg="cyan", bold=True)
        click.secho("=" * 50, fg="cyan")
        click.echo()
        click.echo(f"  Session ID:      {session_id}")
        click.echo(f"  Mapping count:   {mapping_count}")
        click.echo(f"  Total entries:   {stats['total_entries']}")

        if stats.get("categories"):
            click.echo()
            click.secho("  PHI Categories:", bold=True)
            for category, count in stats["categories"].items():
                click.echo(f"    {category:<30} {count}")

        if stats.get("date_range"):
            dr = stats["date_range"]
            click.echo()
            click.echo(f"  Earliest entry:  {dr['earliest']}")
            click.echo(f"  Latest entry:    {dr['latest']}")

        click.echo()
        click.secho("=" * 50, fg="cyan")
    finally:
        vault.close()


@cli_command.command("close")
@click.argument("session_id")
@click.pass_context
def close_session(ctx: click.Context, session_id: str) -> None:
    """Close a session and purge its vault entries."""
    from phi_redactor.vault.store import PhiVault

    config = ctx.obj["config"]
    vault = PhiVault(db_path=str(config.vault_path))

    try:
        count = vault.purge_session(session_id)
        click.secho(f"Session {session_id} closed. {count} vault entries purged.", fg="green")
    except Exception as exc:
        click.secho(f"Error closing session: {exc}", fg="red", err=True)
        raise SystemExit(1) from exc
    finally:
        vault.close()


@cli_command.command("cleanup")
@click.pass_context
def cleanup_sessions(ctx: click.Context) -> None:
    """Remove all expired sessions and their vault entries."""
    from phi_redactor.vault.store import PhiVault

    config = ctx.obj["config"]
    vault = PhiVault(db_path=str(config.vault_path))

    try:
        removed = vault.cleanup_expired()
        if removed:
            click.secho(f"Cleanup complete. {removed} expired session(s) removed.", fg="green")
        else:
            click.echo("No expired sessions found.")
    finally:
        vault.close()
