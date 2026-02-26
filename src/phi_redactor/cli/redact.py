"""Batch redaction command -- redact PHI from a file or stdin.

This module defines the ``redact`` sub-command.  It is lazily loaded by
the root CLI group to keep startup fast when the user runs other
sub-commands.

When FILE is provided the contents are read from disk.  Otherwise text
is consumed from standard input (useful for piping).
"""

from __future__ import annotations

import json
import sys

import click


@click.command("redact")
@click.argument("file", type=click.Path(exists=True), required=False)
@click.option(
    "--output",
    "-o",
    type=click.Path(),
    default=None,
    help="Output file (defaults to stdout).",
)
@click.pass_context
def redact(ctx: click.Context, file: str | None, output: str | None) -> None:
    """Redact PHI from a file or stdin.

    When FILE is provided the contents are read from disk.  Otherwise text
    is consumed from standard input (useful for piping).
    """
    from phi_redactor import PhiRedactor
    from phi_redactor.config import PhiRedactorConfig

    config: PhiRedactorConfig = ctx.obj["config"]

    # --- Read input -------------------------------------------------------
    if file:
        with open(file, encoding="utf-8") as fh:
            text = fh.read()
    else:
        if sys.stdin.isatty():
            click.echo(
                "Reading from stdin (press Ctrl-D / Ctrl-Z to finish)...",
                err=True,
            )
        text = sys.stdin.read()

    if not text.strip():
        click.echo("No input text provided.", err=True)
        ctx.exit(1)

    # --- Redact -----------------------------------------------------------
    redactor = PhiRedactor(
        sensitivity=config.sensitivity,
        vault_path=str(config.vault_path),
    )
    result = redactor.redact(text)

    # --- Format output ----------------------------------------------------
    if ctx.obj.get("json_output"):
        output_data = {
            "redacted_text": result.redacted_text,
            "session_id": result.session_id,
            "detections": [d.model_dump() for d in result.detections],
            "total_detections": len(result.detections),
        }
        formatted = json.dumps(output_data, indent=2, default=str)
    else:
        formatted = result.redacted_text

    # --- Write output -----------------------------------------------------
    if output:
        with open(output, "w", encoding="utf-8") as fh:
            fh.write(formatted)
        click.echo(f"Redacted output written to {output}", err=True)
        click.echo(f"PHI detections: {len(result.detections)}", err=True)
    else:
        click.echo(formatted)


# Attribute consumed by _LazyGroup.get_command()
cli_command = redact
