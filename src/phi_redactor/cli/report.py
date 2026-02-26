"""CLI command for generating HIPAA Safe Harbor compliance reports.

Usage::

    phi-redactor report                    # Print summary to stdout
    phi-redactor report --full             # Full detailed report
    phi-redactor report --output report.json  # Export to file
    phi-redactor report --session <id>     # Filter by session
"""

from __future__ import annotations

import json

import click


@click.command("report")
@click.option("--full", is_flag=True, help="Generate a full detailed compliance report.")
@click.option("--output", "-o", type=click.Path(), default=None, help="Export report to a file.")
@click.option("--session", "-s", default=None, help="Filter by session ID.")
@click.option("--from-date", default=None, help="Start date (ISO 8601) for the reporting period.")
@click.option("--to-date", default=None, help="End date (ISO 8601) for the reporting period.")
@click.option(
    "--format",
    "fmt",
    type=click.Choice(["json", "md", "html"], case_sensitive=False),
    default="json",
    show_default=True,
    help="Output format: json, md (Markdown), or html.",
)
@click.option(
    "--safe-harbor",
    is_flag=True,
    help="Generate a full Safe Harbor attestation document (implies --full).",
)
@click.pass_context
def cli_command(
    ctx: click.Context,
    full: bool,
    output: str | None,
    session: str | None,
    from_date: str | None,
    to_date: str | None,
    fmt: str,
    safe_harbor: bool,
) -> None:
    """Generate HIPAA Safe Harbor compliance reports."""
    from datetime import datetime

    from phi_redactor.audit.reports import (
        ComplianceReportGenerator,
        render_html,
        render_markdown,
    )
    from phi_redactor.audit.trail import AuditTrail

    config = ctx.obj.get("config")
    if config is None:
        from phi_redactor.config import PhiRedactorConfig
        config = PhiRedactorConfig()

    audit_trail = AuditTrail(audit_dir=str(config.audit_path))
    generator = ComplianceReportGenerator(audit_trail=audit_trail)

    # Parse date filters
    parsed_from = datetime.fromisoformat(from_date) if from_date else None
    parsed_to = datetime.fromisoformat(to_date) if to_date else None

    # --safe-harbor implies a full report with attestation
    if safe_harbor:
        report = generator.generate_safe_harbor(
            from_dt=parsed_from,
            to_dt=parsed_to,
            session_id=session,
        )
    elif full:
        report = generator.generate_report(
            from_dt=parsed_from,
            to_dt=parsed_to,
            session_id=session,
        )
    else:
        report = generator.generate_summary(
            from_dt=parsed_from,
            to_dt=parsed_to,
        )

    # Determine rendered content
    if fmt == "json" or ctx.obj.get("json_output"):
        content = json.dumps(report, indent=2, default=str)
    elif fmt == "md":
        content = render_markdown(report)
    elif fmt == "html":
        content = render_html(report)
    else:
        content = json.dumps(report, indent=2, default=str)

    if output:
        from pathlib import Path
        out_path = Path(output).expanduser()
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(content, encoding="utf-8")
        click.echo(f"Compliance report exported to: {out_path}")
        return

    if fmt == "json" or ctx.obj.get("json_output"):
        click.echo(content)
    elif fmt in ("md", "html"):
        click.echo(content)
    else:
        _print_human_readable(report, full=full or safe_harbor)


def _print_human_readable(report: dict, full: bool = False) -> None:
    """Print the report in a human-readable format."""
    click.secho("=" * 60, fg="cyan")
    click.secho("  PHI Redactor - Compliance Report", fg="cyan", bold=True)
    click.secho("=" * 60, fg="cyan")

    # Summary
    summary = report.get("summary", report)
    click.echo()
    click.secho("Summary:", bold=True)
    click.echo(f"  Total redaction events: {summary.get('total_redaction_events', 0)}")
    click.echo(f"  Unique sessions:        {summary.get('unique_sessions', 0)}")
    click.echo(f"  PHI entities detected:  {summary.get('phi_entities_detected', 0)}")
    click.echo(f"  Categories detected:    {summary.get('categories_detected', 0)}")

    # Compliance status
    status = report.get("compliance_status", {})
    overall = status.get("overall", "unknown")
    color = "green" if overall == "compliant" else ("yellow" if overall == "review_needed" else "white")
    click.echo()
    click.secho(f"Compliance Status: {overall.upper()}", fg=color, bold=True)
    click.echo(f"  {status.get('message', '')}")

    if full and "checks" in status:
        click.echo()
        click.secho("Compliance Checks:", bold=True)
        for name, check in status["checks"].items():
            icon = "PASS" if check["passed"] else "FAIL"
            fg = "green" if check["passed"] else "red"
            click.secho(f"  [{icon}] {name}: {check['detail']}", fg=fg)

    if full and "category_coverage" in report:
        coverage = report["category_coverage"]
        click.echo()
        click.secho("Category Coverage:", bold=True)
        click.echo(f"  {coverage['categories_covered']}/{coverage['total_categories']} categories ({coverage['coverage_percentage']}%)")

    if full and "integrity_verification" in report:
        integrity = report["integrity_verification"]
        fg = "green" if integrity["hash_chain_valid"] else "red"
        click.echo()
        click.secho(f"Audit Trail Integrity: {integrity['status']}", fg=fg, bold=True)

    click.echo()
    click.secho("=" * 60, fg="cyan")
