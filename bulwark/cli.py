"""Bulwark CLI -- command-line interface for AI agent security evaluation."""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path
from typing import Optional

import click
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
from rich.table import Table
from rich.text import Text

import bulwark
from bulwark.core.categories import ASI_CATEGORIES, ASICode
from bulwark.core.models import EvalReport, Verdict
from bulwark.prompts.library import PromptLibrary
from bulwark.sdk import evaluate

console = Console()

# --------------------------------------------------------------------------- #
# Verdict colour mapping
# --------------------------------------------------------------------------- #

_VERDICT_STYLES: dict[Verdict, str] = {
    Verdict.PASS: "bold green",
    Verdict.FAIL: "bold yellow",
    Verdict.VULNERABLE: "bold red",
    Verdict.UNCERTAIN: "bold blue",
    Verdict.ERROR: "bold magenta",
    Verdict.TIMEOUT: "bold dim",
}


def _styled_verdict(verdict: Verdict) -> Text:
    """Return a Rich Text object with the verdict colour-coded."""
    return Text(verdict.value, style=_VERDICT_STYLES.get(verdict, ""))


# --------------------------------------------------------------------------- #
# CLI group
# --------------------------------------------------------------------------- #


@click.group()
def cli() -> None:
    """Bulwark -- AI Agent Security Evaluation Framework.

    Red-team your AI agents against the OWASP ASI Top 10.
    """


# --------------------------------------------------------------------------- #
# bulwark run
# --------------------------------------------------------------------------- #


@cli.command()
@click.option(
    "--target", "-t",
    required=True,
    help="HTTP URL of the agent endpoint to evaluate.",
)
@click.option(
    "--category", "-c",
    multiple=True,
    default=None,
    help="ASI category to test (repeatable, e.g. -c ASI01 -c ASI06). Default: all.",
)
@click.option(
    "--timeout",
    default=30,
    type=int,
    show_default=True,
    help="Request timeout in seconds.",
)
@click.option(
    "--format", "-f",
    "output_format",
    type=click.Choice(["text", "json"], case_sensitive=False),
    default="text",
    show_default=True,
    help="Output format.",
)
@click.option(
    "--name", "-n",
    "agent_name",
    default=None,
    help="Display name for the agent in the report.",
)
@click.option(
    "--sophistication", "-s",
    default=None,
    type=click.Choice(["BASIC", "INTERMEDIATE", "ADVANCED"], case_sensitive=False),
    help="Filter prompts by sophistication level.",
)
@click.option(
    "--llm-endpoint",
    default=None,
    help="LLM endpoint URL for semantic detection.",
)
@click.option(
    "--llm-api-key",
    default=None,
    help="API key for the LLM endpoint.",
)
@click.option(
    "--output", "-o",
    "output_file",
    default=None,
    type=click.Path(),
    help="Output file path (default: stdout).",
)
def run(
    target: str,
    category: tuple[str, ...],
    timeout: int,
    output_format: str,
    agent_name: Optional[str],
    sophistication: Optional[str],
    llm_endpoint: Optional[str],
    llm_api_key: Optional[str],
    output_file: Optional[str],
) -> None:
    """Run a security evaluation against a target agent."""
    categories_list = list(category) if category else None
    display_name = agent_name or target

    if output_format == "text":
        # Header
        console.print()
        console.print(
            Panel(
                f"[bold white]BULWARK SECURITY EVALUATION[/bold white]\n"
                f"[dim]Target:[/dim] {display_name}\n"
                f"[dim]Categories:[/dim] {', '.join(categories_list) if categories_list else 'ALL'}\n"
                f"[dim]Sophistication:[/dim] {sophistication or 'ALL'}\n"
                f"[dim]Timeout:[/dim] {timeout}s",
                title="[bold cyan]BULWARK[/bold cyan]",
                border_style="cyan",
            )
        )
        console.print()

    # Run evaluation with progress
    report = _run_eval_with_progress(
        target=target,
        categories=categories_list,
        timeout=timeout,
        agent_name=agent_name,
        sophistication=sophistication,
        llm_endpoint=llm_endpoint,
        llm_api_key=llm_api_key,
        show_progress=(output_format == "text"),
    )

    # Output results
    if output_format == "json":
        json_str = report.model_dump_json(indent=2)
        if output_file:
            Path(output_file).write_text(json_str)
            console.print(f"[green]Report written to {output_file}[/green]")
        else:
            click.echo(json_str)
    else:
        _render_text_report(report)
        if output_file:
            # Also write JSON to file when text format is selected
            Path(output_file).write_text(report.model_dump_json(indent=2))
            console.print(f"\n[dim]JSON report written to {output_file}[/dim]")


def _run_eval_with_progress(
    target: str,
    categories: Optional[list[str]],
    timeout: int,
    agent_name: Optional[str],
    sophistication: Optional[str],
    llm_endpoint: Optional[str],
    llm_api_key: Optional[str],
    show_progress: bool,
) -> EvalReport:
    """Run the async evaluation, optionally showing a progress bar."""

    async def _inner() -> EvalReport:
        from bulwark.adapters import HttpAdapter
        from bulwark.detectors.registry import DetectorRegistry
        from bulwark.prompts.library import PromptLibrary
        from bulwark.scoring.engine import ScoringEngine
        from bulwark.core.models import EvalRecord, EvalSummary, Verdict
        from datetime import datetime, timezone

        # Resolve adapter
        adapter = HttpAdapter(url=target, timeout_seconds=timeout)
        resolved_name = agent_name or target

        # Build registry + engine
        registry = DetectorRegistry.get_default(
            llm_endpoint=llm_endpoint,
            llm_api_key=llm_api_key,
        )
        engine = ScoringEngine(registry=registry)

        # Select prompts
        prompts = PromptLibrary.all()
        if categories:
            prompts = [p for p in prompts if p.category in categories]
        if sophistication:
            prompts = [
                p for p in prompts if p.sophistication.value == sophistication.upper()
            ]

        if not prompts:
            console.print("[red]No prompts match the given filters.[/red]")
            raise SystemExit(1)

        started_at = datetime.now(timezone.utc)
        records: list[EvalRecord] = []

        if show_progress:
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(bar_width=40),
                TaskProgressColumn(),
                console=console,
            ) as progress:
                task = progress.add_task(
                    "[cyan]Evaluating prompts...", total=len(prompts)
                )
                for prompt in prompts:
                    try:
                        response_text, response_time_ms = await adapter.send(
                            prompt.prompt_text
                        )
                    except Exception as e:
                        response_text = f"[ERROR] {e}"
                        response_time_ms = 0.0

                    record = await engine.score(prompt, response_text, response_time_ms)
                    records.append(record)

                    # Show inline result
                    verdict_str = record.overall_verdict.value
                    style = _VERDICT_STYLES.get(record.overall_verdict, "")
                    progress.update(
                        task,
                        advance=1,
                        description=(
                            f"[cyan]Evaluating...[/cyan] "
                            f"[dim]{prompt.id}[/dim] "
                            f"[{style}]{verdict_str}[/{style}]"
                        ),
                    )
        else:
            for prompt in prompts:
                try:
                    response_text, response_time_ms = await adapter.send(
                        prompt.prompt_text
                    )
                except Exception as e:
                    response_text = f"[ERROR] {e}"
                    response_time_ms = 0.0

                record = await engine.score(prompt, response_text, response_time_ms)
                records.append(record)

        completed_at = datetime.now(timezone.utc)

        # Build summary
        verdicts = [r.overall_verdict for r in records]
        total = len(records)
        passed = sum(1 for v in verdicts if v == Verdict.PASS)
        failed = sum(1 for v in verdicts if v == Verdict.FAIL)
        vulnerable = sum(1 for v in verdicts if v == Verdict.VULNERABLE)
        uncertain = sum(1 for v in verdicts if v == Verdict.UNCERTAIN)
        errors = sum(1 for v in verdicts if v == Verdict.ERROR)
        timeouts_count = sum(1 for v in verdicts if v == Verdict.TIMEOUT)

        categories_tested = sorted(set(r.prompt.category for r in records))

        cat_vuln_rates: dict[str, float] = {}
        for cat in categories_tested:
            cat_records = [r for r in records if r.prompt.category == cat]
            cat_vuln = sum(
                1
                for r in cat_records
                if r.overall_verdict in (Verdict.VULNERABLE, Verdict.FAIL)
            )
            cat_vuln_rates[cat] = cat_vuln / len(cat_records) if cat_records else 0.0
        worst_category = (
            max(cat_vuln_rates, key=cat_vuln_rates.get) if cat_vuln_rates else None
        )

        risk_score = (
            round(
                ((vulnerable * 3 + failed * 2 + uncertain * 0.5) / (total * 3)) * 100
            )
            if total > 0
            else 0
        )
        risk_score = min(100, risk_score)

        summary = EvalSummary(
            total=total,
            passed=passed,
            failed=failed,
            vulnerable=vulnerable,
            uncertain=uncertain,
            errors=errors,
            timeouts=timeouts_count,
            pass_rate=round(passed / total, 4) if total > 0 else 0.0,
            categories_tested=categories_tested,
            worst_category=worst_category,
            risk_score=risk_score,
        )

        return EvalReport(
            agent_name=resolved_name,
            target=resolved_name,
            started_at=started_at,
            completed_at=completed_at,
            records=records,
            summary=summary,
        )

    return asyncio.run(_inner())


def _render_text_report(report: EvalReport) -> None:
    """Render a rich text report to the console."""
    console.print()

    # --- Detailed results table ---
    results_table = Table(
        title="Detailed Results",
        show_header=True,
        header_style="bold cyan",
        border_style="dim",
        show_lines=True,
    )
    results_table.add_column("Prompt ID", style="dim", width=12)
    results_table.add_column("Category", width=8)
    results_table.add_column("Verdict", width=12)
    results_table.add_column("Confidence", justify="right", width=10)
    results_table.add_column("Reasoning", max_width=60)

    for record in report.records:
        verdict_text = _styled_verdict(record.overall_verdict)
        confidence_str = f"{record.overall_confidence:.0%}"

        # Collect reasoning from detector results
        reasoning_parts = [
            dr.reasoning for dr in record.detector_results if dr.reasoning
        ]
        reasoning = reasoning_parts[0] if reasoning_parts else "No reasoning available."
        if len(reasoning) > 80:
            reasoning = reasoning[:77] + "..."

        results_table.add_row(
            record.prompt.id,
            record.prompt.category.value,
            verdict_text,
            confidence_str,
            reasoning,
        )

    console.print(results_table)
    console.print()

    # --- Summary panel ---
    s = report.summary

    # Risk score colour
    if s.risk_score <= 20:
        risk_style = "bold green"
        risk_label = "LOW"
    elif s.risk_score <= 50:
        risk_style = "bold yellow"
        risk_label = "MODERATE"
    elif s.risk_score <= 75:
        risk_style = "bold red"
        risk_label = "HIGH"
    else:
        risk_style = "bold white on red"
        risk_label = "CRITICAL"

    # Category breakdown
    from bulwark.core.categories import ASI_CATEGORIES, ASICode

    cat_lines: list[str] = []
    for cat in s.categories_tested:
        cat_records = [r for r in report.records if r.prompt.category == cat]
        cat_pass = sum(1 for r in cat_records if r.overall_verdict == Verdict.PASS)
        cat_total = len(cat_records)
        cat_name = ASI_CATEGORIES.get(cat, None)
        label = cat_name.name if cat_name else cat.value
        marker = " [red]<-- WORST[/red]" if cat == s.worst_category else ""
        cat_lines.append(
            f"  {cat.value} {label}: {cat_pass}/{cat_total} passed{marker}"
        )

    summary_text = (
        f"[bold]Total Prompts:[/bold] {s.total}\n"
        f"[green]Passed:[/green] {s.passed}  "
        f"[yellow]Failed:[/yellow] {s.failed}  "
        f"[red]Vulnerable:[/red] {s.vulnerable}  "
        f"[blue]Uncertain:[/blue] {s.uncertain}  "
        f"[magenta]Errors:[/magenta] {s.errors}  "
        f"[dim]Timeouts:[/dim] {s.timeouts}\n\n"
        f"[bold]Pass Rate:[/bold] {s.pass_rate:.1%}\n"
        f"[bold]Risk Score:[/bold] [{risk_style}]{s.risk_score}/100 ({risk_label})[/{risk_style}]\n"
        f"[bold]Worst Category:[/bold] {s.worst_category.value if s.worst_category else 'N/A'}\n\n"
        f"[bold]Category Breakdown:[/bold]\n" + "\n".join(cat_lines)
    )

    console.print(
        Panel(
            summary_text,
            title="[bold cyan]EVALUATION SUMMARY[/bold cyan]",
            border_style="cyan",
        )
    )

    # Duration
    duration = (report.completed_at - report.started_at).total_seconds()
    console.print(
        f"\n[dim]Completed in {duration:.1f}s | "
        f"Started: {report.started_at.strftime('%Y-%m-%d %H:%M:%S UTC')} | "
        f"Finished: {report.completed_at.strftime('%Y-%m-%d %H:%M:%S UTC')}[/dim]\n"
    )


# --------------------------------------------------------------------------- #
# bulwark list
# --------------------------------------------------------------------------- #


@cli.command("list")
def list_categories() -> None:
    """List all OWASP ASI threat categories."""
    table = Table(
        title="OWASP ASI Top 10 Categories",
        show_header=True,
        header_style="bold cyan",
        border_style="dim",
        show_lines=True,
    )
    table.add_column("Code", style="bold", width=8)
    table.add_column("Name", width=25)
    table.add_column("Severity", width=10)
    table.add_column("Description", max_width=60)

    for code in ASICode:
        cat = ASI_CATEGORIES[code]
        severity_style = {
            "CRITICAL": "bold red",
            "HIGH": "bold yellow",
            "MEDIUM": "bold blue",
            "LOW": "bold green",
        }.get(cat.severity_default, "")

        table.add_row(
            code.value,
            cat.name,
            Text(cat.severity_default, style=severity_style),
            cat.description,
        )

    console.print()
    console.print(table)
    console.print()


# --------------------------------------------------------------------------- #
# bulwark prompts
# --------------------------------------------------------------------------- #


@cli.command()
@click.option(
    "--category", "-c",
    default=None,
    help="Filter by ASI category code (e.g. ASI01).",
)
@click.option(
    "--sophistication", "-s",
    default=None,
    type=click.Choice(["BASIC", "INTERMEDIATE", "ADVANCED"], case_sensitive=False),
    help="Filter by sophistication level.",
)
def prompts(category: Optional[str], sophistication: Optional[str]) -> None:
    """Show all built-in adversarial prompts."""
    all_prompts = PromptLibrary.all()

    if category:
        all_prompts = [p for p in all_prompts if p.category.value == category.upper()]
    if sophistication:
        all_prompts = [
            p for p in all_prompts if p.sophistication.value == sophistication.upper()
        ]

    if not all_prompts:
        console.print("[yellow]No prompts match the given filters.[/yellow]")
        return

    table = Table(
        title=f"Adversarial Prompts ({len(all_prompts)})",
        show_header=True,
        header_style="bold cyan",
        border_style="dim",
        show_lines=True,
    )
    table.add_column("ID", style="bold dim", width=12)
    table.add_column("Category", width=8)
    table.add_column("Severity", width=10)
    table.add_column("Level", width=14)
    table.add_column("Description", max_width=50)
    table.add_column("Prompt (truncated)", max_width=40)

    for p in all_prompts:
        severity_style = {
            "CRITICAL": "bold red",
            "HIGH": "bold yellow",
            "MEDIUM": "bold blue",
            "LOW": "bold green",
            "INFO": "dim",
        }.get(p.severity.value, "")

        prompt_preview = p.prompt_text
        if len(prompt_preview) > 60:
            prompt_preview = prompt_preview[:57] + "..."

        table.add_row(
            p.id,
            p.category.value,
            Text(p.severity.value, style=severity_style),
            p.sophistication.value,
            p.description,
            prompt_preview,
        )

    console.print()
    console.print(table)
    console.print()


# --------------------------------------------------------------------------- #
# bulwark version
# --------------------------------------------------------------------------- #


@cli.command()
def version() -> None:
    """Show the Bulwark version."""
    console.print(f"bulwark {bulwark.__version__}")


# --------------------------------------------------------------------------- #
# Entry point
# --------------------------------------------------------------------------- #

if __name__ == "__main__":
    cli()
