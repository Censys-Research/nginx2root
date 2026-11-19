"""Unified, consent-gated CLI for the five isolated nginx2root PoCs."""

from __future__ import annotations

import json
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

import click
from rich.console import Console
from rich.table import Table

from .adapters import get_result
from .models import (
    CVE_IDS,
    LAB_ACK,
    Budget,
    Phase,
    PocResult,
    Status,
    SuiteError,
    SuiteReport,
    load_manifest,
    manifest_path,
    prepare_command,
)

console = Console(stderr=True)
SELECTION = click.Choice(
    [cve.lower() for cve in CVE_IDS] + ["all"], case_sensitive=False
)


def _selection(values: tuple[str, ...]) -> list[str]:
    """Return unique canonical IDs in the user's requested order."""
    if not values:
        raise click.UsageError("choose at least one CVE or 'all'")
    lowered = [value.lower() for value in values]
    if "all" in lowered and len(lowered) != 1:
        raise click.UsageError("'all' cannot be combined with individual CVEs")
    selected = (
        list(CVE_IDS) if lowered == ["all"] else [value.upper() for value in lowered]
    )
    return list(dict.fromkeys(selected))


def _budget(attempts: int, max_bytes: int, timeout: int, parallel: bool) -> Budget:
    """Create a validated execution budget with one worker by default."""
    try:
        return Budget(
            attempts=attempts,
            max_bytes=max_bytes,
            timeout=timeout,
            jobs=5 if parallel else 1,
        )
    except ValueError as exc:
        raise click.BadParameter(str(exc)) from exc


def _print_report(report: SuiteReport, as_json: bool) -> None:
    """Emit pure JSON on stdout or a human-readable table on stderr."""
    if as_json:
        click.echo(report.model_dump_json(indent=2))
        return
    table = Table(title=f"nginx2root {report.action}")
    for column in ("CVE", "Status", "Attempts", "Details"):
        table.add_column(column)
    for result in report.results:
        table.add_row(
            result.cve,
            result.status.value,
            str(result.attempts),
            " | ".join(result.details),
        )
    console.print(table)
    if not as_json and report.action != "list":
        for result in report.results:
            if result.verification and result.verification.reasons:
                console.print(f"{result.cve}: {'; '.join(result.verification.reasons)}")


def _exit_code(report: SuiteReport) -> int:
    """Only successfully verified requested runs return zero."""
    if report.action == "list":
        return 0
    return 0 if report.all_verified else 1


def _execute(
    action: str,
    values: tuple[str, ...],
    *,
    execute: bool,
    acknowledge: str | None,
    attempts: int,
    max_bytes: int,
    timeout: int,
    parallel: bool,
    as_json: bool,
) -> None:
    """Validate policy before scheduling any manifest subprocess."""
    selected = _selection(values)
    if execute and acknowledge != LAB_ACK:
        raise click.UsageError(
            f"execution requires --acknowledge-local-lab {LAB_ACK}; use dry-run otherwise"
        )
    budget = _budget(attempts, max_bytes, timeout, parallel)
    results = (
        [get_result(cve, action, budget, not execute) for cve in selected]
        if not parallel
        else _parallel_results(selected, action, budget, not execute)
    )
    report = SuiteReport(
        action=action,
        dry_run=not execute,
        results=results,
        all_verified=all(
            result.status == Status.VERIFIED
            and bool(result.verification and result.verification.rce_verified)
            for result in results
        ),
    )
    _print_report(report, as_json)
    raise click.exceptions.Exit(_exit_code(report))


def _parallel_results(
    selected: list[str], action: str, budget: Budget, dry_run: bool
) -> list[PocResult]:
    """Run explicitly opted-in independent CVE adapters, retaining input order."""
    with ThreadPoolExecutor(max_workers=budget.jobs) as executor:
        futures = {
            cve: executor.submit(get_result, cve, action, budget, dry_run)
            for cve in selected
        }
        return [futures[cve].result() for cve in selected]


@click.group(
    invoke_without_command=True,
    context_settings={"help_option_names": ["-h", "--help"]},
)
@click.option(
    "--json", "as_json", is_flag=True, help="Emit machine-readable JSON for listing."
)
@click.pass_context
def cli(ctx: click.Context, as_json: bool) -> None:
    """List or run authorized, isolated nginx2root lab PoCs.

    With no subcommand, lists all five adapters without contacting a target.
    """
    if ctx.invoked_subcommand is None:
        ctx.invoke(list_pocs, as_json=as_json)


@cli.command("list")
@click.option("--json", "as_json", is_flag=True, help="Emit machine-readable JSON.")
def list_pocs(as_json: bool) -> None:
    """List adapter readiness and archived evidence without executing anything."""
    results: list[PocResult] = []
    for cve in CVE_IDS:
        try:
            manifest = load_manifest(cve)
            status = (
                Status.ARCHIVED
                if manifest.archived
                else Status.READY if manifest.implemented else Status.NOT_IMPLEMENTED
            )
            results.append(
                PocResult(
                    cve=cve,
                    title=manifest.title,
                    status=status,
                    implemented=manifest.implemented,
                    archived=manifest.archived,
                    requested_action="list",
                    dry_run=True,
                    details=[manifest.notes],
                )
            )
        except SuiteError as exc:
            results.append(
                PocResult(
                    cve=cve,
                    title=cve,
                    status=Status.REFUSED,
                    implemented=False,
                    requested_action="list",
                    dry_run=True,
                    details=[str(exc)],
                )
            )
    report = SuiteReport(
        action="list", dry_run=True, results=results, all_verified=False
    )
    _print_report(report, as_json)


def _common_options(function: Any) -> Any:
    """Apply identical bounds and selection to every action."""
    options = [
        click.argument("cves", nargs=-1, required=True, type=SELECTION),
        click.option(
            "--execute", is_flag=True, help="Run commands; default is dry-run."
        ),
        click.option(
            "--acknowledge-local-lab",
            default=None,
            help=f"Required with --execute; exact value: {LAB_ACK}",
        ),
        click.option(
            "--attempts", default=1, type=click.IntRange(1, 3), show_default=True
        ),
        click.option(
            "--max-bytes",
            default=64 * 1024 * 1024,
            type=click.IntRange(64 * 1024, 2 * 1024**3),
            show_default=True,
            help="Combined subprocess-output cap per stage.",
        ),
        click.option(
            "--timeout",
            default=60,
            type=click.IntRange(1, 900),
            show_default=True,
            help="Wall-clock seconds per stage.",
        ),
        click.option(
            "--parallel", is_flag=True, help="Run selected CVEs concurrently."
        ),
        click.option(
            "--json", "as_json", is_flag=True, help="Emit machine-readable JSON."
        ),
    ]
    for option in reversed(options):
        function = option(function)
    return function


@cli.command("build")
@_common_options
def build_pocs(
    cves: tuple[str, ...],
    execute: bool,
    acknowledge_local_lab: str | None,
    attempts: int,
    max_bytes: int,
    timeout: int,
    parallel: bool,
    as_json: bool,
) -> None:
    """Plan or build selected PoCs; never claims RCE verification."""
    _execute(
        "build",
        cves,
        execute=execute,
        acknowledge=acknowledge_local_lab,
        attempts=attempts,
        max_bytes=max_bytes,
        timeout=timeout,
        parallel=parallel,
        as_json=as_json,
    )


@cli.command("run")
@_common_options
def run_pocs(
    cves: tuple[str, ...],
    execute: bool,
    acknowledge_local_lab: str | None,
    attempts: int,
    max_bytes: int,
    timeout: int,
    parallel: bool,
    as_json: bool,
) -> None:
    """Plan or execute selected PoCs with independent marker verification."""
    _execute(
        "run",
        cves,
        execute=execute,
        acknowledge=acknowledge_local_lab,
        attempts=attempts,
        max_bytes=max_bytes,
        timeout=timeout,
        parallel=parallel,
        as_json=as_json,
    )


@cli.command("verify")
@_common_options
def verify_pocs(
    cves: tuple[str, ...],
    execute: bool,
    acknowledge_local_lab: str | None,
    attempts: int,
    max_bytes: int,
    timeout: int,
    parallel: bool,
    as_json: bool,
) -> None:
    """Verify recorded evidence or independently query an existing fresh lab."""
    _execute(
        "verify",
        cves,
        execute=execute,
        acknowledge=acknowledge_local_lab,
        attempts=attempts,
        max_bytes=max_bytes,
        timeout=timeout,
        parallel=parallel,
        as_json=as_json,
    )


def main() -> None:
    """Console entry point."""
    cli()
