from __future__ import annotations

import traceback
from pathlib import Path
from typing import Optional

import typer

from reai import __version__
from reai.cli.console import render_error, render_result
from reai.cli.progress import ENRICHIDB_PHASE_TITLES, phase_progress
from reai.core.config import build_config
from reai.core.exceptions import ReaiError
from reai.core.orchestrator import AnalysisOrchestrator

app = typer.Typer(
    add_completion=False,
    no_args_is_help=True,
    context_settings={"help_option_names": ["-h", "--help"]},
)


def _version_callback(value: bool) -> None:
    if value:
        typer.echo(f"reai {__version__}")
        raise typer.Exit()


@app.command()
def main(
    input_path: Path = typer.Argument(..., metavar="INPUT", help="Sample file or directory to initialize."),
    output: Optional[Path] = typer.Option(None, "-o", "--output", help="Output root directory."),
    recursive: Optional[bool] = typer.Option(None, "--recursive", help="Discover files recursively for directory input."),
    workers: Optional[int] = typer.Option(None, "--workers", min=1, help="Worker count reserved for later batch phases.", hidden=True),
    config: Optional[Path] = typer.Option(None, "--config", help="TOML configuration file."),
    max_functions: Optional[int] = typer.Option(None, "--max-functions", min=1, help="Development limit for Phase 3 AI target count.", hidden=True),
    no_mcp: bool = typer.Option(False, "--no-mcp", help="Run in degraded bulk-extraction-only investigation mode without live MCP.", hidden=True),
    enrichidb: bool = typer.Option(False, "--enrichidb", help="Only rename sub_* functions, rename variables, add function comments, and save analyzed .i64."),
    enrichidb_rename_only: bool = typer.Option(False, "--enrichidb-rename-only", help="With --enrichidb, only rename functions; skip variable renames and function comments."),
    verbose: bool = typer.Option(False, "--verbose", help="Show additional debugging information."),
    version: bool = typer.Option(False, "--version", callback=_version_callback, is_eager=True, help="Show version and exit."),
) -> None:
    del version
    try:
        if enrichidb_rename_only:
            enrichidb = True
        app_config = build_config(
            config_path=config,
            output_dir=output,
            workers=workers,
            recursive=recursive,
            verbose=verbose,
            max_functions=max_functions,
            no_mcp=no_mcp,
        )
        initial_message = "Starting REAI IDB enrichment..." if enrichidb else "Starting REAI analysis..."
        phase_titles = ENRICHIDB_PHASE_TITLES if enrichidb else None
        with phase_progress(initial_message, phase_titles=phase_titles) as progress:
            orchestrator = AnalysisOrchestrator(
                app_config,
                progress_callback=progress.update,
                enrich_idb_only=enrichidb,
                enrich_idb_rename_only=enrichidb_rename_only,
            )
            result = orchestrator.analyze(input_path)
        render_result(result)
        if result.failed_count:
            raise typer.Exit(code=3)
    except ReaiError as exc:
        render_error(str(exc), verbose=verbose, details=traceback.format_exc())
        raise typer.Exit(code=2) from exc
    except typer.Exit:
        raise
    except Exception as exc:
        render_error("Unexpected failure during initialization.", verbose=verbose, details=traceback.format_exc())
        raise typer.Exit(code=1) from exc
