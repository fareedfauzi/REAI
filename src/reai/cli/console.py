from __future__ import annotations

from pathlib import Path

from rich.console import Console
from rich.markup import escape
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from reai.core.orchestrator import AnalysisRunResult, InputKind, ResultStatus

console = Console()
error_console = Console(stderr=True)


def render_result(result: AnalysisRunResult) -> None:
    if result.input_kind == InputKind.FILE and len(result.samples) == 1:
        _render_single(result)
    else:
        _render_batch(result)


def _render_header(title: str) -> None:
    console.print(Panel.fit(title, border_style="cyan"))


def _render_single(result: AnalysisRunResult) -> None:
    item = result.samples[0]
    sample = item.sample
    title = (
        "REAI - Existing Analysis Workspace"
        if item.status == ResultStatus.EXISTING
        else "REAI - IDA Static Analysis"
        if item.status == ResultStatus.READY_FOR_ANALYSIS
        else "REAI - Bottom-Up AI Analysis"
        if item.status == ResultStatus.AI_ANALYZED
        else "REAI - MCP Investigation"
        if item.status == ResultStatus.MCP_INVESTIGATED
        else "REAI - Malware Understanding"
        if item.status == ResultStatus.VALIDATED
        else "REAI - IDB Enrichment"
        if item.status == ResultStatus.ENRICHED
        else "REAI - Analysis Complete"
        if item.status == ResultStatus.COMPLETE
        else "REAI - Autonomous Malware Reverse Engineering"
    )
    _render_header(title)
    table = Table.grid(padding=(0, 2))
    table.add_column(style="bold")
    table.add_column()
    table.add_row("Sample", sample.filename)
    table.add_row("SHA256", _short_hash(sample.sha256, 16))
    table.add_row("Size", _format_size(sample.size))
    if item.ida_version:
        table.add_row("IDA", item.ida_version)
    table.add_row("Output", _display_path(item.workspace.root))
    table.add_row("Status", item.status.value)
    console.print(table)
    console.print("-" * min(console.width, 80), style="cyan")
    steps = Table.grid(padding=(0, 2))
    steps.add_column()
    steps.add_column(style="green")
    steps.add_row("Discovery", "OK")
    steps.add_row("Hashing", "OK")
    steps.add_row("Workspace", "OK")
    steps.add_row("Database", "OK")
    console.print(steps)
    if item.ai_stats is not None:
        if item.extraction_stats is not None:
            _render_phase2_stats(item.extraction_stats)
        _render_phase3_stats(item.ai_stats)
        if item.mcp_stats is not None:
            _render_phase4_stats(item.mcp_stats)
        if item.semantic_stats is not None:
            _render_phase5_stats(item.semantic_stats)
            if item.enrichment_stats is not None:
                _render_phase6_stats(item.enrichment_stats)
                if item.report_stats is not None:
                    _render_phase7_stats(item.report_stats)
                    console.print("\nAnalysis complete. Report and analyzed IDB are ready.")
                else:
                    console.print("\nPhase 6 complete. Analyzed IDB is ready.")
            else:
                console.print("\nPhase 5 complete. Ready for IDB enrichment.")
        elif item.mcp_stats is not None:
            console.print("\nPhase 4 complete. Ready for multi-pass malware understanding.")
        else:
            console.print("\nPhase 3 complete. Ready for autonomous MCP investigation.")
    elif item.extraction_stats is not None:
        _render_phase2_stats(item.extraction_stats)
        console.print("\nPhase 2 complete. Ready for bottom-up AI analysis.")
    else:
        console.print("\nPhase 1 initialization complete.")


def _render_batch(result: AnalysisRunResult) -> None:
    _render_header("REAI - Batch Initialization")
    summary = Table.grid(padding=(0, 2))
    summary.add_column(style="bold")
    summary.add_column()
    summary.add_row("Input", _display_path(result.input_path))
    summary.add_row("Samples", str(len(result.samples)))
    summary.add_row("Complete", str(result.complete_count))
    summary.add_row("Failed", str(result.failed_count))
    summary.add_row("Duplicates", str(result.duplicate_count))
    summary.add_row("Workers", str(result.workers))
    summary.add_row("Recursive", str(result.recursive))
    summary.add_row("Output", _display_path(result.output_root))
    console.print(summary)
    console.print()

    table = Table(show_header=True, header_style="bold cyan")
    table.add_column("Sample")
    table.add_column("SHA256")
    table.add_column("Status")
    table.add_column("Workspace")
    for item in result.samples:
        status_style = {
            ResultStatus.INITIALIZED: "green",
            ResultStatus.EXISTING: "yellow",
            ResultStatus.DUPLICATE: "magenta",
            ResultStatus.READY_FOR_ANALYSIS: "green",
            ResultStatus.AI_ANALYZED: "green",
            ResultStatus.MCP_INVESTIGATED: "green",
            ResultStatus.VALIDATED: "green",
            ResultStatus.ENRICHED: "green",
            ResultStatus.COMPLETE: "green",
            ResultStatus.FAILED: "red",
        }[item.status]
        status = Text(item.status.value, style=status_style)
        table.add_row(
            item.sample.filename,
            item.sample.sha256[:8],
            status,
            _display_path(item.workspace.root),
        )
    console.print(table)
    if result.skipped:
        console.print(f"\nSkipped {len(result.skipped)} item(s). Use --verbose for details.", style="yellow")
    if result.failed_count:
        console.print(f"\nFailed {result.failed_count} sample(s). See batch-summary.json and per-sample logs.", style="red")
    if any(item.ai_stats for item in result.samples):
        if any(item.report_stats for item in result.samples):
            console.print("\nAnalysis complete.")
        elif any(item.enrichment_stats for item in result.samples):
            console.print("\nPhase 6 complete.")
        elif any(item.semantic_stats for item in result.samples):
            console.print("\nPhase 5 complete.")
        elif any(item.mcp_stats for item in result.samples):
            console.print("\nPhase 4 complete.")
        else:
            console.print("\nPhase 3 complete.")
    else:
        console.print("\nPhase 2 complete." if any(item.extraction_stats for item in result.samples) else "\nPhase 1 initialization complete.")


def render_error(message: str, *, verbose: bool = False, details: str | None = None) -> None:
    error_console.print(f"[bold red]Error:[/bold red] {escape(message)}")
    if verbose and details:
        error_console.print(escape(details))


def _short_hash(value: str, edge: int = 12) -> str:
    if len(value) <= edge * 2:
        return value
    return f"{value[:edge]}...{value[-edge:]}"


def _format_size(size: int) -> str:
    units = ["B", "KB", "MB", "GB", "TB"]
    value = float(size)
    for unit in units:
        if value < 1024 or unit == units[-1]:
            return f"{value:.1f} {unit}" if unit != "B" else f"{size} B"
        value /= 1024
    return f"{size} B"


def _display_path(path: Path) -> str:
    try:
        return str(path.resolve().relative_to(Path.cwd().resolve()))
    except ValueError:
        return str(path)


def _render_phase2_stats(stats) -> None:
    console.print()
    console.print("IDA Analysis", style="bold cyan")
    ida_steps = Table.grid(padding=(0, 2))
    ida_steps.add_column()
    ida_steps.add_column(style="green")
    ida_steps.add_row("Sample loaded", "OK")
    ida_steps.add_row("Auto-analysis complete", "OK")
    ida_steps.add_row("Original IDB saved", "OK")
    console.print(ida_steps)
    console.print("-" * min(console.width, 80), style="cyan")
    console.print("Bulk Extraction", style="bold cyan")
    table = Table.grid(padding=(0, 2))
    table.add_column()
    table.add_column(justify="right")
    rows = [
        ("Functions", stats.total_functions),
        ("sub_* functions", stats.sub_functions),
        ("Library functions", stats.library_functions),
        ("Thunks", stats.thunks),
        ("Pseudocode", stats.decompiled_successfully),
        ("Decompile failures", stats.decompilation_failures),
        ("Strings", stats.strings),
        ("Imports", stats.imports),
        ("Exports", stats.exports),
        ("Globals", stats.globals),
        ("Segments", stats.segments),
        ("Types", stats.types),
        ("Call edges", stats.call_edges),
        ("Recursive components", stats.recursive_components),
        ("Partial failures", stats.partial_failures),
    ]
    for label, value in rows:
        table.add_row(label, f"{value:,}")
    console.print(table)


def _render_phase3_stats(stats) -> None:
    console.print("-" * min(console.width, 80), style="cyan")
    console.print("Bottom-Up AI Analysis", style="bold cyan")
    table = Table.grid(padding=(0, 2))
    table.add_column()
    table.add_column(justify="right")
    rows = [
        ("Target functions", stats.target_functions),
        ("Analyzed", stats.analyzed),
        ("Failed", stats.failed),
        ("High confidence", stats.high_confidence),
        ("Medium confidence", stats.medium_confidence),
        ("Low confidence", stats.low_confidence),
        ("Proposed function names", stats.proposed_function_names),
        ("Variable proposals", stats.variable_proposals),
        ("Needs investigation", stats.needs_investigation),
        ("Context truncated", stats.context_truncated),
        ("AI requests", stats.ai_requests),
        ("Input tokens", stats.total_input_tokens),
        ("Output tokens", stats.total_output_tokens),
    ]
    for label, value in rows:
        table.add_row(label, f"{value:,}")
    table.add_row("Generic name rate", f"{stats.generic_name_rate:.1%}")
    console.print(table)


def _render_phase4_stats(stats) -> None:
    console.print("-" * min(console.width, 80), style="cyan")
    console.print("Autonomous MCP Investigation", style="bold cyan")
    table = Table.grid(padding=(0, 2))
    table.add_column()
    table.add_column(justify="right")
    rows = [
        ("Investigation candidates", stats.candidates),
        ("Attempted", stats.attempted),
        ("Completed", stats.completed),
        ("Resolved HIGH", stats.resolved_high),
        ("Resolved MEDIUM", stats.resolved_medium),
        ("Unresolved", stats.unresolved),
        ("Budget exhausted", stats.budget_exhausted),
        ("MCP unavailable", stats.mcp_unavailable),
        ("Failed", stats.failed),
        ("Rounds", stats.rounds),
        ("MCP calls", stats.mcp_calls),
        ("Tool failures", stats.tool_failures),
        ("Confidence improved", stats.confidence_improved),
        ("Confidence reduced", stats.confidence_reduced),
        ("Interpretation changed", stats.interpretation_changed),
    ]
    for label, value in rows:
        table.add_row(label, f"{value:,}")
    table.add_row("Avg confidence before", f"{stats.average_confidence_before:.2f}")
    table.add_row("Avg confidence after", f"{stats.average_confidence_after:.2f}")
    console.print(table)


def _render_phase5_stats(stats) -> None:
    console.print("-" * min(console.width, 80), style="cyan")
    console.print("Malware Understanding and Validation", style="bold cyan")
    table = Table.grid(padding=(0, 2))
    table.add_column()
    table.add_column(justify="right")
    rows = [
        ("Functions validated", stats.functions_validated),
        ("Rename candidates", stats.rename_candidates),
        ("Comment candidates", stats.comment_candidates),
        ("Variable candidates", stats.variable_candidates),
        ("Type candidates", stats.type_candidates),
        ("Subsystems", stats.subsystems),
        ("Capabilities", stats.capabilities),
        ("Recovered structures", stats.recovered_structures),
        ("Recovered fields", stats.recovered_fields),
        ("Command handlers", stats.command_handlers),
        ("Configuration items", stats.configuration_items),
        ("Validated artifacts", stats.validated_artifacts),
        ("Validated IOCs", stats.validated_iocs),
        ("Contradictions", stats.contradictions),
        ("Unresolved contradictions", stats.unresolved_contradictions),
        ("Propagation passes", stats.propagation_passes),
        ("Semantic relationships", stats.semantic_relationships),
    ]
    for label, value in rows:
        table.add_row(label, f"{value:,}")
    console.print(table)


def _render_phase6_stats(stats) -> None:
    console.print("-" * min(console.width, 80), style="cyan")
    console.print("IDB Enrichment", style="bold cyan")
    table = Table.grid(padding=(0, 2))
    table.add_column()
    table.add_column(justify="right")
    rows = [
        ("Total candidates", stats.total_candidates),
        ("Eligible candidates", stats.eligible_candidates),
        ("Function renames", stats.function_renames),
        ("Variable renames", stats.variable_renames),
        ("Comments", stats.comments),
        ("Structures", stats.structures),
        ("Structure fields", stats.structure_fields),
        ("Types", stats.types),
        ("Applied", stats.applied),
        ("Verified", stats.verified),
        ("Skipped", stats.skipped),
        ("Failed", stats.failed),
        ("Verification failures", stats.verification_failures),
    ]
    for label, value in rows:
        table.add_row(label, f"{value:,}")
    console.print(table)


def _render_phase7_stats(stats) -> None:
    console.print("-" * min(console.width, 80), style="cyan")
    console.print("Evidence-Backed Report", style="bold cyan")
    table = Table.grid(padding=(0, 2))
    table.add_column()
    table.add_column(justify="right")
    rows = [
        ("Sections generated", stats.sections_generated),
        ("Sections omitted", stats.sections_omitted),
        ("Tables", stats.tables_generated),
        ("Diagrams", stats.diagrams_generated),
        ("IOCs rendered", stats.iocs_rendered),
        ("Functions referenced", stats.functions_referenced),
        ("Evidence references", stats.evidence_references),
        ("Validation failures", stats.validation_failures),
    ]
    for label, value in rows:
        table.add_row(label, f"{value:,}")
    table.add_row("report.md", "OK" if stats.markdown_generated else "-")
    table.add_row("report.html", "OK" if stats.html_generated else "-")
    table.add_row("report.pdf", "OK" if stats.pdf_generated else "-")
    console.print(table)
