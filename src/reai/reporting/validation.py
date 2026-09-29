from __future__ import annotations

from reai.reporting.schemas import ReportModel


def validate_report_model(model: Any) -> list[str]:
    failures: list[str] = []
    funcs = getattr(model, "key_functions", getattr(model, "functions", []))
    if not funcs:
        failures.append("Report has no validated functions.")
    sections = getattr(model, "sections", [])
    if not sections and not getattr(model, "technical_analysis", []):
        failures.append("Report has no generated sections.")
    for function in funcs:
        applied = getattr(function, "applied_name", getattr(function, "idb_name", None))
        display = getattr(function, "display_name", "")
        status = getattr(function, "idb_status", None)
        if applied and applied not in display:
            failures.append(f"IDB-applied name is not represented in report display name: {function.address}")
        if status == "VERIFIED" and not applied:
            failures.append(f"Verified IDB rename is missing applied name: {function.address}")
    return failures


def validate_markdown(markdown: str, model: Any) -> list[str]:
    failures: list[str] = []
    has_exec = "## Executive Summary" in markdown or "## Executive Assessment" in markdown
    if not has_exec:
        failures.append("Markdown is missing required section: Executive Assessment")

    has_sample = "## Sample Information" in markdown or "## 2. Sample Profile" in markdown or "## Sample Profile" in markdown
    if not has_sample:
        failures.append("Markdown is missing required section: Sample Profile")

    has_funcs = "## Important Functions" in markdown or "## 5. Reverse Engineering Findings" in markdown or "## Reverse Engineering" in markdown
    if not has_funcs:
        failures.append("Markdown is missing required section: Reverse Engineering")

    has_appendix = "## Appendix" in markdown or "## 11. Technical Appendix" in markdown or "## Technical Appendix" in markdown
    if not has_appendix:
        failures.append("Markdown is missing required section: Appendix")

    if model.sample.sha256 not in markdown:
        failures.append("Markdown is missing full SHA256.")
    funcs = getattr(model, "key_functions", getattr(model, "functions", []))
    for function in funcs:
        applied = getattr(function, "applied_name", getattr(function, "idb_name", None))
        if applied and applied not in markdown:
            failures.append(f"Markdown is missing verified IDB function name: {applied}")
    return failures
