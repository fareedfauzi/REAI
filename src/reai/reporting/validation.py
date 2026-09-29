from __future__ import annotations

from reai.reporting.schemas import ReportModel


def validate_report_model(model: ReportModel) -> list[str]:
    failures: list[str] = []
    if not model.functions:
        failures.append("Report has no validated functions.")
    if not model.sections:
        failures.append("Report has no generated sections.")
    for function in model.functions:
        if function.idb_name and function.idb_name not in function.display_name:
            failures.append(f"IDB-applied name is not represented in report display name: {function.address}")
        if function.idb_status == "VERIFIED" and not function.idb_name:
            failures.append(f"Verified IDB rename is missing applied name: {function.address}")
    if model.iocs and not any(section.section_id == "iocs" for section in model.sections):
        failures.append("Validated IOCs exist but IOC section was not generated.")
    if model.execution_flows and not any(section.section_id == "execution_flow" for section in model.sections):
        failures.append("Validated execution flows exist but execution-flow section was not generated.")
    return failures


def validate_markdown(markdown: str, model: ReportModel) -> list[str]:
    failures: list[str] = []
    required = ["Executive Summary", "Sample Information", "Important Functions", "Evidence and Confidence", "Appendix"]
    for title in required:
        if f"## {title}" not in markdown:
            failures.append(f"Markdown is missing required section: {title}")
    if model.sample.sha256 not in markdown:
        failures.append("Markdown is missing full SHA256.")
    for function in model.functions:
        if function.idb_name and function.idb_name not in markdown:
            failures.append(f"Markdown is missing verified IDB function name: {function.idb_name}")
    return failures
