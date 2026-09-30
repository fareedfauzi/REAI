from __future__ import annotations

import html
import re
import textwrap
from pathlib import Path

from reai.reporting.models_v2 import (
    ImportanceLevel,
    IOCType,
    KeyFunctionCard,
    ReportModelV2,
)


def render_markdown_v2(model: ReportModelV2) -> str:
    lines: list[str] = []

    lines.append("# Malware Category")
    lines.append("")
    lines.append(_malware_category(model))
    lines.append("")
    lines.append("# Executive Summary")
    lines.append("")
    lines.append(_executive_summary_text(model))
    lines.append("")
    lines.append("This report in a nutshell:")
    for point in _nutshell_points(model):
        lines.append(f"- {point}")
    lines.append("")
    lines.append("# Sample Profile")
    lines.append("")
    for label, value in _sample_profile_items(model):
        lines.append(f"{label}: {value}")
    lines.append("")
    lines.append("# Technical Analysis")
    lines.append("")
    lines.extend(_technical_analysis_lines(model))
    lines.extend(_conclusion_lines(model))
    lines.extend(_ioc_lines(model))
    lines.extend(_yara_lines(model))
    lines.extend(_mitre_lines(model))
    lines.extend(_analyst_note_lines(model))

    return "\n".join(lines).rstrip() + "\n"


def _malware_category(model: ReportModelV2) -> str:
    badges = [badge for badge in model.sample.classification_badges if badge not in {"WINDOWS", f"PE{model.sample.bitness}"}]
    if badges:
        return f"{model.sample.observed_role} ({', '.join(badges).title()})"
    return model.sample.observed_role


def _executive_summary_text(model: ReportModelV2) -> str:
    main = _primary_function(model)
    network = _first_indicator(model, IOCType.NETWORK_IOC)
    host = _first_indicator(model, IOCType.HOST_IOC)
    command = _first_indicator(model, IOCType.COMMAND_LINE_ARTIFACT)
    paragraphs = [
        (
            f"`{model.sample.filename}` is a {model.sample.bitness}-bit Windows executable classified as "
            f"{model.sample.observed_role}. Static analysis shows that the sample's main logic is concentrated in "
            f"`{main.display_name if main else '_main'}` and is responsible for retrieval, local staging, process launch, "
            "and post-execution cleanup behavior."
        )
    ]
    if network and host:
        paragraphs.append(
            f"The downloader retrieves content from `{network.display_value}` and stages it as `{host.display_value}`. "
            "The staged file is then used by the execution path identified in the main function."
        )
    if command:
        paragraphs.append(
            f"The sample also embeds a command-line cleanup pattern, `{command.display_value}`, which is consistent with delayed deletion or artifact removal after execution."
        )
    if _has_timing_stage(model):
        paragraphs.append(
            "A timing routine is present before or during the main workflow. This may affect sandbox timing and should be considered during dynamic analysis."
        )
    paragraphs.append(
        "Attribution is not established from this sample alone. The recovered build path is useful development context, but it is not sufficient to identify an operator or campaign."
    )
    return "\n\n".join(paragraphs)


def _nutshell_points(model: ReportModelV2) -> list[str]:
    points: list[str] = []
    network = _first_indicator(model, IOCType.NETWORK_IOC)
    host = _first_indicator(model, IOCType.HOST_IOC)
    command = _first_indicator(model, IOCType.COMMAND_LINE_ARTIFACT)
    main = _primary_function(model)
    if main:
        points.append(f"Primary logic is implemented in `{main.display_name}` at `{main.address}`.")
    if network:
        points.append(f"Downloads or references remote content from `{network.display_value}`.")
    if host:
        points.append(f"Stages a payload-like file at `{host.display_value}`.")
    if command:
        points.append(f"Contains command execution or cleanup behavior: `{command.display_value}`.")
    if _has_timing_stage(model):
        points.append("Includes timing/sleep behavior that may delay execution or complicate sandbox observation.")
    build = _first_indicator(model, IOCType.BUILD_ARTIFACT)
    if build:
        points.append(f"Contains build provenance string `{build.display_value}`; this is context, not attribution.")
    return points[:6]


def _sample_profile_items(model: ReportModelV2) -> list[tuple[str, str]]:
    return [
        ("MD5", f"`{model.sample.md5}`"),
        ("SHA1", f"`{model.sample.sha1}`"),
        ("SHA256", f"`{model.sample.sha256}`"),
        ("Link time", "Not recovered from current static metadata"),
        ("File Type", str(model.sample.file_type or "Unknown")),
        ("Compiler", _compiler_guess(model)),
        ("File Size", f"{model.sample.size} bytes"),
        ("File Name", f"`{model.sample.filename}`"),
    ]


def _technical_analysis_lines(model: ReportModelV2) -> list[str]:
    lines: list[str] = []
    
    if getattr(model, "ai_narrative", None):
        lines.append(model.ai_narrative.strip())
        lines.append("")
        if model.threat_intelligence.development_context:
            lines.extend(["### Build and Development Context", "", model.threat_intelligence.development_context, ""])
        return lines

    main = _primary_function(model)
    if main:
        lines.extend(
            [
                "### Primary Routine Evidence",
                "",
                f"`{main.display_name}` at `{main.address}` is the primary routine supported by recovered decompiled code.",
                "",
                "| Evidence | Value |",
                "| --- | --- |",
                f"| Original name | `{main.original_name}` |",
                f"| Applied name | `{main.display_name}` |",
                f"| Analyst purpose | {_md_cell(main.role)} |",
                f"| Validated summary | {_md_cell(main.summary)} |",
                f"| Code-backed artifacts | {_md_cell(', '.join(main.artifacts) or 'None promoted')} |",
                "",
            ]
        )
        if main.original_decompiled_code:
            lines.extend(
                [
                    "The following excerpt is from the recovered Hex-Rays pseudocode and is included here as the primary code evidence:",
                    "",
                    "```c",
                    _code_preview(main.original_decompiled_code, max_lines=70),
                    "```",
                    "",
                ]
            )

    network_items = [item for item in model.indicators if item.ioc_type == IOCType.NETWORK_IOC]
    host_items = [item for item in model.indicators if item.ioc_type == IOCType.HOST_IOC]
    if network_items:
        lines.extend(["### Network Evidence", ""])
        first = network_items[0]
        lines.append(
            f"The decompiled routine references `{first.display_value}` as network material. Treat it as an indicator because it is tied to function-level evidence, not because an AI inferred a downloader pattern."
        )
        if len(network_items) > 1:
            lines.append("")
            lines.append("Additional embedded network material was also recovered:")
            lines.extend(f"- `{item.display_value}` ({item.role})" for item in network_items[1:])
        lines.append("")

    if host_items:
        lines.extend(["### File Artifact Evidence", ""])
        for item in host_items:
            lines.append(
                f"`{item.display_value}` is a validated host artifact associated with the same recovered function evidence."
            )
            lines.append("")

    command_items = [item for item in model.indicators if item.ioc_type == IOCType.COMMAND_LINE_ARTIFACT]
    if command_items:
        lines.extend(["### Command Evidence", ""])
        lines.append("The recovered command strings are shown verbatim for analyst validation:")
        lines.append("")
        for item in command_items:
            lines.append("```cmd")
            lines.append(item.value)
            lines.append("```")
            lines.append("")

    timing = next((fn for fn in model.key_functions if "timing" in fn.role.lower() or "sleep" in _join(fn.behaviors).lower()), None)
    if timing:
        lines.extend(
            [
                "### Timing Routine Evidence",
                "",
                f"`{timing.display_name}` at `{timing.address}` was classified from function-level behavior and recovered code context.",
                "",
            ]
        )

    if model.threat_intelligence.development_context:
        lines.extend(["### Build and Development Context", "", model.threat_intelligence.development_context, ""])

    return lines


def _conclusion_lines(model: ReportModelV2) -> list[str]:
    network = _first_indicator(model, IOCType.NETWORK_IOC)
    host = _first_indicator(model, IOCType.HOST_IOC)
    command = _first_indicator(model, IOCType.COMMAND_LINE_ARTIFACT)
    lines = ["", "# Conclusion", ""]
    if network and host and command:
        lines.append(
            f"Based on the validated static findings, `{model.sample.filename}` acts as a {model.sample.observed_role.lower()} "
            f"that retrieves content from `{network.display_value}`, stages it at `{host.display_value}`, launches or prepares execution, "
            "and embeds delayed cleanup behavior. The sample should be treated as malicious downloader activity until the retrieved "
            "secondary payload is recovered and analyzed."
        )
    else:
        lines.append(
            f"Based on the validated static findings, `{model.sample.filename}` is best classified as {model.sample.observed_role}. "
            "The available evidence is static and should be paired with dynamic analysis where possible."
        )
    if model.threat_intelligence.development_context:
        lines.append("")
        lines.append("Recovered development artifacts provide context only and should not be treated as actor attribution.")
    lines.append("")
    return lines


def _ioc_lines(model: ReportModelV2) -> list[str]:
    lines = ["# Indicator of Compromise", ""]
    lines.extend(
        [
            "## Hashes",
            "",
            f"- MD5: `{model.sample.md5}`",
            f"- SHA1: `{model.sample.sha1}`",
            f"- SHA256: `{model.sample.sha256}`",
            "",
        ]
    )
    groups = [
        ("Network IOCs", IOCType.NETWORK_IOC),
        ("Host Artifacts", IOCType.HOST_IOC),
        ("Command Lines", IOCType.COMMAND_LINE_ARTIFACT),
        ("Filenames and Build Artifacts", IOCType.BUILD_ARTIFACT),
    ]
    for title, kind in groups:
        items = [item for item in _report_indicators(model) if item.ioc_type == kind]
        if not items:
            continue
        lines.extend([f"## {title}", ""])
        for item in items:
            lines.append(f"- `{item.display_value}` - {item.role}")
        lines.append("")
    if len(lines) <= 7:
        lines.extend(["No validated indicators were promoted into this report.", ""])
    return lines


def _yara_lines(model: ReportModelV2) -> list[str]:
    lines = ["# YARA Rules", ""]
    if not model.yara_rule:
        lines.extend(["No YARA rule was generated from the validated artifact set.", ""])
        return lines
    lines.extend(
        [
            "The following rule is based on unique validated strings and should be tested against cleanware and malware corpora before operational deployment.",
            "",
            "```yara",
            model.yara_rule.rule_text,
            "```",
            "",
        ]
    )
    return lines


def _mitre_lines(model: ReportModelV2) -> list[str]:
    lines = ["# MITRE ATT&CK Mappings", ""]
    if not model.attack_mappings:
        lines.extend(["No MITRE ATT&CK mappings reached the report threshold.", ""])
        return lines
    lines.extend(["| Tactic | Technique | ID | Evidence |", "| --- | --- | --- | --- |"])
    for mapping in model.attack_mappings:
        funcs = ", ".join(f"`{fn}`" for fn in mapping.functions[:3])
        evidence = mapping.evidence or funcs or mapping.observed_behavior
        lines.append(f"| {mapping.tactic} | {mapping.technique} | `{mapping.technique_id}` | {_md_cell(evidence)} |")
    lines.append("")
    return lines


def _analyst_note_lines(model: ReportModelV2) -> list[str]:
    lines = ["# Note For Analyst", ""]
    lines.extend(_analysis_gap_lines(model))
    lines.extend(_execution_overview_lines(model))
    lines.extend(_capability_feature_lines(model))
    lines.extend(_suspicious_import_lines(model))
    lines.extend(_strings_analysis_lines(model))
    lines.extend(_function_analysis_lines(model))
    return lines


def _analysis_gap_lines(model: ReportModelV2) -> list[str]:
    lines = ["## Analysis gaps", ""]
    if model.analytical_gaps:
        for gap in model.analytical_gaps:
            lines.append(f"- **{gap.title}**: {gap.description} Recommended action: {gap.recommended_action}")
    else:
        lines.append("- Secondary payload contents were not recovered from static analysis alone.")
        lines.append("- Live infrastructure status was not verified during static analysis.")
        lines.append("- Runtime behavior should be confirmed in a sandbox or endpoint telemetry where possible.")
    lines.append("")
    return lines


def _execution_overview_lines(model: ReportModelV2) -> list[str]:
    lines = ["## Execution Flow Overview", ""]
    if not model.execution_chain:
        lines.extend(["No validated execution chain was constructed.", ""])
        return lines
    lines.extend(["| Stage | Description | Evidence |", "| --- | --- | --- |"])
    for stage in model.execution_chain:
        evidence = ", ".join(stage.functions[:2] + stage.apis[:3] + stage.artifacts[:2])
        lines.append(f"| {stage.step_number}. {stage.stage_name} | {_md_cell(stage.description)} | {_md_cell(evidence)} |")
    lines.append("")
    return lines


def _capability_feature_lines(model: ReportModelV2) -> list[str]:
    lines = ["## Capability or Malware Features", ""]
    if not model.execution_chain:
        lines.extend(["No higher-level capabilities were promoted from validated evidence.", ""])
        return lines
    lines.extend(["| Capability | What the evidence supports | Function / Artifact Evidence |", "| --- | --- | --- |"])
    for stage in model.execution_chain:
        formatted_evidence = [f"`{f}`" for f in stage.functions[:2]] + [f"`{a}`" for a in stage.artifacts[:3]]
        evidence = ", ".join(formatted_evidence) or "Function-level evidence only"
        lines.append(f"| {stage.stage_name} | {_md_cell(stage.description)} | {_md_cell(evidence)} |")
    lines.append("")
    return lines


def _suspicious_import_lines(model: ReportModelV2) -> list[str]:
    lines = ["## Suspicious Imports", ""]
    rows: list[tuple[str, str, str]] = []
    for fn in model.key_functions:
        for api in fn.key_apis:
            reason = _api_reason(api)
            if reason:
                rows.append((api, reason, f"{fn.display_name} ({fn.address})"))
    if not rows:
        lines.extend(["No suspicious imports were promoted into the final report.", ""])
        return lines
    lines.extend(["| API Name | Category | Associated Function |", "| --- | --- | --- |"])
    seen: set[tuple[str, str]] = set()
    for api, reason, function in rows:
        key = (api, function)
        if key in seen:
            continue
        seen.add(key)
        lines.append(f"| `{api}` | {reason} | `{function}` |")
    lines.append("")
    return lines


def _strings_analysis_lines(model: ReportModelV2) -> list[str]:
    lines = ["## Strings analysis", ""]
    contextual = [item for item in model.indicators if item.ioc_type == IOCType.CONTEXTUAL_ARTIFACT]
    interesting = _report_indicators(model) + contextual
    if not interesting:
        lines.extend(["No reportable strings were promoted from validation.", ""])
        return lines
    lines.extend(["| String | Category | Notes |", "| --- | --- | --- |"])
    for item in interesting:
        lines.append(f"| `{item.display_value}` | {item.ioc_type} | {_md_cell(item.role)} |")
    lines.append("")
    return lines


def _function_analysis_lines(model: ReportModelV2) -> list[str]:
    lines = ["## Function Analysis", ""]
    full = model.appendix.full_functions
    key_by_address = {fn.address: fn for fn in model.key_functions}
    renamed = [fn for fn in full if _was_renamed_sub(fn)]
    interesting = [fn for fn in model.key_functions if fn.importance_label in {"CRITICAL", "HIGH"}]
    suspicious = [fn for fn in model.key_functions if fn.confidence_label in {"MEDIUM", "LOW"} and fn.importance_label in {"HIGH", "SUPPORTING"}]
    malicious = [fn for fn in model.key_functions if fn.importance_label == "CRITICAL"]
    benign = [fn for fn in full if fn.get("idb_status") == "VERIFIED" and fn.get("address") not in key_by_address][:20]

    lines.extend(_function_bucket("### All renamed sub_* functions", renamed))
    lines.extend(_function_bucket("### Interesting Functions to Check", interesting))
    lines.extend(_function_bucket("### Suspicious Function", suspicious))
    lines.extend(_function_bucket("### Malicious Function", malicious))
    lines.extend(_function_bucket("### Benign Function", benign))
    lines.extend(["### Function in depth", ""])
    depth_items = interesting or model.key_functions[:5]
    if not depth_items:
        lines.extend(["No function-level findings were available for in-depth rendering.", ""])
        return lines
    for item in depth_items[:8]:
        lines.extend(_function_depth_lines(item))
    return lines


def _function_bucket(title: str, functions: list) -> list[str]:
    lines = [title, ""]
    if not functions:
        lines.extend(["- None identified.", ""])
        return lines
    lines.extend(["| Function | Address | Summary |", "| --- | --- | --- |"])
    for fn in functions[:60]:
        if isinstance(fn, KeyFunctionCard):
            name = fn.display_name
            address = fn.address
            summary = fn.summary
        else:
            name = str(fn.get("applied_name") or fn.get("original_name") or "unknown")
            address = str(fn.get("address") or "")
            summary = str(fn.get("summary") or "")
        lines.append(f"| `{name}` | `{address}` | {_md_cell(_one_line(summary, 220))} |")
    lines.append("")
    return lines


def _function_depth_lines(function: KeyFunctionCard) -> list[str]:
    risk = "malicious" if function.importance_label == "CRITICAL" else "suspicious" if function.importance_label == "HIGH" else "benign"
    confidence = int(round(function.confidence_score * 100))
    details = function.behaviors + [f"Uses `{api}`" for api in function.key_apis[:5]] + [f"References `{artifact}`" for artifact in function.artifacts[:4]]
    lines = [
        f"#### {function.display_name} @ {function.address}",
        "",
        f"{risk} Conf: {confidence}% | Importance: {function.importance_label}",
        f"Suggested Names: {function.display_name}",
        f"Purpose: {function.role}.",
        f"Summary: {function.summary}",
        f"Contextual Purpose: {_contextual_purpose(function)}",
        f"Return Value: {_return_value_note(function)}",
        f"Risk Logic: {_risk_logic(function)}",
        "Details:",
    ]
    if details:
        lines.extend(f"- {item}" for item in details)
    else:
        lines.append("- No additional details were promoted.")
    if function.original_decompiled_code:
        lines.extend(
            [
                "",
                "##### Original Decompiled (Hex-Rays)",
                "",
                "```c",
                function.original_decompiled_code.strip(),
                "```",
            ]
        )
    if function.readable_code:
        lines.extend(
            [
                "",
                "##### Readable Code (Analysis Rewrite)",
                "",
                "```c",
                function.readable_code.strip(),
                "```",
            ]
        )
    if function.execution_flow:
        lines.extend(
            [
                "",
                "##### High-level Execution Flow",
                "",
                "```text",
                function.execution_flow.strip(),
                "```",
            ]
        )
    lines.append("")
    return lines


def _primary_function(model: ReportModelV2):
    return next((fn for fn in model.key_functions if fn.address == "0x401080" or "main" in fn.display_name.lower()), model.key_functions[0] if model.key_functions else None)


def _execution_chain_lines(model: ReportModelV2) -> list[str]:
    if not model.execution_chain:
        return []
    lines = [
        "### Execution Chain",
        "",
        "The following flow is reconstructed from validated function roles, call relationships, imports, and artifact references.",
        "",
        "```mermaid",
        "flowchart TD",
    ]
    for stage in model.execution_chain:
        lines.append(f'    S{stage.step_number}["{stage.step_number}. {_mermaid_label(stage.stage_name)}"]')
    for index in range(1, len(model.execution_chain)):
        lines.append(f"    S{index} --> S{index + 1}")
    lines.extend(["```", ""])
    for stage in model.execution_chain:
        evidence = ", ".join(stage.functions[:2] + stage.apis[:3] + stage.artifacts[:2])
        detail = f" Evidence: {evidence}." if evidence else ""
        lines.append(f"- **{stage.step_number}. {stage.stage_name}**: {stage.description}{detail}")
    lines.append("")
    return lines


def _first_indicator(model: ReportModelV2, ioc_type: str):
    return next((item for item in model.indicators if item.ioc_type == ioc_type), None)


def _report_indicators(model: ReportModelV2):
    priority = {
        IOCType.NETWORK_IOC: 0,
        IOCType.HOST_IOC: 1,
        IOCType.COMMAND_LINE_ARTIFACT: 2,
        IOCType.BUILD_ARTIFACT: 3,
    }
    items = [item for item in model.indicators if item.ioc_type in priority]
    return sorted(items, key=lambda item: (priority.get(item.ioc_type, 99), _indicator_role_rank(item), item.display_value))


def _indicator_role_rank(item) -> int:
    role = str(item.role).lower()
    if "retrieval target" in role or "staged" in role or "dropped" in role:
        return 0
    if "command-line" in role:
        return 1
    if "build" in role:
        return 2
    return 3


def _mermaid_label(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"')


def _has_timing_stage(model: ReportModelV2) -> bool:
    return any("timing" in stage.stage_name.lower() for stage in model.execution_chain)


def _compiler_guess(model: ReportModelV2) -> str:
    text = " ".join(
        [item.value for item in model.indicators]
        + [api for fn in model.key_functions for api in fn.key_apis]
        + [helper.get("name", "") for helper in model.appendix.runtime_helpers]
    ).lower()
    if "msvcp" in text or "msvc" in text or "visual studio" in text or ".pdb" in text:
        return "Microsoft Visual C/C++"
    return "Not recovered from current static metadata"


def _join(items: list[str]) -> str:
    return " ".join(str(item) for item in items)


def _md_cell(value: object) -> str:
    return " ".join(str(value).replace("|", "\\|").split())


def _one_line(value: object, limit: int = 160) -> str:
    clean = " ".join(str(value or "").split())
    if len(clean) <= limit:
        return clean
    return clean[: max(0, limit - 3)].rstrip() + "..."


def _code_preview(code: str, max_lines: int = 80) -> str:
    lines = str(code or "").splitlines()
    if len(lines) <= max_lines:
        return str(code or "").strip()
    omitted = len(lines) - max_lines
    return "\n".join(lines[:max_lines]).rstrip() + f"\n/* ... {omitted} line(s) omitted; see Function Analysis for detail ... */"


def _return_value_note(function: KeyFunctionCard) -> str:
    flow = (function.execution_flow or "").lower()
    code = (function.original_decompiled_code or "").lower()
    if "return success" in flow or "return 1" in code:
        return "Returns success/non-zero on one recovered path."
    if "return failure" in flow or "return 0" in code:
        return "Returns zero on one recovered path."
    return "Not fully recovered from the current static model."


def _api_reason(api: str) -> str:
    lower = api.lower()
    if any(token in lower for token in ("internet", "url", "http", "download", "recv", "send", "connect")):
        return "Network retrieval or C2-capable API"
    if any(token in lower for token in ("createprocess", "shellexecute", "winexec", "system")):
        return "Process launch or command execution API"
    if any(token in lower for token in ("createfile", "writefile", "copyfile", "deletefile", "movefile")):
        return "Filesystem staging or cleanup API"
    if any(token in lower for token in ("sleep", "waitforsingleobject", "gettickcount", "queryperformance")):
        return "Timing, delay, or sandbox-sensitive API"
    if any(token in lower for token in ("virtualalloc", "virtualprotect", "writeprocessmemory", "createremotethread")):
        return "Memory manipulation or injection API"
    if any(token in lower for token in ("regopen", "regset", "regcreate", "service", "schtasks")):
        return "Persistence or system configuration API"
    return ""


def _was_renamed_sub(function_row: dict) -> bool:
    original = str(function_row.get("original_name") or function_row.get("name") or "")
    applied = str(function_row.get("applied_name") or "")
    status = str(function_row.get("idb_status") or "").upper()
    if not applied or applied == original:
        return False
    if status and status not in {"APPLIED", "VERIFIED"}:
        return False
    return original.lower().startswith(("sub_", "nullsub_", "loc_"))


def _contextual_purpose(function: KeyFunctionCard) -> str:
    role = function.role.rstrip(".")
    if function.artifacts:
        return f"{role}; references {', '.join(function.artifacts[:3])}."
    if function.key_apis:
        return f"{role}; supported by {', '.join(function.key_apis[:4])}."
    return f"{role} in the recovered execution path."


def _risk_logic(function: KeyFunctionCard) -> str:
    signals: list[str] = []
    if function.key_apis:
        signals.append(f"API evidence includes {', '.join(function.key_apis[:4])}")
    if function.artifacts:
        signals.append(f"artifact evidence includes {', '.join(function.artifacts[:3])}")
    if function.behaviors:
        signals.append(f"behavioral evidence includes {_one_line('; '.join(function.behaviors[:2]), 140)}")
    evidence = "; ".join(signals) if signals else "limited evidence is available in the current static model"
    if function.importance_label == ImportanceLevel.CRITICAL:
        return f"Classified as malicious because it anchors a critical behavior and {evidence}."
    if function.importance_label == ImportanceLevel.HIGH:
        return f"Classified as suspicious because it materially supports the attack chain and {evidence}."
    return f"Classified as supporting because it provides context for higher-risk routines; {evidence}."


def render_html_v2(model: ReportModelV2) -> str:
    md_text = render_markdown_v2(model)

    nav_titles = [
        "Malware Category",
        "Executive Summary",
        "Sample Profile",
        "Technical Analysis",
        "Conclusion",
        "Indicator of Compromise",
        "YARA Rules",
        "MITRE ATT&CK Mappings",
        "Note For Analyst",
        "Analysis gaps",
        "Execution Flow Overview",
        "Capability or Malware Features",
        "Suspicious Imports",
        "Strings analysis",
        "Function Analysis",
    ]
    nav_html = "\n".join(
        f'<li><a href="#{_slugify(title)}">{html.escape(title)}</a></li>' for title in nav_titles
    )
    summary_cards_html = f"""
    <div class="summary-cards">
        <div class="metric-card">
            <span class="card-label">CLASSIFICATION</span>
            <span class="card-value highlight">{html.escape(model.sample.observed_role)}</span>
        </div>
        <div class="metric-card">
            <span class="card-label">PLATFORM</span>
            <span class="card-value">Windows {html.escape(model.sample.architecture)}</span>
        </div>
        <div class="metric-card">
            <span class="card-label">PRIMARY OBJECTIVE</span>
            <span class="card-value">{html.escape(model.sample.primary_objective)}</span>
        </div>
        <div class="metric-card">
            <span class="card-label">NETWORK PROTOCOL</span>
            <span class="card-value">{html.escape(model.sample.c2_retrieval_protocol)}</span>
        </div>
        <div class="metric-card">
            <span class="card-label">PERSISTENCE</span>
            <span class="card-value muted">{html.escape(model.sample.persistence_status)}</span>
        </div>
        <div class="metric-card">
            <span class="card-label">ANALYSIS CONFIDENCE</span>
            <span class="card-value accent">{html.escape(model.sample.confidence_overall)}</span>
        </div>
    </div>
    """
    badges_html = "".join(f'<span class="badge">{html.escape(b)}</span>' for b in model.sample.classification_badges)

    body_lines: list[str] = []
    in_code = False
    code_lang = ""
    code_buffer: list[str] = []
    in_table = False
    in_list = False
    in_section = False
    in_fn_card = False
    in_code_detail = False

    def close_list() -> None:
        nonlocal in_list
        if in_list:
            body_lines.append("</ul>")
            in_list = False

    def close_table() -> None:
        nonlocal in_table
        if in_table:
            body_lines.append("</tbody></table></div>")
            in_table = False

    def close_fn_card() -> None:
        nonlocal in_fn_card
        close_code_detail()
        if in_fn_card:
            body_lines.append("</article>")
            in_fn_card = False

    def close_code_detail() -> None:
        nonlocal in_code_detail
        if in_code_detail:
            body_lines.append("</div></details>")
            in_code_detail = False

    def close_section() -> None:
        nonlocal in_section
        close_list()
        close_table()
        close_fn_card()
        if in_section:
            body_lines.append("</section>")
            in_section = False

    for line in md_text.splitlines():
        if line.startswith("```"):
            if in_code:
                body_lines.append(_render_code_block(code_lang, code_buffer))
                in_code = False
                code_lang = ""
                code_buffer = []
            else:
                code_lang = line[3:].strip().lower()
                code_buffer = []
                in_code = True
            continue

        if in_code:
            code_buffer.append(line)
            continue

        if line.startswith("|"):
            if re.match(r"^\|(?:\s*:?-+:?\s*\|)+$", line.strip()):
                continue
            close_list()
            cells = _split_md_table_row(line)
            if not in_table:
                body_lines.append('<div class="table-container"><table class="data-table">')
                in_table = True
                body_lines.append("<thead><tr>" + "".join(f"<th>{_format_cell(c)}</th>" for c in cells) + "</tr></thead><tbody>")
            else:
                body_lines.append("<tr>" + "".join(f"<td>{_format_cell(c)}</td>" for c in cells) + "</tr>")
            continue

        close_table()

        if line.startswith("# "):
            close_section()
            sec_title = line[2:].strip()
            anchor_id = _slugify(sec_title)
            body_lines.append(f'<section class="section" id="{anchor_id}">')
            body_lines.append(f'<h2 class="section-title">{html.escape(sec_title)}</h2>')
            in_section = True
        elif line.startswith("## "):
            close_list()
            close_table()
            close_fn_card()
            sec_title = line[3:].strip()
            anchor_id = _slugify(sec_title)
            body_lines.append(f'<h3 class="subsection-title" id="{anchor_id}">{html.escape(sec_title)}</h3>')
        elif line.startswith("### "):
            close_list()
            close_fn_card()
            sub_title = line[4:].strip()
            body_lines.append(f'<h3 class="subsection-title" id="{_slugify(sub_title)}">{html.escape(sub_title)}</h3>')
        elif line.startswith("#### "):
            close_list()
            close_fn_card()
            h4_title = line[5:].strip()
            body_lines.append('<article class="fn-card">')
            body_lines.append(f'<h4 class="fn-card-title">{html.escape(h4_title)}</h4>')
            in_fn_card = True
        elif line.startswith("##### "):
            close_list()
            close_code_detail()
            detail_title = line[6:].strip()
            body_lines.append('<details class="code-section">')
            body_lines.append(
                '<summary class="code-section-header">'
                '<span class="toggle-icon">&#9662;</span>'
                f'<span>{html.escape(detail_title)}</span>'
                '</summary><div class="code-section-body">'
            )
            in_code_detail = True
        elif line.startswith("- "):
            if not in_list:
                body_lines.append('<ul class="bullet-list">')
                in_list = True
            body_lines.append(f'<li class="bullet-item">{_format_inline(line[2:])}</li>')
        elif line.startswith("> "):
            close_list()
            body_lines.append(f'<blockquote>{_format_inline(line[2:])}</blockquote>')
        elif line.strip():
            close_list()
            if in_fn_card:
                body_lines.append(_render_function_card_line(line))
            else:
                body_lines.append(f'<p>{_format_inline(line)}</p>')
        else:
            close_list()

    close_section()

    if in_code:
        body_lines.append(_render_code_block(code_lang, code_buffer))

    rendered_body = "\n".join(body_lines)

    html_page = f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>REAI Analysis: {html.escape(model.sample.filename)}</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Fira+Code:wght@400;600&family=Inter:wght@400;500;600;700;800&display=swap" rel="stylesheet">
<style>
:root {{
    --bg: #f8fafc;
    --text: #0f172a;
    --card: #ffffff;
    --accent: #4f46e5;
    --border: #e2e8f0;
    --muted: #64748b;
    --soft: #f1f5f9;
    --code-bg: #0f172a;
    --success: #16a34a;
    --warning: #d97706;
}}

* {{ box-sizing: border-box; margin: 0; padding: 0; }}
body {{
    background: var(--bg);
    color: var(--text);
    font-family: "Inter", -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
    line-height: 1.6;
    font-size: 14px;
    padding-bottom: 80px;
}}

.header {{
    background: linear-gradient(135deg, #1e293b, #0f172a);
    color: white;
    padding: 20px 40px;
    position: sticky;
    top: 0;
    z-index: 1000;
    box-shadow: 0 4px 15px rgba(15, 23, 42, 0.14);
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 24px;
}}
.header h1 {{
    font-size: 20px;
    font-weight: 800;
    margin-bottom: 4px;
    color: #ffffff;
}}
.header-meta {{
    color: #cbd5e1;
    font-size: 12px;
    font-family: "Fira Code", monospace;
    word-break: break-all;
}}
.status-pill {{
    background: rgba(79, 70, 229, 0.22);
    border: 1px solid rgba(199, 210, 254, 0.36);
    border-radius: 999px;
    color: #ffffff;
    font-weight: 700;
    padding: 8px 14px;
    white-space: nowrap;
}}
.layout {{
    display: flex;
    align-items: flex-start;
    max-width: 1480px;
    margin: 0 auto;
    padding: 30px 20px;
    gap: 22px;
}}
.sidebar {{
    width: 260px;
    background: var(--card);
    border: 1px solid var(--border);
    border-radius: 12px;
    position: sticky;
    top: 92px;
    max-height: calc(100vh - 112px);
    padding: 18px 14px;
    overflow-y: auto;
    flex-shrink: 0;
    box-shadow: 0 2px 4px rgba(15, 23, 42, 0.03);
}}
.sidebar .brand {{
    font-weight: 800;
    font-size: 12px;
    letter-spacing: 1px;
    color: #1e293b;
    text-transform: uppercase;
    margin-bottom: 14px;
    padding: 0 8px 12px;
    border-bottom: 1px solid var(--border);
}}
.sidebar ul {{ list-style: none; }}
.sidebar li {{ margin-bottom: 2px; }}
.sidebar a {{
    color: var(--muted);
    text-decoration: none;
    font-size: 13px;
    display: block;
    padding: 7px 8px;
    border-radius: 6px;
}}
.sidebar a:hover {{
    color: var(--accent);
    background: #eef2ff;
}}
.content {{
    flex: 1;
    min-width: 0;
    max-width: 1250px;
}}
.badges-container {{
    display: flex;
    flex-wrap: wrap;
    gap: 8px;
    margin-top: 8px;
}}
.badge {{
    background: rgba(255, 255, 255, 0.1);
    border: 1px solid rgba(255, 255, 255, 0.18);
    color: #e0e7ff;
    font-family: "Fira Code", monospace;
    font-size: 11px;
    font-weight: 600;
    padding: 4px 10px;
    border-radius: 4px;
    letter-spacing: 0.5px;
}}

/* Summary Cards */
.summary-cards {{
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
    gap: 14px;
    margin-bottom: 24px;
}}
.metric-card {{
    background: var(--card);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 16px;
    box-shadow: 0 2px 4px rgba(15, 23, 42, 0.03);
}}
.card-label {{
    font-size: 11px;
    font-weight: 700;
    color: var(--muted);
    letter-spacing: 0.5px;
    margin-bottom: 8px;
    display: block;
}}
.card-value {{
    font-size: 14px;
    font-weight: 700;
    color: var(--text);
    display: block;
}}
.card-value.highlight {{ color: var(--accent); }}
.card-value.accent {{ color: var(--accent); }}
.card-value.muted {{ color: var(--muted); }}
.section {{
    background: var(--card);
    border-radius: 12px;
    padding: 30px;
    margin-bottom: 25px;
    box-shadow: 0 2px 4px rgba(15, 23, 42, 0.03);
    border: 1px solid var(--border);
}}
.section-title {{
    font-size: 20px;
    font-weight: 700;
    color: #1e293b;
    border-bottom: 2px solid var(--soft);
    padding-bottom: 12px;
    margin-bottom: 20px;
}}
.subsection-title {{
    font-size: 16px;
    font-weight: 700;
    color: #334155;
    margin: 24px 0 12px;
}}
p {{
    color: #334155;
    margin-bottom: 14px;
}}
.bullet-list {{
    margin: 8px 0 18px 20px;
}}
.bullet-item {{
    margin-bottom: 7px;
    color: #334155;
}}
.table-container {{
    overflow-x: auto;
    margin: 16px 0 24px;
    border: 1px solid var(--border);
    border-radius: 8px;
    background: #ffffff;
}}
.data-table {{
    width: 100%;
    border-collapse: collapse;
    font-size: 13px;
    text-align: left;
}}
.data-table th {{
    background: var(--soft);
    color: #475569;
    font-weight: 600;
    padding: 12px 15px;
}}
.data-table td {{
    padding: 12px 15px;
    border-bottom: 1px solid var(--border);
    color: #334155;
    vertical-align: top;
}}
.data-table tr:hover td {{ background: #f8fafc; }}
.fn-card {{
    background: #ffffff;
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 20px;
    margin: 16px 0 20px;
    box-shadow: 0 1px 3px rgba(15, 23, 42, 0.05);
}}
.fn-card-title {{
    font-family: "Fira Code", "Cascadia Code", monospace;
    font-size: 16px;
    font-weight: 600;
    color: #1e293b;
    margin-bottom: 12px;
    border-bottom: 1px dotted #cbd5e1;
    padding-bottom: 8px;
}}
.fn-info-row {{
    margin-bottom: 8px;
    color: #334155;
}}
.muted {{ color: var(--muted); }}
.risk-badge {{
    display: inline-block;
    padding: 4px 12px;
    border-radius: 12px;
    font-size: 11px;
    font-weight: 800;
    text-transform: uppercase;
    box-shadow: 0 1px 2px rgba(15, 23, 42, 0.1);
    margin-right: 8px;
}}
.code-section {{
    margin-top: 8px;
    border: 1px solid var(--border);
    border-radius: 8px;
    overflow: hidden;
    background: #ffffff;
}}
.code-section-header {{
    display: flex;
    align-items: center;
    gap: 8px;
    background: #f8fafc;
    padding: 8px 14px;
    cursor: pointer;
    font-weight: 800;
    font-size: 11px;
    color: #64748b;
    text-transform: uppercase;
    letter-spacing: 0.4px;
    user-select: none;
    list-style: none;
}}
.code-section-header::-webkit-details-marker {{ display: none; }}
.code-section-header::marker {{ display: none; content: ""; }}
.code-section-header:hover {{
    background: #f1f5f9;
    color: var(--accent);
}}
.code-section-body pre {{
    margin: 0;
    border-radius: 0;
    max-height: 680px;
    border: none;
}}
pre {{
    background: var(--code-bg);
    border-radius: 8px;
    padding: 16px;
    overflow-x: auto;
    margin: 16px 0;
    color: #e2e8f0;
    font-family: "Fira Code", "Cascadia Code", monospace;
    font-size: 12px;
}}
.mermaid-wrap {{
    background: #ffffff;
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 20px;
    overflow-x: auto;
    margin: 16px 0 24px;
    box-shadow: 0 1px 3px rgba(15, 23, 42, 0.04);
}}
.mermaid {{ min-width: 520px; }}
code {{
    font-family: "Fira Code", "Cascadia Code", monospace;
    font-size: 12.5px;
}}
p code, td code, li code {{
    background: #f1f5f9;
    border: 1px solid #cbd5e1;
    padding: 2px 6px;
    border-radius: 4px;
    color: #1e293b;
}}
blockquote {{
    white-space: pre-wrap;
    color: #334155;
    line-height: 1.7;
    background: #fbfcfe;
    padding: 20px;
    border-left: 4px solid var(--accent);
    border-radius: 4px 8px 8px 4px;
    margin: 16px 0;
}}
@media (max-width: 900px) {{
    .header {{ position: static; padding: 18px 20px; flex-direction: column; align-items: flex-start; }}
    .layout {{ display: block; padding: 20px 14px; }}
    .sidebar {{ width: 100%; max-height: none; position: static; margin-bottom: 18px; }}
    .section {{ padding: 22px; }}
}}
</style>
</head>
<body>
<header class="header">
    <div>
        <h1>REAI Malware Analysis Report</h1>
        <div class="header-meta">Target: {html.escape(model.sample.filename)} | SHA256: {html.escape(model.sample.sha256)}</div>
        <div class="badges-container">
            {badges_html}
        </div>
    </div>
    <div class="status-pill">{html.escape(model.sample.observed_role)}</div>
</header>

<div class="layout">
    <aside class="sidebar">
        <div class="brand">Report Navigation</div>
        <ul>
            {nav_html}
        </ul>
    </aside>
    <main class="content">
        {summary_cards_html}
        {rendered_body}
    </main>
</div>

<script src="https://cdn.jsdelivr.net/npm/mermaid@10/dist/mermaid.min.js"></script>
<script>
mermaid.initialize({{
    startOnLoad: true,
    theme: "default",
    securityLevel: "strict",
    flowchart: {{ useMaxWidth: true, htmlLabels: true }}
}});
</script>
<script src="https://code.jquery.com/jquery-3.7.0.min.js"></script>
<link rel="stylesheet" href="https://cdn.datatables.net/1.13.6/css/jquery.dataTables.min.css">
<script src="https://cdn.datatables.net/1.13.6/js/jquery.dataTables.min.js"></script>
<style>
/* Modern DataTables Styling */
.dataTables_wrapper {{
    padding: 16px 0;
    font-family: inherit;
    font-size: 13.5px;
    color: var(--text);
}}
.dataTables_wrapper .dataTables_filter input {{
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 6px 12px;
    margin-left: 8px;
    font-size: 13px;
    outline: none;
    box-shadow: inset 0 1px 2px rgba(15,23,42,0.02);
    transition: all 0.2s;
    background: #fff;
}}
.dataTables_wrapper .dataTables_filter input:focus {{
    border-color: var(--accent);
    box-shadow: 0 0 0 3px rgba(79, 70, 229, 0.15);
}}
.dataTables_wrapper .dataTables_length select {{
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 4px 8px;
    font-size: 13px;
    outline: none;
    background: #fff;
}}
.dataTables_wrapper .dataTables_paginate .paginate_button {{
    padding: 0.4em 0.8em !important;
    margin-left: 4px;
    border-radius: 6px !important;
    border: 1px solid transparent !important;
    color: var(--muted) !important;
    font-weight: 500;
    transition: all 0.15s;
}}
.dataTables_wrapper .dataTables_paginate .paginate_button:hover {{
    background: var(--soft) !important;
    border-color: var(--border) !important;
    color: var(--text) !important;
}}
.dataTables_wrapper .dataTables_paginate .paginate_button.current, 
.dataTables_wrapper .dataTables_paginate .paginate_button.current:hover {{
    background: var(--accent) !important;
    color: white !important;
    border-color: var(--accent) !important;
    box-shadow: 0 2px 4px rgba(79, 70, 229, 0.2);
}}
.dataTables_wrapper .dataTables_info {{
    color: var(--muted) !important;
    padding-top: 1.2em !important;
}}
table.dataTable.no-footer {{
    border-bottom: 1px solid var(--border) !important;
}}
table.dataTable thead th {{
    background: var(--soft) !important;
    color: #475569 !important;
    border-bottom: 2px solid var(--border) !important;
    font-weight: 600 !important;
    padding: 12px 15px !important;
}}
table.dataTable tbody td {{
    padding: 12px 15px !important;
    border-bottom: 1px solid var(--border) !important;
}}
table.dataTable tbody tr:hover {{
    background: #f8fafc !important;
}}

/* Improve code block string readability inside the table */
table.dataTable tbody td code {{
    background: transparent;
    border: none;
    padding: 0;
    color: #0f172a;
    font-weight: 500;
    font-size: 13px;
    word-break: break-all;
}}
</style>
<script>
$(document).ready(function() {{
    $('#strings-analysis').nextUntil('h2, h3', '.table-container').find('table').DataTable({{
        pageLength: 20,
        lengthMenu: [10, 20, 50, 100],
        language: {{ search: "Filter strings:" }}
    }});
}});
</script>
</body>
</html>
"""
    return html_page


def _render_code_block(lang: str, lines: list[str]) -> str:
    code = "\n".join(lines)
    if lang == "mermaid":
        return f'<div class="mermaid-wrap"><div class="mermaid">{html.escape(code)}</div></div>'
    class_name = f' class="language-{html.escape(lang)}"' if lang else ""
    return f"<pre><code{class_name}>{html.escape(code)}</code></pre>"


def _render_function_card_line(line: str) -> str:
    lowered = line.lower()
    for risk in ("malicious", "suspicious", "benign"):
        if lowered.startswith(risk):
            rest = line[len(risk):].strip()
            return f'<div class="fn-info-row">{_risk_badge_html(risk)} <span class="muted">{html.escape(rest)}</span></div>'
    for label in ("Suggested Names", "Purpose", "Summary", "Contextual Purpose", "Return Value", "Risk Logic"):
        prefix = f"{label}:"
        if line.startswith(prefix):
            return f'<div class="fn-info-row"><b>{html.escape(label)}:</b> {_format_inline(line[len(prefix):].strip())}</div>'
    if line == "Details:":
        return '<div class="fn-info-row"><b>Details:</b></div>'
    return f"<p>{_format_inline(line)}</p>"


def _risk_badge_html(risk: str) -> str:
    colors = {
        "malicious": "#dc2626",
        "suspicious": "#f59e0b",
        "benign": "#16a34a",
    }
    color = colors.get(risk.lower(), "#64748b")
    return (
        f'<span class="risk-badge" style="background:{color};color:#fff;">'
        f"{html.escape(risk.upper())}</span>"
    )


def _slugify(text: str) -> str:
    cleaned = re.sub(r"[^a-zA-Z0-9\s-]", "", text).strip().lower()
    return re.sub(r"[\s-]+", "-", cleaned)


def _format_inline(text: str) -> str:
    # Escape HTML first
    escaped = html.escape(text)
    # Format code ticks `foo`
    escaped = re.sub(r"`([^`]+)`", r"<code>\1</code>", escaped)
    # Format bold **foo**
    escaped = re.sub(r"\*\*([^*]+)\*\*", r"<strong>\1</strong>", escaped)
    # Format italic *foo*
    escaped = re.sub(r"\*([^*]+)\*", r"<em>\1</em>", escaped)
    return escaped


def _format_inline_pdf(text: str) -> str:
    escaped = html.escape(text)
    escaped = re.sub(r"`([^`]+)`", r"<font name='Courier'>\1</font>", escaped)
    escaped = re.sub(r"\*\*([^*]+)\*\*", r"<b>\1</b>", escaped)
    escaped = re.sub(r"\*([^*]+)\*", r"<i>\1</i>", escaped)
    return escaped


def _split_md_table_row(line: str) -> list[str]:
    content = line.strip().strip("|")
    cells: list[str] = []
    current: list[str] = []
    escaped = False
    for char in content:
        if escaped:
            if char == "|":
                current.append("|")
            else:
                current.append("\\")
                current.append(char)
            escaped = False
            continue
        if char == "\\":
            escaped = True
            continue
        if char == "|":
            cells.append("".join(current).strip())
            current = []
            continue
        current.append(char)
    if escaped:
        current.append("\\")
    cells.append("".join(current).strip())
    return cells


def _format_cell(cell: str) -> str:
    return _format_inline(cell)


def render_pdf_v2(markdown: str, model: ReportModelV2, pdf_path: Path) -> None:
    """Renders a structured, publication-ready PDF using reportlab or fallback text PDF."""
    try:
        from reportlab.lib.pagesizes import letter
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib import colors

        doc = SimpleDocTemplate(
            str(pdf_path),
            pagesize=letter,
            rightMargin=40,
            leftMargin=40,
            topMargin=40,
            bottomMargin=40,
        )
        styles = getSampleStyleSheet()

        title_style = ParagraphStyle(
            "CoverTitle",
            parent=styles["Title"],
            fontSize=22,
            leading=26,
            textColor=colors.HexColor("#0D131C"),
            spaceAfter=15,
        )
        h2_style = ParagraphStyle(
            "Heading2",
            parent=styles["Heading2"],
            fontSize=14,
            leading=18,
            textColor=colors.HexColor("#1A365D"),
            spaceBefore=12,
            spaceAfter=8,
            keepWithNext=True,
        )
        h3_style = ParagraphStyle(
            "Heading3",
            parent=styles["Heading3"],
            fontSize=12,
            leading=16,
            textColor=colors.HexColor("#2D3748"),
            spaceBefore=10,
            spaceAfter=6,
            keepWithNext=True,
        )
        h4_style = ParagraphStyle(
            "Heading4",
            parent=styles["Heading4"],
            fontSize=10.5,
            leading=14,
            textColor=colors.HexColor("#4A5568"),
            spaceBefore=8,
            spaceAfter=4,
            keepWithNext=True,
        )
        h5_style = ParagraphStyle(
            "Heading5",
            parent=styles.get("Heading5", styles["Normal"]),
            fontSize=9.5,
            leading=12,
            textColor=colors.HexColor("#4A5568"),
            spaceBefore=6,
            spaceAfter=4,
            keepWithNext=True,
        )
        body_style = ParagraphStyle(
            "Body",
            parent=styles["Normal"],
            fontSize=9.5,
            leading=13.5,
            textColor=colors.HexColor("#2D3748"),
            spaceAfter=6,
        )
        code_style = ParagraphStyle(
            "Code",
            parent=styles["Code"],
            fontSize=8,
            leading=10,
            textColor=colors.HexColor("#2B6CB0"),
        )
        table_cell_style = ParagraphStyle(
            "TableCell",
            parent=body_style,
            fontSize=8.5,
            leading=11,
        )

        story = []
        story.append(Paragraph(f"<b>REAI MALWARE ANALYSIS REPORT</b>", body_style))
        story.append(Spacer(1, 10))
        story.append(Paragraph(f"{model.sample.filename}", title_style))
        story.append(Paragraph(f"<b>Classification:</b> {model.sample.observed_role} | <b>Platform:</b> Windows {model.sample.architecture}", body_style))
        story.append(Paragraph(f"<b>SHA256:</b> <font name='Courier'>{model.sample.sha256}</font>", body_style))
        story.append(Paragraph(f"<b>Analysis Timestamp:</b> {model.sample.analysis_timestamp}", body_style))
        story.append(Spacer(1, 15))

        # Process markdown sections into PDF elements
        in_code_block = False
        code_lang = ""
        code_lines: list[str] = []
        
        table_data = []

        def flush_table():
            if table_data:
                t = Table(table_data, colWidths=[None]*len(table_data[0]))
                t.setStyle(TableStyle([
                    ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#f1f5f9")),
                    ('TEXTCOLOR', (0,0), (-1,0), colors.HexColor("#1A365D")),
                    ('ALIGN', (0,0), (-1,-1), 'LEFT'),
                    ('VALIGN', (0,0), (-1,-1), 'TOP'),
                    ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
                    ('BOTTOMPADDING', (0,0), (-1,0), 6),
                    ('BACKGROUND', (0,1), (-1,-1), colors.white),
                    ('GRID', (0,0), (-1,-1), 1, colors.HexColor("#e2e8f0"))
                ]))
                story.append(t)
                story.append(Spacer(1, 6))
                table_data.clear()

        for line in markdown.splitlines():
            if not line.startswith("|"):
                flush_table()

            if line.startswith("# Malware Analysis Report"):
                continue
            if line.startswith("```"):
                if in_code_block:
                    if code_lang == "mermaid":
                        story.append(Paragraph("<b>Execution chain diagram:</b>", body_style))
                        for item in code_lines:
                            if "-->" in item or "-.->" in item:
                                story.append(Paragraph(html.escape(item.strip()), code_style))
                    else:
                        wrapped = []
                        for code_line in code_lines:
                            wrapped.extend(textwrap.wrap(code_line, width=95) or [""])
                        story.append(Paragraph("<br/>".join(html.escape(item) for item in wrapped[:80]), code_style))
                    story.append(Spacer(1, 6))
                    code_lines = []
                    in_code_block = False
                    code_lang = ""
                else:
                    code_lang = line[3:].strip().lower()
                    in_code_block = True
                continue
            if in_code_block:
                code_lines.append(line)
                continue

            if line.startswith("##### "):
                story.append(Paragraph(f"<b>{_format_inline_pdf(line[6:])}</b>", h5_style))
            elif line.startswith("#### "):
                story.append(Paragraph(f"<b>{_format_inline_pdf(line[5:])}</b>", h4_style))
            elif line.startswith("### "):
                story.append(Paragraph(f"<b>{_format_inline_pdf(line[4:])}</b>", h3_style))
            elif line.startswith("## "):
                story.append(Paragraph(f"<b>{_format_inline_pdf(line[3:])}</b>", h2_style))
            elif line.startswith("# "):
                story.append(Paragraph(f"<b>{_format_inline_pdf(line[2:])}</b>", h2_style))
            elif line.startswith("|"):
                if re.match(r"^\|(?:\s*:?-+:?\s*\|)+$", line.strip()):
                    continue
                cells = [c.strip() for c in line.strip("|").split("|")]
                row = [Paragraph(_format_inline_pdf(c), table_cell_style) for c in cells]
                table_data.append(row)
            elif line.strip():
                story.append(Paragraph(_format_inline_pdf(line), body_style))
                
        flush_table()
        doc.build(story)
    except Exception:
        # Fallback to deterministic PDF generation
        _render_plain_pdf_v2(markdown, model, pdf_path)


def _render_plain_pdf_v2(markdown: str, model: ReportModelV2, pdf_path: Path) -> None:
    """Robust plain text PDF fallback with real page objects."""
    from reai.reporting.render import _write_simple_pdf

    text_lines = _markdown_to_pdf_lines_v2(markdown)
    pages: list[list[str]] = []
    current: list[str] = []
    for line in text_lines:
        for wrapped in textwrap.wrap(line, width=92) or [""]:
            current.append(wrapped)
            if len(current) >= 54:
                pages.append(current)
                current = []
    if current:
        pages.append(current)
    _write_simple_pdf(pdf_path, pages or [[f"REAI Malware Analysis Report: {model.sample.filename}"]])


def _markdown_to_pdf_lines_v2(markdown: str) -> list[str]:
    lines: list[str] = []
    in_code = False
    code_lang = ""
    for line in markdown.splitlines():
        if line.startswith("```"):
            if in_code:
                in_code = False
                code_lang = ""
            else:
                code_lang = line[3:].strip().lower()
                in_code = True
                if code_lang == "mermaid":
                    lines.append("Execution chain diagram:")
            continue
        if in_code and code_lang != "mermaid":
            lines.append(line)
            continue
        if in_code and code_lang == "mermaid":
            if "-->" in line or "-.->" in line:
                lines.append(line.strip())
            continue
        if re.match(r"^\|(?:\s*:?-+:?\s*\|)+$", line.strip()):
            continue
        clean = re.sub(r"^#{1,6}\s*", "", line)
        clean = re.sub(r"</?(details|summary|strong)>", "", clean)
        clean = clean.replace("|", "  ")
        clean = re.sub(r"`([^`]+)`", r"\1", clean)
        clean = clean.replace("**", "").replace("*", "")
        lines.append(html.unescape(clean))
    return lines

