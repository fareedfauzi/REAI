from __future__ import annotations

import json
from typing import Any

from reai.extraction.models import ExtractionBundle, ExtractionStats
from reai.extraction.serialization import atomic_write_text, write_json
from reai.reporting.models_v2 import ReportModelV2
from reai.storage.repository import AnalysisRepository
from reai.utils.paths import WorkspacePaths


def write_extraction_findings(workspace: WorkspacePaths, bundle: ExtractionBundle, stats: ExtractionStats) -> None:
    imports = sorted({f"{item.module}!{item.name}" for item in bundle.imports if item.module and item.name})[:30]
    strings = [item.value for item in bundle.strings if _interesting_string(item.value)][:30]
    decompile_failures = [failure for failure in bundle.failures if failure.extractor == "pseudocode"]
    payload = {
        "phase": "Phase 2",
        "summary": _dump(stats),
        "entry_points": bundle.metadata.entry_points,
        "imports": imports,
        "interesting_strings": strings,
        "decompile_failures": [_dump(item) for item in decompile_failures[:25]],
    }
    write_json(workspace.findings / "phase-2-extraction.json", payload)

    lines = [
        "# Phase 2 Findings - Deterministic Extraction",
        "",
        "## Scope",
        "",
        "IDA produced the deterministic corpus used by later analysis: functions, call graph, imports, strings, xrefs, pseudocode, and disassembly.",
        "",
        "## Extraction Summary",
        "",
        f"- Functions discovered: {stats.total_functions}",
        f"- Decompiled successfully: {stats.decompiled_successfully}",
        f"- Decompilation failures: {stats.decompilation_failures}",
        f"- Strings extracted: {stats.strings}",
        f"- Imports extracted: {stats.imports}",
        f"- Call edges: {stats.call_edges}",
        "",
    ]
    if imports:
        lines.extend(["## Important Imports", "", *[f"- `{item}`" for item in imports[:20]], ""])
    if strings:
        lines.extend(["## Interesting Strings", "", *[f"- `{_one_line(item, 180)}`" for item in strings[:20]], ""])
    _write_markdown(workspace, "phase-2-extraction.md", lines)


def write_ai_findings(
    workspace: WorkspacePaths,
    repository: AnalysisRepository,
    sample_id: str,
    stats: Any,
) -> None:
    rows = repository.get_ai_analysis_rows(sample_id)
    functions = []
    for row in rows:
        try:
            result = json.loads(row["result_json"])
        except (TypeError, ValueError):
            result = {}
        functions.append(
            {
                "address": row["address"],
                "original_name": row["original_name"],
                "proposed_name": row["proposed_name"],
                "summary": row["summary"],
                "confidence": row["confidence"],
                "confidence_label": row["confidence_label"],
                "needs_investigation": bool(row["needs_investigation"]),
                "evidence": result.get("evidence", [])[:8],
                "unknowns": result.get("unknowns", [])[:8],
            }
        )
    payload = {"phase": "Phase 3", "stats": _dump(stats), "functions": functions}
    write_json(workspace.findings / "phase-3-bottom-up-ai.json", payload)

    lines = [
        "# Phase 3 Findings - Bottom-Up Function Analysis",
        "",
        "## Scope",
        "",
        "Each function is analyzed independently with extracted pseudocode/disassembly context before higher-level conclusions are built.",
        "",
        "## Summary",
        "",
        f"- Target functions: {getattr(stats, 'target_functions', 0)}",
        f"- Analyzed: {getattr(stats, 'analyzed', 0)}",
        f"- Failed: {getattr(stats, 'failed', 0)}",
        f"- Functions needing MCP investigation: {getattr(stats, 'needs_investigation', 0)}",
        "",
        "## Function Findings",
        "",
    ]
    for item in functions[:50]:
        lines.extend(
            [
                f"### `{item['address']}` `{item['proposed_name'] or item['original_name']}`",
                "",
                f"- Original name: `{item['original_name']}`",
                f"- Confidence: {item['confidence_label']} ({item['confidence']})",
                f"- Summary: {_one_line(str(item['summary'] or ''), 300)}",
                "",
            ]
        )
        if item["unknowns"]:
            lines.extend(["Unresolved questions:", "", *[f"- {_one_line(str(q), 220)}" for q in item["unknowns"][:5]], ""])
    _write_markdown(workspace, "phase-3-bottom-up-ai.md", lines)


def write_mcp_findings(
    workspace: WorkspacePaths,
    repository: AnalysisRepository,
    sample_id: str,
    stats: Any,
) -> None:
    investigations = repository.get_mcp_investigation_rows(sample_id)
    evidence = repository.get_mcp_evidence_rows(sample_id)
    payload = {
        "phase": "Phase 4",
        "stats": _dump(stats),
        "investigations": investigations,
        "evidence": evidence,
    }
    write_json(workspace.findings / "phase-4-mcp-investigation.json", payload)

    lines = [
        "# Phase 4 Findings - MCP Investigation",
        "",
        "## Scope",
        "",
        "MCP checks targeted uncertain or high-importance functions and recorded every tool result as evidence.",
        "",
        "## Summary",
        "",
        f"- Candidates: {getattr(stats, 'candidates', 0)}",
        f"- Attempted: {getattr(stats, 'attempted', 0)}",
        f"- Completed: {getattr(stats, 'completed', 0)}",
        f"- Evidence records: {len(evidence)}",
        f"- Tool calls: {getattr(stats, 'mcp_calls', 0)}",
        "",
        "## Investigation Outcomes",
        "",
    ]
    for row in investigations[:50]:
        lines.extend(
            [
                f"### `{row.get('function_address')}`",
                "",
                f"- Status: {row.get('status')}",
                f"- Outcome: {row.get('outcome')}",
                f"- Confidence: {row.get('confidence_before')} -> {row.get('confidence_after')}",
                "",
            ]
        )
    _write_markdown(workspace, "phase-4-mcp-investigation.md", lines)


def write_semantic_findings(workspace: WorkspacePaths, model: Any) -> None:
    payload = {
        "phase": "Phase 5",
        "stats": _dump(getattr(model, "stats", {})),
        "capabilities": _dump(getattr(model, "capabilities", [])),
        "artifacts": _dump(getattr(model, "validated_artifacts", [])),
        "execution_flows": _dump(getattr(model, "execution_flows", [])),
        "change_candidates": _dump(getattr(model, "change_candidates", [])),
    }
    write_json(workspace.findings / "phase-5-semantic-validation.json", payload)

    stats = getattr(model, "stats", None)
    lines = [
        "# Phase 5 Findings - Semantic Validation",
        "",
        "## Scope",
        "",
        "Function-level findings are propagated, validated, and converted into capabilities, artifacts, execution flow, and IDB change candidates.",
        "",
        "## Summary",
        "",
        f"- Functions validated: {getattr(stats, 'functions_validated', 0)}",
        f"- Validated artifacts: {getattr(stats, 'validated_artifacts', 0)}",
        f"- Validated IOCs: {getattr(stats, 'validated_iocs', 0)}",
        f"- Rename candidates: {getattr(stats, 'rename_candidates', 0)}",
        f"- Comment candidates: {getattr(stats, 'comment_candidates', 0)}",
        f"- Variable candidates: {getattr(stats, 'variable_candidates', 0)}",
        "",
    ]
    artifacts = list(getattr(model, "validated_artifacts", []) or [])
    if artifacts:
        lines.extend(["## Validated Artifacts", ""])
        for item in artifacts[:50]:
            lines.append(
                f"- `{_one_line(str(getattr(item, 'original_value', '')), 180)}` "
                f"({getattr(item, 'artifact_type', 'artifact')}, {getattr(item, 'role', 'context')})"
            )
        lines.append("")
    _write_markdown(workspace, "phase-5-semantic-validation.md", lines)


def write_enrichment_findings(
    workspace: WorkspacePaths,
    repository: AnalysisRepository,
    sample_id: str,
    run_id: str,
    stats: Any,
) -> None:
    changes = repository.get_idb_change_rows(sample_id, run_id)
    verification = repository.get_idb_verification_rows(sample_id, run_id)
    payload = {
        "phase": "Phase 6",
        "stats": _dump(stats),
        "changes": changes,
        "verification": verification,
    }
    write_json(workspace.findings / "phase-6-idb-enrichment.json", payload)

    lines = [
        "# Phase 6 Findings - IDB Enrichment",
        "",
        "## Scope",
        "",
        "Validated function names, variable names, comments, and recovered structures are applied to the companion IDB when safe.",
        "",
        "## Summary",
        "",
        f"- Eligible candidates: {getattr(stats, 'eligible_candidates', 0)}",
        f"- Function renames: {getattr(stats, 'function_renames', 0)}",
        f"- Variable renames: {getattr(stats, 'variable_renames', 0)}",
        f"- Comments: {getattr(stats, 'comments', 0)}",
        f"- Applied: {getattr(stats, 'applied', 0)}",
        f"- Verified: {getattr(stats, 'verified', 0)}",
        "",
        "## Applied Changes",
        "",
    ]
    for row in changes[:80]:
        lines.append(
            f"- `{row.get('address') or ''}` {row.get('entity')} {row.get('operation')}: "
            f"`{_one_line(str(row.get('original') or ''), 80)}` -> `{_one_line(str(row.get('applied') or row.get('proposed') or ''), 120)}` "
            f"({row.get('status')})"
        )
    lines.append("")
    _write_markdown(workspace, "phase-6-idb-enrichment.md", lines)


def write_report_findings(workspace: WorkspacePaths, model: ReportModelV2) -> None:
    write_analyst_notebook(workspace, model)
    payload = {
        "phase": "Phase 7",
        "report_fingerprint": model.fingerprint,
        "source_analysis_fingerprint": model.source_analysis_fingerprint,
        "enrichment_fingerprint": model.enrichment_fingerprint,
        "inputs": [
            "Analysis Findings/analyst-notebook.md",
            "Analysis Findings/phase-2-extraction.md",
            "Analysis Findings/phase-3-bottom-up-ai.md",
            "Analysis Findings/phase-4-mcp-investigation.md",
            "Analysis Findings/phase-5-semantic-validation.md",
            "Analysis Findings/phase-6-idb-enrichment.md",
            "Extracted Codes/pseudocode/",
            "Extracted Codes/disassembly/",
            "Raw Data/",
        ],
    }
    write_json(workspace.findings / "phase-7-report-sources.json", payload)
    lines = [
        "# Phase 7 Findings - Report Source Review",
        "",
        "## Scope",
        "",
        "The final report is synthesized from accumulated phase findings, extracted code, raw artifacts, validated semantics, and IDB enrichment results.",
        "",
        "## Source Trail",
        "",
        "- `Analysis Findings/analyst-notebook.md`",
        "- `Analysis Findings/phase-2-extraction.md`",
        "- `Analysis Findings/phase-3-bottom-up-ai.md`",
        "- `Analysis Findings/phase-4-mcp-investigation.md`",
        "- `Analysis Findings/phase-5-semantic-validation.md`",
        "- `Analysis Findings/phase-6-idb-enrichment.md`",
        "- `Extracted Codes/pseudocode/`",
        "- `Extracted Codes/disassembly/`",
        "- `Raw Data/`",
        "",
    ]
    _write_markdown(workspace, "phase-7-report-sources.md", lines)


def write_analyst_notebook(workspace: WorkspacePaths, model: ReportModelV2) -> None:
    """Write the curated evidence notebook used as final-report source material."""
    strategic_indicators = [
        item
        for item in model.indicators
        if str(item.ioc_type) != "CONTEXTUAL ARTIFACT" and item.value.strip().lower() not in {"mozilla/5.0"}
    ]
    contextual_indicators = [item for item in model.indicators if item not in strategic_indicators]
    notebook = {
        "sample": _dump(model.sample),
        "strategic_indicators": [_dump(item) for item in strategic_indicators],
        "contextual_artifacts": [_dump(item) for item in contextual_indicators],
        "execution_chain": [_dump(stage) for stage in model.execution_chain],
        "critical_functions": [_dump(item) for item in model.key_functions if item.importance_label in {"CRITICAL", "HIGH"}],
        "supporting_functions": model.appendix.runtime_helpers[:25],
        "attack_mappings": [_dump(item) for item in model.attack_mappings],
        "analytical_gaps": [_dump(item) for item in model.analytical_gaps],
        "fingerprints": {
            "source_analysis": model.source_analysis_fingerprint,
            "enrichment": model.enrichment_fingerprint,
            "report": model.fingerprint,
        },
    }
    write_json(workspace.findings / "analyst-notebook.json", notebook)

    lines = [
        "# Analyst Notebook",
        "",
        "This notebook is the curated bridge between phase findings and the final report. It preserves what the analysis knows, what it changed in the IDB, and what still needs review.",
        "",
        "## System and Binary Context",
        "",
        f"- File: `{model.sample.filename}`",
        f"- Type: {model.sample.file_type or 'Unknown'}",
        f"- Architecture: {model.sample.architecture or 'Unknown'} / {model.sample.bitness or 'unknown'}-bit",
        f"- SHA256: `{model.sample.sha256}`",
        f"- Category: {model.sample.observed_role}",
        f"- Primary objective: {model.sample.primary_objective}",
        f"- Overall confidence: {model.sample.confidence_overall}",
        "",
        "## Strategic Indicators",
        "",
    ]
    if strategic_indicators:
        for item in strategic_indicators:
            lines.append(f"- **{item.ioc_type}** `{_one_line(item.display_value, 180)}` - {item.role} ({item.confidence_label})")
    else:
        lines.append("- No validated indicators were promoted into the report model.")
    if contextual_indicators:
        lines.extend(["", "## Contextual Artifacts", ""])
        for item in contextual_indicators:
            lines.append(f"- **{item.ioc_type}** `{_one_line(item.display_value, 180)}` - {item.role} ({item.confidence_label})")
    lines.extend(["", "## Execution Chain", ""])
    if model.execution_chain:
        for stage in model.execution_chain:
            support = ", ".join(stage.functions[:3] + stage.apis[:3] + stage.artifacts[:2])
            lines.append(f"- {stage.step_number}. **{stage.stage_name}**: {_one_line(stage.description, 220)}")
            if support:
                lines.append(f"  Evidence: {_one_line(support, 220)}")
    else:
        lines.append("- No semantic execution chain could be constructed from validated evidence.")
    lines.extend(["", "## Critical Malware-Relevant Functions", ""])
    critical = [item for item in model.key_functions if item.importance_label in {"CRITICAL", "HIGH"}]
    if critical:
        for function in critical:
            lines.extend(
                [
                    f"### `{function.display_name}` `{function.address}`",
                    "",
                    f"- Original name: `{function.original_name}`",
                    f"- Role: {function.role}",
                    f"- Confidence: {function.confidence_label} ({function.confidence_score:.2f})",
                    f"- IDB status: {function.idb_status or 'UNMODIFIED'}",
                    f"- Summary: {_one_line(function.summary, 320)}",
                    "",
                ]
            )
            if function.key_apis:
                lines.extend(["APIs:", "", *[f"- `{api}`" for api in function.key_apis[:8]], ""])
            if function.artifacts:
                reportable_artifacts = [artifact for artifact in function.artifacts if artifact.strip().lower() not in {"mozilla/5.0"}]
                if reportable_artifacts:
                    lines.extend(["Artifacts:", "", *[f"- `{_one_line(artifact, 180)}`" for artifact in reportable_artifacts[:8]], ""])
    else:
        lines.append("- No functions met the critical/high notebook threshold.")
    lines.extend(["", "## Supporting and Runtime Functions", ""])
    helpers = model.appendix.runtime_helpers[:25]
    if helpers:
        for helper in helpers:
            lines.append(f"- `{helper.get('name')}` `{helper.get('address')}` - {_one_line(str(helper.get('summary') or helper.get('category') or ''), 180)}")
    else:
        lines.append("- No low-signal supporting functions were separated from the main report.")
    lines.extend(["", "## ATT&CK and Hunting Leads", ""])
    if model.attack_mappings:
        for mapping in model.attack_mappings:
            lines.append(f"- `{mapping.technique_id}` {mapping.technique}: {_one_line(mapping.observed_behavior, 220)}")
    else:
        lines.append("- No ATT&CK mappings reached the report threshold.")
    if model.hunting_leads:
        lines.extend(["", "Hunting leads:", ""])
        for lead in model.hunting_leads:
            lines.append(f"- **{lead.category}**: {_one_line(lead.detection_guidance, 220)}")
    lines.extend(["", "## Open Questions and Gaps", ""])
    if model.analytical_gaps:
        for gap in model.analytical_gaps:
            lines.append(f"- **{gap.title}**: {_one_line(gap.description, 240)}")
    else:
        lines.append("- No unresolved report-level gaps were recorded.")
    lines.extend(
        [
            "",
            "## Provenance",
            "",
            f"- Source analysis fingerprint: `{model.source_analysis_fingerprint or 'not recorded'}`",
            f"- Enrichment fingerprint: `{model.enrichment_fingerprint or 'not recorded'}`",
            f"- Report fingerprint: `{model.fingerprint}`",
            "",
        ]
    )
    _write_markdown(workspace, "analyst-notebook.md", lines)


def _write_markdown(workspace: WorkspacePaths, name: str, lines: list[str]) -> None:
    atomic_write_text(workspace.findings / name, "\n".join(lines).rstrip() + "\n")


def _dump(value: Any) -> Any:
    if hasattr(value, "model_dump"):
        return value.model_dump(mode="json")
    if isinstance(value, list):
        return [_dump(item) for item in value]
    if isinstance(value, dict):
        return {key: _dump(item) for key, item in value.items()}
    return value


def _interesting_string(value: str) -> bool:
    lowered = value.lower()
    if len(value) >= 120:
        return False
    return any(marker in lowered for marker in ("http://", "https://", ".exe", ".dll", "cmd.exe", "powershell", "public", ".pdb"))


def _one_line(value: str, limit: int) -> str:
    clean = " ".join(value.replace("\r", " ").replace("\n", " ").split())
    if len(clean) <= limit:
        return clean
    return clean[: max(0, limit - 3)].rstrip() + "..."
