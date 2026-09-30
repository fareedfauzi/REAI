from __future__ import annotations

import hashlib
import json
import re
from typing import Any

from reai.core.config import ReportConfig
from reai.reporting.models_v2 import (
    AnalyticalGap,
    AppendixModel,
    APISequence,
    AttackMappingDetail,
    ExecutionChainStage,
    HuntingLead,
    IOCItem,
    IOCType,
    KeyFinding,
    KeyFunctionCard,
    RecoveredStructure,
    ReportModelV2,
    ReportStatsV2,
    SampleProfile,
    TechnicalBehaviorSection,
    ThreatIntelligenceModel,
    YaraRuleModel,
)
from reai.storage.database import connect_database
from reai.storage.repository import AnalysisRepository
from reai.utils.paths import WorkspacePaths


CRT_RUNTIME_NAMES = {
    "scrt",
    "except_handler",
    "seh_",
    "initterm",
    "security_cookie",
    "guard_check",
    "register_onexit",
    "initialize_stdio",
    "set_app_type",
    "memset",
    "memcpy",
    "alldiv",
    "allmul",
}

STUB_NAMES = {"return_one", "return_zero", "noop_function", "nullsub", "recursive_noop_function"}

NETWORK_APIS = ("internet", "winhttp", "urldownload", "socket", "connect", "recv", "send", "dns")
PROCESS_APIS = ("createprocess", "shellexecute", "winexec", "createthread", "loadlibrary")
FILE_APIS = ("createfile", "writefile", "readfile", "deletefile", "copyfile", "movefile")
TIMING_APIS = ("sleep", "gettickcount", "queryperformance", "perf_counter", "perf_frequency")
PERSISTENCE_TERMS = ("run key", "startup", "service", "schtasks", "persistence", "autorun")


def defang_indicator(value: str, kind: str) -> str:
    if not value:
        return value
    if kind in {"url", "domain"}:
        defanged = value.replace("http://", "hxxp://").replace("https://", "hxxps://")
        return re.sub(r"\.(?=[A-Za-z0-9_-])", "[.]", defanged)
    if kind == "ip":
        return re.sub(r"\.(?=[0-9])", "[.]", value)
    if kind in {"file_path", "command_line"}:
        return value.replace(".exe", "[.]exe").replace(".dll", "[.]dll")
    return value


def synthesize_report_model(
    config: ReportConfig,
    repository: AnalysisRepository,
    workspace: WorkspacePaths,
    sample_id: str,
) -> ReportModelV2:
    rows = _load_report_rows(repository, sample_id)
    sample_row = rows["sample"]
    if not sample_row:
        raise KeyError(f"Sample not found: {sample_id}")

    report_artifacts = [artifact for artifact in rows["artifacts"] if _is_reportable_artifact(artifact)]

    profile = _build_sample_profile(sample_row, rows["metadata"], rows["functions"], report_artifacts)
    key_functions, runtime_helpers = _score_and_categorize_functions(
        rows["functions"],
        rows["applied_names"],
        rows["import_usage"],
        report_artifacts,
        rows["flow_rows"],
        config.max_important_functions,
        workspace,
    )
    indicators = _build_indicators(report_artifacts, config.defang_iocs)
    execution_chain = _build_semantic_execution_chain(key_functions, report_artifacts, rows["flow_rows"])
    technical_analysis = _build_technical_analysis(key_functions, indicators, rows["configuration_items"], execution_chain)
    executive_assessment = _build_executive_assessment(profile, key_functions, indicators, execution_chain)
    key_findings = _build_key_findings(key_functions, indicators, execution_chain)
    api_sequences = _build_api_sequences(execution_chain)
    structures = _build_structures(rows["structure_rows"])
    threat_intel = _build_threat_intel(indicators, profile)
    attack_mappings = _build_attack_mappings(key_functions, indicators, execution_chain)
    hunting_leads = _build_hunting_leads(indicators, execution_chain)
    yara_rule = _build_yara_rule(profile, indicators)
    analytical_gaps = _build_analytical_gaps(key_functions, indicators, rows["contradiction_rows"], rows["question_rows"], execution_chain)
    appendix = _build_appendix(
        runtime_helpers,
        rows["functions"],
        rows["applied_names"],
        repository.get_validated_analysis_fingerprint(sample_id),
        rows["enrichment_fingerprint"],
    )

    fingerprint_data = {
        "sample": profile.model_dump(),
        "findings": [finding.model_dump() for finding in key_findings],
        "chain": [stage.model_dump() for stage in execution_chain],
        "iocs": [indicator.model_dump() for indicator in indicators],
        "attack": [mapping.model_dump() for mapping in attack_mappings],
        "schema": "report-engine-v2",
    }
    report_fingerprint = hashlib.sha256(json.dumps(fingerprint_data, sort_keys=True).encode("utf-8")).hexdigest()
    appendix.report_fingerprint = report_fingerprint

    stats = ReportStatsV2(
        sections_generated=8 + bool(attack_mappings) + bool(hunting_leads) + bool(analytical_gaps),
        sections_omitted=max(0, 11 - (8 + bool(attack_mappings) + bool(hunting_leads) + bool(analytical_gaps))),
        tables_generated=4 + bool(attack_mappings) + bool(indicators),
        diagrams_generated=1 if execution_chain else 0,
        iocs_rendered=len(indicators),
        functions_referenced=len(key_functions),
        evidence_references=sum(len(f.artifacts) + len(f.key_apis) for f in key_functions),
    )

    return ReportModelV2(
        fingerprint=report_fingerprint,
        source_analysis_fingerprint=repository.get_validated_analysis_fingerprint(sample_id),
        enrichment_fingerprint=rows["enrichment_fingerprint"],
        sample=profile,
        executive_assessment=executive_assessment,
        key_findings=key_findings,
        execution_chain=execution_chain,
        technical_analysis=technical_analysis,
        key_functions=key_functions,
        api_sequences=api_sequences,
        structures=structures,
        threat_intelligence=threat_intel,
        indicators=indicators,
        attack_mappings=attack_mappings,
        hunting_leads=hunting_leads,
        yara_rule=yara_rule,
        analytical_gaps=analytical_gaps,
        appendix=appendix,
        stats=stats,
        ai_narrative=workspace.analysis.joinpath("ai_narrative.md").read_text(encoding="utf-8") if workspace.analysis.joinpath("ai_narrative.md").exists() else None,
    )


def _load_report_rows(repository: AnalysisRepository, sample_id: str) -> dict[str, Any]:
    with connect_database(repository.database_path) as conn:
        sample = dict(conn.execute("SELECT * FROM samples WHERE sample_id = ?", (sample_id,)).fetchone() or {})
        metadata = dict(conn.execute("SELECT * FROM binary_metadata WHERE sample_id = ?", (sample_id,)).fetchone() or {})
        if metadata.get("metadata_json"):
            try:
                metadata.update(json.loads(metadata["metadata_json"]))
            except ValueError:
                pass
        functions = [
            _normalize_function_row(dict(row))
            for row in conn.execute(
                """
                SELECT function_address AS address, original_name, proposed_name, summary,
                       confidence, confidence_label, analysis_pass, finding_json
                FROM validated_function_findings
                WHERE sample_id = ?
                ORDER BY function_address
                """,
                (sample_id,),
            )
        ]
        artifacts = [
            dict(row)
            for row in conn.execute(
                "SELECT * FROM validated_artifacts WHERE sample_id = ? ORDER BY confidence DESC, address",
                (sample_id,),
            )
        ]
        flow_rows = [
            dict(row)
            for row in conn.execute(
                "SELECT * FROM execution_flows WHERE sample_id = ? ORDER BY confidence DESC, flow_id",
                (sample_id,),
            )
        ]
        structure_rows = [
            dict(row)
            for row in conn.execute(
                "SELECT * FROM recovered_structures WHERE sample_id = ? ORDER BY confidence DESC, name",
                (sample_id,),
            )
        ]
        contradiction_rows = [
            dict(row)
            for row in conn.execute(
                "SELECT * FROM contradictions WHERE sample_id = ? ORDER BY severity, contradiction_id",
                (sample_id,),
            )
        ]
        question_rows = [
            dict(row)
            for row in conn.execute(
                """
                SELECT * FROM mcp_questions
                WHERE sample_id = ? AND status IN ('UNRESOLVED', 'FAILED')
                ORDER BY priority, created_at, question_id
                """,
                (sample_id,),
            )
        ]
        configuration_items = [
            dict(row)
            for row in conn.execute(
                "SELECT * FROM configuration_items WHERE sample_id = ? ORDER BY confidence DESC, key",
                (sample_id,),
            )
        ]

    applied_names: dict[str, tuple[str, str]] = {}
    for row in repository.get_idb_change_rows(sample_id):
        if row["entity"] == "function" and row["operation"] == "rename":
            applied_names[row["address"]] = (row["applied"] or row["proposed"], row["status"])
    latest_enrichment = repository.get_latest_enrichment_run(sample_id)
    return {
        "sample": sample,
        "metadata": metadata,
        "functions": functions,
        "artifacts": artifacts,
        "flow_rows": flow_rows,
        "structure_rows": structure_rows,
        "contradiction_rows": contradiction_rows,
        "question_rows": question_rows,
        "configuration_items": configuration_items,
        "applied_names": applied_names,
        "import_usage": repository.get_import_usage_by_function(sample_id),
        "enrichment_fingerprint": latest_enrichment.get("enrichment_fingerprint") if latest_enrichment else None,
    }


def _normalize_function_row(row: dict[str, Any]) -> dict[str, Any]:
    payload: dict[str, Any] = {}
    if row.get("finding_json"):
        try:
            payload = json.loads(row["finding_json"])
        except ValueError:
            payload = {}
    for key in ("capabilities", "behavior", "evidence", "unknowns", "artifacts", "variables"):
        row[key] = payload.get(key) or []
    return row


def _load_function_pseudocode(workspace: WorkspacePaths, address: str) -> str:
    normalized = _address_token(address)
    
    # Try pseudocode (.c) first
    if workspace.pseudocode.exists():
        matches = sorted(workspace.pseudocode.glob(f"{normalized}_*.c"))
        if not matches:
            short = normalized.lstrip("0") or "0"
            matches = sorted(workspace.pseudocode.glob(f"*{short}_*.c"))
            
        if matches:
            try:
                return matches[0].read_text(encoding="utf-8", errors="replace")
            except OSError:
                pass
                
    # Fallback to disassembly (.asm)
    if workspace.disassembly.exists():
        matches = sorted(workspace.disassembly.glob(f"{normalized}_*.asm"))
        if not matches:
            short = normalized.lstrip("0") or "0"
            matches = sorted(workspace.disassembly.glob(f"*{short}_*.asm"))
            
        if matches:
            try:
                return matches[0].read_text(encoding="utf-8", errors="replace")
            except OSError:
                pass
                
    return ""


def _address_token(address: str) -> str:
    try:
        return f"{int(str(address), 16):016x}"
    except ValueError:
        return re.sub(r"[^0-9a-fA-F]", "", str(address)).lower().rjust(16, "0")


def _normalize_code_for_report(code: str) -> str:
    if not code:
        return ""
    replacements = {
        "â”Š": "  ",
        "â”‚": "|",
        "â”œ": "|",
        "â””": "`",
        "â”€": "-",
        "┊": "  ",
        "\u250a": "  ",
    }
    cleaned = code.replace("\r\n", "\n").replace("\r", "\n")
    for old, new in replacements.items():
        cleaned = cleaned.replace(old, new)
    cleaned = "\n".join(line.rstrip() for line in cleaned.splitlines())
    return cleaned.strip()


def _build_readable_code(
    original_code: str,
    original_name: str,
    display_name: str,
    variables: list[dict[str, Any]],
    applied_names: dict[str, tuple[str, str]],
) -> str:
    if not original_code:
        return ""
    readable = original_code
    name_pairs = [(original_name, display_name), (_ida_short_name(original_name), display_name)]
    if original_name == "_main":
        name_pairs.append(("main", display_name))
    for address, (applied, _status) in applied_names.items():
        if not applied:
            continue
        try:
            suffix = f"{int(address, 16):X}"
        except ValueError:
            continue
        name_pairs.append((f"sub_{suffix}", applied))
    for old, new in name_pairs:
        if old and new and old != new:
            readable = re.sub(rf"\b{re.escape(old)}\b", new, readable)
    for item in variables:
        old = str(item.get("original") or "").strip()
        new = str(item.get("proposed") or "").strip()
        if not old or not new or old == new:
            continue
        readable = re.sub(rf"\b{re.escape(old)}\b", new, readable)
    header = "// Readable reconstruction generated from validated REAI function analysis.\n"
    return header + readable


def _ida_short_name(name: str) -> str:
    if not name:
        return ""
    if name.startswith("sub_"):
        return name
    return name.split("@", 1)[0]


def _build_function_execution_flow(
    row: dict[str, Any],
    display_name: str,
    apis: list[str],
    artifacts: list[str],
    original_code: str,
) -> str:
    steps: list[str] = [f"Start {display_name}"]
    behaviors = [str(item).rstrip(".") for item in row.get("behavior", []) if str(item).strip()]
    for behavior in behaviors[:8]:
        steps.append(behavior)
    if not behaviors:
        summary = str(row.get("summary") or "").rstrip(".")
        if summary:
            steps.append(summary)

    steps.append("End function")

    lines: list[str] = []
    unique_steps = list(dict.fromkeys(steps))
    for index, step in enumerate(unique_steps):
        prefix = "|-- " if index < len(unique_steps) - 1 else "`-- "
        lines.append(prefix + step)
    return "\n".join(lines)


def _code_excerpt(code: str, max_lines: int) -> str:
    lines = code.splitlines()
    if len(lines) <= max_lines:
        return code
    omitted = len(lines) - max_lines
    return "\n".join(lines[:max_lines]) + f"\n/* ... {omitted} line(s) omitted for report display ... */"


def _build_sample_profile(sample: dict[str, Any], metadata: dict[str, Any], functions: list[dict], artifacts: list[dict]) -> SampleProfile:
    bitness = _as_int(metadata.get("bitness"), 32)
    arch = str(metadata.get("architecture") or metadata.get("processor") or ("x86" if bitness == 32 else "x64"))
    file_type = str(metadata.get("file_type") or metadata.get("format") or "Portable executable")
    image_base = str(metadata.get("image_base") or "0x400000")
    role = _sample_role(functions, artifacts)
    badges = ["WINDOWS", f"PE{bitness}"]
    if _has_network(functions, artifacts):
        badges.append("NETWORK")
    if any(_artifact_role(a) == "dropped_payload" for a in artifacts):
        badges.append("STAGER")
    if any(_artifact_role(a) == "persistence" for a in artifacts) or _text_has(functions, PERSISTENCE_TERMS):
        badges.append("PERSISTENCE")
    if _has_timing(functions):
        badges.append("TIMING")
    if len(badges) == 2:
        badges.append("STATIC_ANALYSIS")

    return SampleProfile(
        filename=str(sample.get("filename") or "unknown.bin"),
        sha256=str(sample.get("sha256") or ""),
        sha1=str(sample.get("sha1") or ""),
        md5=str(sample.get("md5") or ""),
        size=_as_int(sample.get("size"), 0),
        file_type=file_type,
        architecture=arch,
        bitness=bitness,
        image_base=image_base,
        analysis_timestamp=str(sample.get("created_at") or ""),
        classification_badges=badges,
        observed_role=role,
        primary_objective=_primary_objective(functions, artifacts),
        c2_retrieval_protocol=_network_protocol(functions, artifacts),
        persistence_status="Observed" if "PERSISTENCE" in badges else "Not observed in static analysis",
        evasion_status="Timing behavior observed" if _has_timing(functions) else "Not observed in static analysis",
        attribution_status="Not established",
        confidence_overall=_aggregate_confidence_label([float(f.get("confidence") or 0.0) for f in functions]),
    )


def _score_and_categorize_functions(
    functions: list[dict],
    applied_names: dict[str, tuple[str, str]],
    import_usage: dict[str, list[str]],
    artifacts: list[dict],
    flows: list[dict],
    max_functions: int,
    workspace: WorkspacePaths,
) -> tuple[list[KeyFunctionCard], list[dict[str, Any]]]:
    artifacts_by_function: dict[str, list[str]] = {}
    for artifact in artifacts:
        function_address = artifact.get("function_address")
        if function_address and _is_behavioral_artifact(artifact):
            artifacts_by_function.setdefault(function_address, []).append(_artifact_display_value(artifact))

    callers: dict[str, int] = {}
    callees: dict[str, int] = {}
    for flow in flows:
        callers[flow["target_function"]] = callers.get(flow["target_function"], 0) + 1
        callees[flow["source_function"]] = callees.get(flow["source_function"], 0) + 1

    cards: list[KeyFunctionCard] = []
    helpers: list[dict[str, Any]] = []
    for row in functions:
        address = str(row["address"])
        original = str(row.get("original_name") or f"sub_{address}")
        applied, idb_status = applied_names.get(address, (row.get("proposed_name") or original, "UNMODIFIED"))
        display_name = str(applied or original)
        apis = sorted(set(import_usage.get(address, [])))
        function_artifacts = artifacts_by_function.get(address, [])
        original_code = _load_function_pseudocode(workspace, address)
        original_code = _normalize_code_for_report(original_code)
        
        ai_readable_path = workspace.readable_code / f"{address}.c"
        if ai_readable_path.exists():
            readable_code = ai_readable_path.read_text(encoding="utf-8")
        else:
            readable_code = _build_readable_code(original_code, original, display_name, row.get("variables") or [], applied_names)
            
        # Prefer AI-generated execution flow if available
        ai_flow_path = workspace.analysis / "ai_execution_flow.txt"
        if ai_flow_path.exists():
            execution_flow = ai_flow_path.read_text(encoding="utf-8").strip()
        else:
            execution_flow = _build_function_execution_flow(row, display_name, apis, function_artifacts, original_code)
        text = _function_text(row, display_name, apis, function_artifacts)
        confidence = float(row.get("confidence") or 0.0)
        is_runtime = _is_runtime_helper(original, display_name, text)
        score = 0.12
        if _looks_like_entry(original, display_name):
            score += 0.35
        score += min(0.18, callers.get(address, 0) * 0.03)
        score += min(0.12, callees.get(address, 0) * 0.02)
        if _has_any(text, NETWORK_APIS) or any(_artifact_type(a) in {"url", "domain", "ip"} for a in artifacts if a.get("function_address") == address):
            score += 0.22
        if _has_any(text, PROCESS_APIS):
            score += 0.20
        if _has_any(text, FILE_APIS) or any(_artifact_type(a) == "file_path" for a in artifacts if a.get("function_address") == address):
            score += 0.14
        if _has_any(text, TIMING_APIS):
            score += 0.12
        if function_artifacts:
            score += min(0.16, len(function_artifacts) * 0.04)
        if is_runtime:
            score -= 0.55
        score = round(max(0.05, min(score, 0.99)), 2)
        importance = "CRITICAL" if score >= 0.70 else "HIGH" if score >= 0.40 else "SUPPORTING"

        card = KeyFunctionCard(
            address=address,
            original_name=original,
            applied_name=display_name if display_name != original else None,
            display_name=display_name,
            role=_derive_function_role(row, display_name, apis, function_artifacts),
            importance_score=score,
            importance_label=importance,
            confidence_label=_confidence_label(confidence),
            confidence_score=confidence,
            summary=str(row.get("summary") or "Function behavior was validated from available static evidence."),
            behaviors=_derive_behaviors(row, apis, function_artifacts),
            key_apis=apis[:8],
            artifacts=function_artifacts[:6],
            related_functions=[],
            pseudocode_snippet=_code_excerpt(original_code, max_lines=40) if original_code else None,
            original_decompiled_code=_code_excerpt(original_code, max_lines=220) if original_code else None,
            readable_code=_code_excerpt(readable_code, max_lines=220) if readable_code else None,
            execution_flow=execution_flow,
            idb_status=idb_status,
        )
        if is_runtime and score < 0.40:
            helpers.append({"address": address, "name": display_name, "summary": card.summary, "category": "Runtime or compiler helper"})
        else:
            cards.append(card)

    cards.sort(key=lambda item: (item.importance_score, item.confidence_score, item.address), reverse=True)
    selected: list[KeyFunctionCard] = []
    omitted: list[KeyFunctionCard] = []
    for card in cards:
        if _should_surface_key_function(card):
            selected.append(card)
        else:
            omitted.append(card)

    if not selected and cards:
        selected.append(cards[0])
        omitted = cards[1:]

    for card in omitted:
        helpers.append(
            {
                "address": card.address,
                "name": card.display_name,
                "summary": card.summary,
                "category": "Supporting or low-signal routine",
            }
        )

    return selected[:max_functions], helpers


def _build_indicators(artifacts: list[dict], defang: bool) -> list[IOCItem]:
    items: list[IOCItem] = []
    seen: set[tuple[str, str, str | None]] = set()
    for artifact in artifacts:
        value = _artifact_display_value(artifact)
        if not value:
            continue
        raw_type = _artifact_type(artifact)
        role = _artifact_role(artifact)
        key = (raw_type, value, artifact.get("function_address"))
        if key in seen:
            continue
        seen.add(key)
        ioc_type, role_desc = _indicator_type_and_role(raw_type, role, value)
        items.append(
            IOCItem(
                ioc_type=ioc_type,
                value=value,
                display_value=defang_indicator(value, raw_type) if defang else value,
                role=role_desc,
                source=_evidence_source(artifact),
                function=str(artifact.get("function_address") or "Static Data"),
                confidence_label=_confidence_label(float(artifact.get("confidence") or 0.0)),
            )
        )
    return items


def _build_semantic_execution_chain(
    functions: list[KeyFunctionCard],
    artifacts: list[dict],
    flows: list[dict],
) -> list[ExecutionChainStage]:
    stages: list[ExecutionChainStage] = []
    important = functions[:6]
    entry = next((fn for fn in important if _looks_like_entry(fn.original_name, fn.display_name)), important[0] if important else None)
    if entry:
        stages.append(
            ExecutionChainStage(
                step_number=1,
                stage_name="Initialization",
                description=f"Execution begins in `{entry.display_name}` and reaches malware-relevant logic identified by static analysis.",
                apis=entry.key_apis[:3],
                artifacts=[],
                functions=[_function_ref(entry)],
            )
        )
    if any(_has_any(_card_text(fn), TIMING_APIS) for fn in important):
        fn = _best_stage_function(important, role_terms=("timing", "delay"), text_terms=TIMING_APIS) or entry
        stages.append(_stage("Anti-Analysis / Timing", "Timing or delay behavior is present before or during the main workflow.", fn))
    if any(_has_any(_card_text(fn), NETWORK_APIS) for fn in important) or any(i.get("artifact_type") in {"url", "domain", "ip"} for i in artifacts):
        fn = next((fn for fn in important if _has_any(_card_text(fn), NETWORK_APIS)), entry)
        stages.append(_stage("Network Communication", "The sample references network material or networking APIs for external communication or retrieval.", fn, artifacts, {"url", "domain", "ip"}))
    if any(_artifact_role(a) == "dropped_payload" or _artifact_type(a) == "file_path" for a in artifacts):
        fn = _function_for_artifacts(important, artifacts, {"file_path"}) or entry
        stages.append(_stage("Payload Staging / File Artifact", "A file-system artifact is associated with staging, writing, reading, or later consumption.", fn, artifacts, {"file_path"}))
    if any(_has_any(_card_text(fn), PROCESS_APIS) for fn in important) or any(_artifact_type(a) == "command_line" for a in artifacts):
        fn = next((fn for fn in important if _has_any(_card_text(fn), PROCESS_APIS)), entry)
        stages.append(_stage("Execution / Command Launch", "Process or command execution evidence is present.", fn, artifacts, {"command_line"}))
    if any(_artifact_role(a) == "persistence" for a in artifacts) or any(_has_any(_card_text(fn), PERSISTENCE_TERMS) for fn in important):
        fn = _function_for_artifacts(important, artifacts, {"registry_path"}) or entry
        stages.append(_stage("Persistence", "Persistence-related artifact or behavior is supported by validated evidence.", fn, artifacts, {"registry_path"}))
    if any("del " in str(a.get("original_value", "")).lower() or "delete" in str(a.get("usage", "")).lower() for a in artifacts):
        fn = _function_for_artifacts(important, artifacts, {"command_line"}) or entry
        stages.append(_stage("Cleanup / Artifact Removal", "Command or API evidence indicates cleanup or file deletion behavior.", fn, artifacts, {"command_line"}))

    for index, stage in enumerate(stages, 1):
        stage.step_number = index
    return stages


def _build_technical_analysis(
    functions: list[KeyFunctionCard],
    indicators: list[IOCItem],
    configuration_items: list[dict],
    chain: list[ExecutionChainStage],
) -> list[TechnicalBehaviorSection]:
    sections: list[TechnicalBehaviorSection] = []
    for stage in chain:
        evidence = [{"source": "VALIDATED_ANALYSIS", "description": stage.description}]
        sections.append(
            TechnicalBehaviorSection(
                section_id=_slug(stage.stage_name),
                title=stage.stage_name,
                narrative=_narrative_for_stage(stage, indicators),
                functions=stage.functions,
                apis=stage.apis,
                artifacts=stage.artifacts,
                confidence_label="HIGH" if stage.apis or stage.artifacts or stage.functions else "MEDIUM",
                evidence=evidence,
            )
        )
    if configuration_items:
        reportable_items = [item for item in configuration_items if _is_reportable_value(str(item.get("value") or ""))]
        items = ", ".join(f"`{key}`" for key in dict.fromkeys(str(item["key"]) for item in reportable_items[:5]))
        sections.append(
            TechnicalBehaviorSection(
                section_id="configuration",
                title="Configuration",
                narrative=f"Validated configuration-like material was recovered: {items}. Values are presented only where backed by artifact evidence.",
                functions=[str(item.get("function_address")) for item in configuration_items if item.get("function_address")],
                artifacts=[_compact_evidence_value(str(item.get("value"))) for item in reportable_items if item.get("value")],
                confidence_label=_aggregate_confidence_label([float(item.get("confidence") or 0.0) for item in configuration_items]),
                evidence=[{"source": "VALIDATED_ANALYSIS", "description": "configuration_items rows"}],
            )
        )
    return sections


def _build_executive_assessment(
    profile: SampleProfile,
    functions: list[KeyFunctionCard],
    indicators: list[IOCItem],
    chain: list[ExecutionChainStage],
) -> str:
    facts: list[str] = []
    if any(item.ioc_type == IOCType.NETWORK_IOC for item in indicators) or any("Network" in stage.stage_name for stage in chain):
        facts.append("network communication or retrieval behavior")
    if any(item.ioc_type == IOCType.HOST_IOC for item in indicators):
        facts.append("host file artifacts")
    if any("Execution" in stage.stage_name for stage in chain):
        facts.append("process or command execution")
    if any("Timing" in stage.stage_name for stage in chain):
        facts.append("timing behavior that may affect sandbox execution")
    if any("Cleanup" in stage.stage_name for stage in chain):
        facts.append("artifact cleanup or deletion behavior")
    observed = ", ".join(facts) if facts else "the validated function behavior present in the current analysis"
    top = functions[0].display_name if functions else "the analyzed code"
    build_artifacts = [item.display_value for item in indicators if item.ioc_type == IOCType.BUILD_ARTIFACT]

    paragraphs = [
        f"**{profile.filename}** is a {profile.bitness}-bit Windows sample assessed as **{profile.observed_role}** based on validated static-analysis evidence.",
        f"The strongest available evidence centers on `{top}` and supports {observed}. Confidence reflects evidence quality, not analyst certainty about unobserved runtime behavior.",
    ]
    if build_artifacts:
        paragraphs.append(
            "Build or development artifacts were recovered and are useful for context, but they do not establish campaign, malware-family, or threat-actor attribution by themselves."
        )
    else:
        paragraphs.append("No evidence in the current report establishes campaign, malware-family, or threat-actor attribution.")
    return "\n\n".join(paragraphs)


def _build_key_findings(
    functions: list[KeyFunctionCard],
    indicators: list[IOCItem],
    chain: list[ExecutionChainStage],
) -> list[KeyFinding]:
    findings: list[KeyFinding] = []
    for stage in chain[:5]:
        findings.append(
            KeyFinding(
                number=f"{len(findings) + 1:02d}",
                title=stage.stage_name.upper(),
                summary=stage.description,
                confidence_label="HIGH" if stage.apis or stage.artifacts else "MEDIUM",
                evidence_summary=", ".join(stage.apis[:3] + stage.artifacts[:2] + stage.functions[:1]),
            )
        )
    for ioc_type, title in (
        (IOCType.NETWORK_IOC, "NETWORK ARTIFACTS"),
        (IOCType.HOST_IOC, "HOST ARTIFACTS"),
        (IOCType.BUILD_ARTIFACT, "BUILD CONTEXT"),
    ):
        matching = [item for item in indicators if item.ioc_type == ioc_type]
        if matching and len(findings) < 8:
            findings.append(
                KeyFinding(
                    number=f"{len(findings) + 1:02d}",
                    title=title,
                    summary=f"{len(matching)} {ioc_type.lower()} item(s) were classified with supporting function or static-data context.",
                    confidence_label=_aggregate_confidence_label([1.0 if item.confidence_label == "HIGH" else 0.7 for item in matching]),
                    evidence_summary=matching[0].display_value,
                )
            )
    if not findings and functions:
        fn = functions[0]
        findings.append(
            KeyFinding(
                number="01",
                title="PRIMARY FUNCTION",
                summary=f"`{fn.display_name}` is the highest-importance validated function.",
                confidence_label=fn.confidence_label,
                evidence_summary=fn.summary,
            )
        )
    return findings


def _build_api_sequences(chain: list[ExecutionChainStage]) -> list[APISequence]:
    apis = []
    for stage in chain:
        for api in stage.apis:
            if api not in apis:
                apis.append(api)
    if not apis:
        return []
    return [
        APISequence(
            name="Validated Behavior Sequence",
            description="Ordered from the semantic execution chain; this is not a raw call graph.",
            apis=apis,
            function=", ".join(dict.fromkeys(fn for stage in chain for fn in stage.functions)),
        )
    ]


def _build_structures(rows: list[dict]) -> list[RecoveredStructure]:
    return [
        RecoveredStructure(
            name=str(row.get("name") or "RecoveredStructure"),
            size=row.get("size"),
            fields=[],
            confidence_label=_confidence_label(float(row.get("confidence") or 0.0)),
        )
        for row in rows
    ]


def _build_threat_intel(indicators: list[IOCItem], profile: SampleProfile) -> ThreatIntelligenceModel:
    build_values = [item.display_value for item in indicators if item.ioc_type == IOCType.BUILD_ARTIFACT]
    if any("pmat" in item.lower() or "huskyhacks" in item.lower() for item in build_values):
        development_context = (
            "Build artifacts reference a HuskyHacks/PMAT-maldev development path. "
            "This is useful provenance context, not threat-actor attribution."
        )
    elif build_values:
        development_context = "Build artifacts are presented as development context only."
    else:
        development_context = "No build artifacts were recovered."
    return ThreatIntelligenceModel(
        network_infrastructure=[
            {"endpoint": item.display_value, "role": item.role, "observation_type": "OBSERVED", "confidence": item.confidence_label}
            for item in indicators
            if item.ioc_type == IOCType.NETWORK_IOC
        ],
        host_artifacts=[
            {"path": item.display_value, "role": item.role, "observation_type": "OBSERVED", "confidence": item.confidence_label}
            for item in indicators
            if item.ioc_type in {IOCType.HOST_IOC, IOCType.COMMAND_LINE_ARTIFACT}
        ],
        build_artifacts=[
            {"artifact": item.display_value, "role": item.role, "observation_type": "OBSERVED", "confidence": item.confidence_label}
            for item in indicators
            if item.ioc_type == IOCType.BUILD_ARTIFACT
        ],
        behavioral_characteristics=[
            {"trait": badge, "detail": f"{badge} behavior is supported by validated static evidence."}
            for badge in profile.classification_badges
            if badge not in {"WINDOWS", f"PE{profile.bitness}", "STATIC_ANALYSIS"}
        ],
        development_context=development_context,
        campaign_assessment="Not established from static analysis.",
        actor_assessment="Not established from static analysis.",
        attribution_status="NOT ESTABLISHED",
    )


def _build_attack_mappings(
    functions: list[KeyFunctionCard],
    indicators: list[IOCItem],
    chain: list[ExecutionChainStage],
) -> list[AttackMappingDetail]:
    mappings: list[AttackMappingDetail] = []
    function_refs = [_function_ref(fn) for fn in functions[:3]]
    if any("Network" in stage.stage_name for stage in chain):
        mappings.append(
            AttackMappingDetail(
                tactic="Command and Control",
                technique="Application Layer Protocol: Web Protocols",
                technique_id="T1071.001",
                observed_behavior="Uses web or networking APIs/artifacts for external communication.",
                evidence=_first_evidence(indicators, IOCType.NETWORK_IOC) or _api_evidence(functions, NETWORK_APIS),
                functions=function_refs,
                confidence_label="MEDIUM",
            )
        )
        if any(item.ioc_type == IOCType.HOST_IOC for item in indicators):
            mappings.append(
                AttackMappingDetail(
                    tactic="Command and Control",
                    technique="Ingress Tool Transfer",
                    technique_id="T1105",
                    observed_behavior="Network retrieval is associated with host staging artifacts.",
                    evidence=f"{_first_evidence(indicators, IOCType.NETWORK_IOC)}; {_first_evidence(indicators, IOCType.HOST_IOC)}",
                    functions=function_refs,
                    confidence_label="MEDIUM",
                )
            )
    if any("Execution" in stage.stage_name for stage in chain):
        mappings.append(
            AttackMappingDetail(
                tactic="Execution",
                technique="Native API",
                technique_id="T1106",
                observed_behavior="Invokes process or shell execution APIs.",
                evidence=_api_evidence(functions, PROCESS_APIS),
                functions=function_refs,
                confidence_label="MEDIUM",
            )
        )
    if any("Timing" in stage.stage_name for stage in chain):
        mappings.append(
            AttackMappingDetail(
                tactic="Defense Evasion",
                technique="Virtualization/Sandbox Evasion: Time Based Evasion",
                technique_id="T1497.003",
                observed_behavior="Contains delay or timing behavior.",
                evidence=_api_evidence(functions, TIMING_APIS),
                functions=function_refs,
                confidence_label="MEDIUM",
            )
        )
    if any("Cleanup" in stage.stage_name for stage in chain):
        mappings.append(
            AttackMappingDetail(
                tactic="Defense Evasion",
                technique="Indicator Removal: File Deletion",
                technique_id="T1070.004",
                observed_behavior="Contains file-deletion or cleanup command evidence.",
                evidence=_first_evidence(indicators, IOCType.COMMAND_LINE_ARTIFACT),
                functions=function_refs,
                confidence_label="MEDIUM",
            )
        )
    return [mapping for mapping in mappings if mapping.evidence]


def _build_hunting_leads(indicators: list[IOCItem], chain: list[ExecutionChainStage]) -> list[HuntingLead]:
    leads: list[HuntingLead] = []
    if any(item.ioc_type == IOCType.NETWORK_IOC for item in indicators):
        leads.append(HuntingLead(category="Network", lead_title="Observed Network Artifacts", artifact_or_behavior=_first_evidence(indicators, IOCType.NETWORK_IOC), detection_guidance="Hunt proxy, DNS, and EDR network telemetry for the observed endpoint and nearby variants."))
    if any(item.ioc_type == IOCType.HOST_IOC for item in indicators):
        leads.append(HuntingLead(category="Endpoint", lead_title="Observed Host Artifacts", artifact_or_behavior=_first_evidence(indicators, IOCType.HOST_IOC), detection_guidance="Hunt file-create, file-write, and process ancestry telemetry around this path or naming pattern."))
    if any("Execution" in stage.stage_name for stage in chain):
        leads.append(HuntingLead(category="Process", lead_title="Process Launch Behavior", artifact_or_behavior="Process or command execution APIs were observed.", detection_guidance="Review process creation telemetry for child processes launched by the analyzed binary."))
    return leads


def _build_yara_rule(profile: SampleProfile, indicators: list[IOCItem]) -> YaraRuleModel | None:
    strings = [item.value for item in indicators if item.ioc_type in {IOCType.NETWORK_IOC, IOCType.HOST_IOC, IOCType.BUILD_ARTIFACT, IOCType.COMMAND_LINE_ARTIFACT}]
    strings = [item for item in dict.fromkeys(strings) if len(item) >= 8][:8]
    if not strings:
        return None
    rule_name = re.sub(r"[^A-Za-z0-9_]", "_", f"REAI_{profile.filename}")[:80]
    string_lines = "\n".join(f'        $s{i} = "{_escape_yara(value)}" ascii wide nocase' for i, value in enumerate(strings, 1))
    rule_text = f"""rule {rule_name}
{{
    meta:
        description = "REAI evidence-backed strings for analyst review"
        sample_sha256 = "{profile.sha256}"
        status = "ANALYST REVIEW REQUIRED"

    strings:
{string_lines}

    condition:
        uint16(0) == 0x5A4D and any of them
}}"""
    return YaraRuleModel(rule_name=rule_name, rule_text=rule_text, rationale="Rule is based only on validated static artifacts and requires analyst tuning against cleanware and malware corpora.")


def _build_analytical_gaps(
    functions: list[KeyFunctionCard],
    indicators: list[IOCItem],
    contradictions: list[dict],
    question_rows: list[dict],
    chain: list[ExecutionChainStage],
) -> list[AnalyticalGap]:
    gaps: list[AnalyticalGap] = []
    for row in contradictions:
        gaps.append(
            AnalyticalGap(
                title=f"Unresolved contradiction: {row.get('severity', 'UNKNOWN')}",
                description=str(row.get("description") or "Contradictory evidence remains unresolved."),
                known_evidence=str(row.get("evidence_json") or ""),
                missing_evidence=str(row.get("resolution") or "Analyst review is required."),
                recommended_action="Review the conflicting function evidence in IDA.",
            )
        )
    for row in question_rows:
        if len(gaps) >= 8:
            break
        gaps.append(
            AnalyticalGap(
                title=f"Unresolved investigation question: {row.get('reason')}",
                description=str(row.get("question") or "Investigation question remains unresolved."),
                known_evidence=str(row.get("answer") or "No complete answer recorded."),
                missing_evidence="Additional IDA/MCP evidence is needed to resolve this question.",
                recommended_action=f"Review `{row.get('function_address')}` and rerun targeted investigation if needed.",
            )
        )
    for fn in functions:
        if fn.confidence_label == "LOW" and len(gaps) < 6:
            gaps.append(
                AnalyticalGap(
                    title=f"Low-confidence function: {fn.display_name}",
                    description=fn.summary,
                    known_evidence=", ".join(fn.key_apis + fn.artifacts) or "Limited static evidence.",
                    missing_evidence="Additional caller/callee, xref, or pseudocode context.",
                    recommended_action=f"Investigate `{fn.address}` with targeted IDA review.",
                )
            )
    if any(item.ioc_type == IOCType.NETWORK_IOC for item in indicators) and not any(item.ioc_type == IOCType.HOST_IOC for item in indicators):
        gaps.append(
            AnalyticalGap(
                title="Network Response Handling",
                description="Network artifacts are present, but no validated staged output path was recovered.",
                known_evidence=_first_evidence(indicators, IOCType.NETWORK_IOC),
                missing_evidence="Destination buffer, file path, or consumer of the network response.",
                recommended_action="Inspect xrefs and callers/callees around the network routine.",
            )
        )
    if not chain:
        gaps.append(
            AnalyticalGap(
                title="Behavioral Execution Flow",
                description="A semantic execution flow could not be constructed from the current validated evidence.",
                known_evidence="Validated function findings exist without enough behavior linkage.",
                missing_evidence="Call relationships, APIs, artifacts, or MCP evidence connecting functions to behavior.",
                recommended_action="Run targeted investigation for the highest-importance unresolved functions.",
            )
        )
    return gaps[:8]


def _build_appendix(
    runtime_helpers: list[dict[str, Any]],
    functions: list[dict],
    applied_names: dict[str, tuple[str, str]],
    source_fingerprint: str | None,
    enrichment_fingerprint: str | None,
) -> AppendixModel:
    full_functions = []
    for row in functions:
        address = str(row["address"])
        original = str(row.get("original_name") or f"sub_{address}")
        applied, status = applied_names.get(address, (row.get("proposed_name") or original, "UNMODIFIED"))
        full_functions.append(
            {
                "address": address,
                "original_name": original,
                "applied_name": applied,
                "summary": row.get("summary") or "",
                "confidence": float(row.get("confidence") or 0.0),
                "idb_status": status,
            }
        )
    return AppendixModel(
        runtime_helpers=runtime_helpers,
        full_functions=full_functions,
        source_analysis_fingerprint=source_fingerprint,
        enrichment_fingerprint=enrichment_fingerprint,
    )


def _stage(
    name: str,
    description: str,
    fn: KeyFunctionCard | None,
    artifacts: list[dict] | None = None,
    artifact_types: set[str] | None = None,
) -> ExecutionChainStage:
    stage_artifacts = []
    if artifacts and artifact_types:
        stage_artifacts = [
            _artifact_display_value(a)
            for a in artifacts
            if _artifact_type(a) in artifact_types and _is_behavioral_artifact(a)
        ][:4]
    return ExecutionChainStage(
        step_number=0,
        stage_name=name,
        description=description,
        apis=_stage_apis(name, fn),
        artifacts=stage_artifacts,
        functions=[_function_ref(fn)] if fn else [],
    )


def _stage_apis(stage_name: str, fn: KeyFunctionCard | None) -> list[str]:
    if fn is None:
        return []
    lowered = stage_name.lower()
    if "network" in lowered:
        terms = NETWORK_APIS
    elif "execution" in lowered or "command" in lowered:
        terms = PROCESS_APIS
    elif "payload" in lowered or "file" in lowered or "cleanup" in lowered:
        terms = FILE_APIS + PROCESS_APIS
    elif "timing" in lowered or "anti-analysis" in lowered:
        terms = TIMING_APIS
    else:
        terms = ()
    matching = [api for api in fn.key_apis if _has_any(api.lower(), terms)] if terms else []
    return (matching or fn.key_apis)[:4]


def _narrative_for_stage(stage: ExecutionChainStage, indicators: list[IOCItem]) -> str:
    support = []
    if stage.functions:
        support.append(f"implemented by {', '.join(f'`{fn}`' for fn in stage.functions)}")
    if stage.apis:
        support.append(f"with API evidence including {', '.join(f'`{api}`' for api in stage.apis[:4])}")
    if stage.artifacts:
        support.append(f"and artifact evidence {', '.join(f'`{artifact}`' for artifact in stage.artifacts[:3])}")
    suffix = "; ".join(support)
    return f"{stage.description} This section is evidence-backed {suffix}." if suffix else stage.description


def _derive_function_role(row: dict[str, Any], name: str, apis: list[str], artifacts: list[str]) -> str:
    text = _function_text(row, name, apis, artifacts)
    if _looks_like_entry(str(row.get("original_name") or ""), name):
        return "Primary orchestration or entry-point logic"
    if _has_any(text, NETWORK_APIS):
        return "Network communication or payload retrieval"
    if _has_any(text, PROCESS_APIS):
        return "Process, shell, or module execution"
    if _has_any(text, FILE_APIS):
        return "File-system interaction"
    if _has_any(text, TIMING_APIS):
        return "Timing or delay behavior"
    return "Supporting binary logic"


def _should_surface_key_function(card: KeyFunctionCard) -> bool:
    if card.importance_label in {"CRITICAL", "HIGH"}:
        return True
    if card.importance_score >= 0.30 and card.role != "Supporting binary logic":
        return True
    if any(term in _card_text(card) for term in ("download", "network", "payload", "process", "command", "file deletion", "timing", "sleep")):
        return card.importance_score >= 0.25 or card.role != "Supporting binary logic"
    return False


def _derive_behaviors(row: dict[str, Any], apis: list[str], artifacts: list[str]) -> list[str]:
    behaviors = [str(item) for item in row.get("behavior") or []]
    text = _function_text(row, "", apis, artifacts)
    if _has_any(text, NETWORK_APIS):
        behaviors.append("Uses network-related API or artifact evidence")
    if _has_any(text, PROCESS_APIS):
        behaviors.append("Launches or prepares process/module execution")
    if _has_any(text, FILE_APIS):
        behaviors.append("Interacts with the file system")
    if _has_any(text, TIMING_APIS):
        behaviors.append("Performs timing or delay operations")
    if artifacts:
        behaviors.append("References validated static artifacts")
    return list(dict.fromkeys(behaviors)) or ["Validated supporting logic"]


def _indicator_type_and_role(raw_type: str, role: str, value: str) -> tuple[str, str]:
    if raw_type in {"url", "domain", "ip"}:
        if "huskyhacks.dev" in value.lower() or role in {"context", "developer_context", "build_artifact"}:
            return IOCType.CONTEXTUAL_ARTIFACT, "Contextual developer or training reference"
        if "favicon" in value.lower() or "download" in role or "payload" in role:
            return IOCType.NETWORK_IOC, "Network retrieval target"
        return IOCType.NETWORK_IOC, "Embedded network endpoint"
    if raw_type in {"file_path", "registry_path"}:
        return IOCType.HOST_IOC, "Host artifact" if role != "dropped_payload" else "Staged or dropped payload path"
    if raw_type == "pdb_path" or value.lower().endswith(".pdb") or role == "build_artifact":
        return IOCType.BUILD_ARTIFACT, "Build or development artifact"
    if raw_type == "command_line" or "cmd.exe" in value.lower() or "powershell" in value.lower():
        return IOCType.COMMAND_LINE_ARTIFACT, "Command-line artifact"
    return IOCType.CONTEXTUAL_ARTIFACT, "Contextual static artifact"


def _sample_role(functions: list[dict], artifacts: list[dict]) -> str:
    text = " ".join(_function_text(fn, "", [], []) for fn in functions)
    has_network = _has_network(functions, artifacts)
    has_host_stage = any(_artifact_role(artifact) == "dropped_payload" for artifact in artifacts)
    has_exec = _has_any(text, PROCESS_APIS) or any(_artifact_type(artifact) == "command_line" for artifact in artifacts)
    if has_network and has_host_stage and has_exec:
        return "Downloader / Stager"
    if has_network and has_host_stage:
        return "Downloader"
    if has_network:
        return "Network-enabled Windows sample"
    if has_exec:
        return "Execution-capable Windows sample"
    return "Windows executable"


def _primary_objective(functions: list[dict], artifacts: list[dict]) -> str:
    role = _sample_role(functions, artifacts)
    if role == "Downloader / Stager":
        return "Retrieve, stage, and execute secondary content"
    if role == "Downloader":
        return "Retrieve external content"
    if role == "Network-enabled Windows sample":
        return "Communicate with external network resources"
    return "Not established from current static evidence"


def _network_protocol(functions: list[dict], artifacts: list[dict]) -> str:
    values = " ".join(str(a.get("original_value") or "").lower() for a in artifacts)
    text = " ".join(_function_text(fn, "", [], []) for fn in functions)
    if "https://" in values:
        return "HTTPS"
    if "http://" in values or "wininet" in text or "internet" in text or "urldownload" in text:
        return "HTTP / WinINet"
    if "winhttp" in text:
        return "HTTP / WinHTTP"
    if any(term in text for term in ("socket", "connect", "recv", "send")):
        return "Socket-based network communication"
    return "Not established"


def _has_network(functions: list[dict], artifacts: list[dict]) -> bool:
    return any(_artifact_type(a) in {"url", "domain", "ip"} for a in artifacts) or _text_has(functions, NETWORK_APIS)


def _has_timing(functions: list[dict]) -> bool:
    return _text_has(functions, TIMING_APIS)


def _text_has(functions: list[dict], terms: tuple[str, ...]) -> bool:
    return any(_has_any(_function_text(fn, "", [], []), terms) for fn in functions)


def _function_text(row: dict[str, Any], name: str, apis: list[str], artifacts: list[str]) -> str:
    return " ".join(
        [
            str(row.get("original_name") or ""),
            str(row.get("proposed_name") or ""),
            str(name),
            str(row.get("summary") or ""),
            " ".join(str(item) for item in row.get("capabilities") or []),
            " ".join(str(item) for item in row.get("behavior") or []),
            " ".join(str(item.get("description") or item.get("value") or "") for item in row.get("evidence") or [] if isinstance(item, dict)),
            " ".join(apis),
            " ".join(artifacts),
        ]
    ).lower()


def _card_text(card: KeyFunctionCard) -> str:
    return " ".join([card.display_name, card.summary, card.role, " ".join(card.behaviors), " ".join(card.key_apis), " ".join(card.artifacts)]).lower()


def _has_any(text: str, terms: tuple[str, ...]) -> bool:
    return any(term in text for term in terms)


def _looks_like_entry(original: str, display: str) -> bool:
    value = f"{original} {display}".lower()
    return "_main" in value or value == "main" or "winmain" in value or "entry" in value


def _is_runtime_helper(original: str, display: str, text: str) -> bool:
    name = f"{original} {display}".lower()
    return any(term in name for term in CRT_RUNTIME_NAMES) or any(stub == original.lower() or stub == display.lower() for stub in STUB_NAMES) or "compiler helper" in text


def _function_ref(function: KeyFunctionCard) -> str:
    return f"{function.display_name} ({function.address})"


def _function_for_artifacts(functions: list[KeyFunctionCard], artifacts: list[dict], artifact_types: set[str]) -> KeyFunctionCard | None:
    addresses = {str(a.get("function_address")) for a in artifacts if _artifact_type(a) in artifact_types and a.get("function_address")}
    return next((fn for fn in functions if fn.address in addresses), None)


def _best_stage_function(
    functions: list[KeyFunctionCard],
    *,
    role_terms: tuple[str, ...],
    text_terms: tuple[str, ...],
) -> KeyFunctionCard | None:
    for fn in functions:
        if any(term in fn.role.lower() for term in role_terms):
            return fn
    return next((fn for fn in functions if _has_any(_card_text(fn), text_terms)), None)


def _artifact_type(artifact: dict[str, Any]) -> str:
    return str(artifact.get("artifact_type") or "").lower()


def _artifact_role(artifact: dict[str, Any]) -> str:
    return str(artifact.get("role") or "").lower()


def _artifact_display_value(artifact: dict[str, Any]) -> str:
    value = str(artifact.get("original_value") or "")
    return _compact_evidence_value(value)


def _is_behavioral_artifact(artifact: dict[str, Any]) -> bool:
    value = _artifact_display_value(artifact)
    raw_type = _artifact_type(artifact)
    role = _artifact_role(artifact)
    ioc_type, _ = _indicator_type_and_role(raw_type, role, value)
    return ioc_type != IOCType.CONTEXTUAL_ARTIFACT


def _is_reportable_artifact(artifact: dict[str, Any]) -> bool:
    return _is_reportable_value(str(artifact.get("original_value") or ""), _artifact_type(artifact))


def _is_reportable_value(value: str, artifact_type: str = "") -> bool:
    if not value:
        return False
    lowered = value.lower()
    has_line_breaks = "\n" in value or "\\n" in value
    if has_line_breaks and any(marker in lowered for marker in ("int __cdecl", "void __", "{", "struct ", "byref")):
        return False
    if len(value) > 500 and artifact_type in {"command_line", "context", "unknown", ""}:
        return False
    return True


def _compact_evidence_value(value: str, limit: int = 220) -> str:
    clean = " ".join(value.replace("\r", " ").replace("\n", " ").split())
    if len(clean) <= limit:
        return clean
    return clean[: limit - 3].rstrip() + "..."


def _evidence_source(artifact: dict[str, Any]) -> str:
    try:
        evidence = json.loads(artifact.get("evidence_json") or "[]")
    except ValueError:
        evidence = []
    sources = [str(item.get("source")) for item in evidence if isinstance(item, dict) and item.get("source")]
    return ", ".join(dict.fromkeys(sources)) or "VALIDATED_ANALYSIS"


def _first_evidence(indicators: list[IOCItem], ioc_type: str) -> str:
    return next((item.display_value for item in indicators if item.ioc_type == ioc_type), "")


def _api_evidence(functions: list[KeyFunctionCard], terms: tuple[str, ...]) -> str:
    for fn in functions:
        matching = [api for api in fn.key_apis if _has_any(api.lower(), terms)]
        if matching:
            return f"{_function_ref(fn)}: {', '.join(matching[:4])}"
    return ""


def _aggregate_confidence_label(values: list[float]) -> str:
    if not values:
        return "LOW"
    avg = sum(values) / len(values)
    return _confidence_label(avg)


def _confidence_label(value: float) -> str:
    return "HIGH" if value >= 0.85 else "MEDIUM" if value >= 0.65 else "LOW"


def _as_int(value: Any, default: int) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _slug(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", value.lower()).strip("_") or "section"


def _escape_yara(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"')
