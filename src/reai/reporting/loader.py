from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Any

from reai import __version__
from reai.core.config import ReportConfig
from reai.reporting.schemas import (
    AttackMapping,
    ReportArtifact,
    ReportCommand,
    ReportConfigItem,
    ReportContradiction,
    ReportDataFlow,
    ReportFlow,
    ReportFunction,
    ReportModel,
    ReportSampleInfo,
    ReportStats,
    ReportStructure,
    ReportStructureField,
    ReportSubsystem,
)
from reai.storage.database import connect_database
from reai.storage.repository import AnalysisRepository
from reai.utils.paths import WorkspacePaths


ATTACK_RULES = {
    "network_c2": ("Application Layer Protocol", "T1071"),
    "persistence": ("Boot or Logon Autostart Execution", "T1547"),
    "execution": ("Command and Scripting Interpreter", "T1059"),
    "injection": ("Process Injection", "T1055"),
    "discovery": ("System Information Discovery", "T1082"),
    "collection": ("Data from Local System", "T1005"),
    "credential_access": ("Credentials from Password Stores", "T1555"),
    "defense_evasion": ("Virtualization/Sandbox Evasion", "T1497"),
    "crypto_encoding": ("Deobfuscate/Decode Files or Information", "T1140"),
    "command_dispatch": ("Command and Control", "T1105"),
}


def build_report_model(
    config: ReportConfig,
    repository: AnalysisRepository,
    workspace: WorkspacePaths,
    sample_id: str,
) -> ReportModel:
    rows = _load_rows(repository, sample_id)
    if rows["sample"] is None:
        raise KeyError(f"Sample not found: {sample_id}")
    if not rows["functions"]:
        raise ValueError("Validated Phase 5 function findings are required for report generation.")

    applied_names, enrichment_fingerprint = _applied_idb_names(repository, sample_id)
    import_usage = repository.get_import_usage_by_function(sample_id)
    functions = _functions(rows["functions"], applied_names, import_usage)
    function_by_address = {function.address: function for function in functions}
    artifacts = _artifacts(rows["artifacts"], config.defang_iocs)
    iocs = [artifact for artifact in artifacts if artifact.is_ioc]
    subsystems = _subsystems(rows["subsystems"], rows["subsystem_functions"], function_by_address)
    capabilities = [row["name"] for row in rows["capabilities"]]
    execution_flows = _execution_flows(rows["execution_flows"], function_by_address)
    data_flows = _data_flows(rows["data_flows"], function_by_address)
    configuration = _configuration(rows["configuration_items"], function_by_address, config.defang_iocs)
    commands = _commands(rows["command_handlers"], function_by_address)
    structures = _structures(rows["structures"], rows["structure_fields"])
    contradictions = _contradictions(rows["contradictions"])
    attack_mappings = _attack_mappings(subsystems)
    limitations = _limitations(functions, contradictions, rows["extraction_failures"], rows["mcp_investigations"])
    source_fingerprint = repository.get_validated_analysis_fingerprint(sample_id)
    sample = _sample_info(rows["sample"], rows["metadata"], rows["jobs"])

    fingerprint_payload = {
        "schema": config.schema_version,
        "prompt": config.prompt_version,
        "defang_iocs": config.defang_iocs,
        "sample": sample.model_dump(mode="json"),
        "source_analysis_fingerprint": source_fingerprint,
        "enrichment_fingerprint": enrichment_fingerprint,
        "functions": [function.model_dump(mode="json") for function in functions],
        "subsystems": [subsystem.model_dump(mode="json") for subsystem in subsystems],
        "capabilities": capabilities,
        "execution_flows": [flow.model_dump(mode="json") for flow in execution_flows],
        "configuration": [item.model_dump(mode="json") for item in configuration],
        "commands": [item.model_dump(mode="json") for item in commands],
        "iocs": [ioc.model_dump(mode="json") for ioc in iocs],
        "structures": [item.model_dump(mode="json") for item in structures],
        "contradictions": [item.model_dump(mode="json") for item in contradictions],
        "limitations": limitations,
    }
    fingerprint = hashlib.sha256(json.dumps(fingerprint_payload, sort_keys=True).encode("utf-8")).hexdigest()
    return ReportModel(
        schema_version=config.schema_version,
        prompt_version=config.prompt_version,
        fingerprint=fingerprint,
        sample=sample,
        source_analysis_fingerprint=source_fingerprint,
        enrichment_fingerprint=enrichment_fingerprint,
        functions=functions,
        subsystems=subsystems,
        capabilities=capabilities,
        execution_flows=execution_flows,
        data_flows=data_flows,
        configuration=configuration,
        commands=commands,
        iocs=iocs,
        artifacts=artifacts,
        attack_mappings=attack_mappings,
        structures=structures,
        contradictions=contradictions,
        limitations=limitations,
        stats=ReportStats(
            iocs_rendered=len(iocs),
            functions_referenced=len({function.address for function in functions}),
            evidence_references=sum(len(function.evidence) for function in functions),
        ),
    )


def _load_rows(repository: AnalysisRepository, sample_id: str) -> dict[str, Any]:
    with connect_database(repository.database_path) as connection:
        one = lambda query: connection.execute(query, (sample_id,)).fetchone()
        many = lambda query: [dict(row) for row in connection.execute(query, (sample_id,)).fetchall()]
        return {
            "sample": dict(one("SELECT * FROM samples WHERE sample_id = ?")),
            "metadata": _dict_or_none(one("SELECT * FROM binary_metadata WHERE sample_id = ?")),
            "jobs": many("SELECT * FROM jobs WHERE sample_id = ? ORDER BY created_at"),
            "functions": many("SELECT * FROM validated_function_findings WHERE sample_id = ? ORDER BY confidence DESC, function_address"),
            "subsystems": many("SELECT * FROM subsystems WHERE sample_id = ? ORDER BY confidence DESC, name"),
            "subsystem_functions": many("SELECT * FROM subsystem_functions WHERE sample_id = ? ORDER BY subsystem_id, confidence DESC"),
            "capabilities": many("SELECT * FROM capabilities WHERE sample_id = ? ORDER BY confidence DESC, name"),
            "execution_flows": many("SELECT * FROM execution_flows WHERE sample_id = ? ORDER BY confidence DESC, source_function, target_function"),
            "data_flows": many("SELECT * FROM data_flows WHERE sample_id = ? ORDER BY confidence DESC, source_entity, target_entity"),
            "artifacts": many("SELECT * FROM validated_artifacts WHERE sample_id = ? ORDER BY is_ioc DESC, artifact_type, normalized_value"),
            "configuration_items": many("SELECT * FROM configuration_items WHERE sample_id = ? ORDER BY confidence DESC, key"),
            "command_handlers": many("SELECT * FROM command_handlers WHERE sample_id = ? ORDER BY dispatcher, command_id"),
            "structures": many("SELECT * FROM recovered_structures WHERE sample_id = ? ORDER BY confidence DESC, name"),
            "structure_fields": many("SELECT * FROM recovered_structure_fields WHERE sample_id = ? ORDER BY structure_id, offset"),
            "contradictions": many("SELECT * FROM contradictions WHERE sample_id = ? ORDER BY severity, contradiction_id"),
            "extraction_failures": many("SELECT * FROM extraction_failures WHERE sample_id = ? ORDER BY extractor, address"),
            "mcp_investigations": many("SELECT * FROM mcp_investigations WHERE sample_id = ? ORDER BY priority_score DESC"),
        }


def _sample_info(sample: dict, metadata: dict | None, jobs: list[dict]) -> ReportSampleInfo:
    meta = _json_dict(metadata.get("metadata_json") if metadata else None)
    latest_job = jobs[-1] if jobs else {}
    return ReportSampleInfo(
        sample_id=sample["sample_id"],
        filename=sample["filename"],
        source_path=sample["source_path"],
        size=int(sample["size"]),
        md5=sample["md5"],
        sha1=sample["sha1"],
        sha256=sample["sha256"],
        architecture=(metadata or {}).get("architecture") or meta.get("architecture"),
        bitness=(metadata or {}).get("bitness") or meta.get("bitness"),
        processor=(metadata or {}).get("processor") or meta.get("processor"),
        file_type=meta.get("file_type"),
        image_base=(metadata or {}).get("image_base") or meta.get("image_base"),
        ida_version=(metadata or {}).get("ida_version") or meta.get("ida_version"),
        reai_version=__version__,
        analysis_timestamp=latest_job.get("completed_at") or sample["updated_at"] or datetime.now(timezone.utc).isoformat(),
    )


def _functions(rows: list[dict], applied_names: dict[str, dict], import_usage: dict[str, list[str]]) -> list[ReportFunction]:
    functions: list[ReportFunction] = []
    for row in rows:
        finding = _json_dict(row["finding_json"])
        applied = applied_names.get(row["function_address"])
        semantic = row["proposed_name"]
        idb_name = applied.get("applied") if applied else None
        original = row["original_name"]
        if idb_name:
            display = idb_name
            idb_status = applied.get("status")
        elif semantic and semantic != original:
            display = f"{semantic} ({original})"
            idb_status = applied.get("status") if applied else None
        else:
            display = original
            idb_status = applied.get("status") if applied else None
        functions.append(
            ReportFunction(
                address=row["function_address"],
                original_name=original,
                semantic_name=semantic,
                idb_name=idb_name,
                display_name=display,
                summary=row["summary"],
                confidence=float(row["confidence"]),
                confidence_label=row["confidence_label"],
                capabilities=list(finding.get("capabilities") or []),
                behavior=list(finding.get("behavior") or []),
                evidence=list(finding.get("evidence") or []),
                unknowns=list(finding.get("unknowns") or []),
                imports=sorted(set(import_usage.get(row["function_address"], []))),
                idb_status=idb_status,
            )
        )
    return functions


def _artifacts(rows: list[dict], defang: bool) -> list[ReportArtifact]:
    artifacts = []
    for row in rows:
        value = row["normalized_value"] or row["original_value"]
        artifacts.append(
            ReportArtifact(
                artifact_id=row["artifact_id"],
                original_value=row["original_value"],
                normalized_value=row["normalized_value"],
                display_value=defang_indicator(value, row["artifact_type"]) if defang and row["is_ioc"] else value,
                artifact_type=row["artifact_type"],
                role=row["role"],
                function_address=row["function_address"],
                address=row["address"],
                usage=row["usage"],
                confidence=float(row["confidence"]),
                is_ioc=bool(row["is_ioc"]),
                evidence=_json_list(row["evidence_json"]),
            )
        )
    return artifacts


def _subsystems(rows: list[dict], member_rows: list[dict], functions: dict[str, ReportFunction]) -> list[ReportSubsystem]:
    members: dict[str, list[ReportFunction]] = {}
    for row in member_rows:
        function = functions.get(row["function_address"])
        if function:
            members.setdefault(row["subsystem_id"], []).append(function)
    return [
        ReportSubsystem(
            subsystem_id=row["subsystem_id"],
            name=row["name"],
            confidence=float(row["confidence"]),
            functions=members.get(row["subsystem_id"], []),
            evidence=_json_list(row["evidence_json"]),
        )
        for row in rows
    ]


def _execution_flows(rows: list[dict], functions: dict[str, ReportFunction]) -> list[ReportFlow]:
    flows = []
    for row in rows:
        source = functions.get(row["source_function"])
        target = functions.get(row["target_function"])
        if source and target:
            flows.append(
                ReportFlow(
                    flow_id=row["flow_id"],
                    source=source,
                    target=target,
                    relationship=row["relationship"],
                    confidence=float(row["confidence"]),
                    evidence=_json_list(row["evidence_json"]),
                )
            )
    return flows


def _data_flows(rows: list[dict], functions: dict[str, ReportFunction]) -> list[ReportDataFlow]:
    flows = []
    for row in rows:
        flows.append(
            ReportDataFlow(
                flow_id=row["flow_id"],
                source_entity=row["source_entity"],
                target=functions.get(row["target_entity"]),
                data_name=row["data_name"],
                confidence=float(row["confidence"]),
                evidence=_json_list(row["evidence_json"]),
            )
        )
    return flows


def _configuration(rows: list[dict], functions: dict[str, ReportFunction], defang: bool) -> list[ReportConfigItem]:
    items = []
    for row in rows:
        value = row["value"]
        items.append(
            ReportConfigItem(
                key=row["key"],
                value=value,
                display_value=defang_indicator(value, row["value_type"]) if value and defang else value,
                value_type=row["value_type"],
                function=functions.get(row["function_address"]),
                confidence=float(row["confidence"]),
                evidence=_json_list(row["evidence_json"]),
            )
        )
    return items


def _commands(rows: list[dict], functions: dict[str, ReportFunction]) -> list[ReportCommand]:
    return [
        ReportCommand(
            command_id=row["command_id"],
            dispatcher=functions.get(row["dispatcher"]),
            handler=functions.get(row["handler"]),
            handler_name=row["handler_name"],
            confidence=float(row["confidence"]),
            evidence=_json_list(row["evidence_json"]),
        )
        for row in rows
    ]


def _structures(rows: list[dict], field_rows: list[dict]) -> list[ReportStructure]:
    fields: dict[str, list[ReportStructureField]] = {}
    for row in field_rows:
        fields.setdefault(row["structure_id"], []).append(
            ReportStructureField(
                offset=row["offset"],
                name=row["name"],
                field_type=row["field_type"],
                confidence=float(row["confidence"]),
            )
        )
    return [
        ReportStructure(
            structure_id=row["structure_id"],
            name=row["name"],
            confidence=float(row["confidence"]),
            size=row["size"],
            fields=fields.get(row["structure_id"], []),
            eligible_for_idb=bool(row["eligible_for_idb"]),
        )
        for row in rows
    ]


def _contradictions(rows: list[dict]) -> list[ReportContradiction]:
    return [
        ReportContradiction(
            contradiction_id=row["contradiction_id"],
            severity=row["severity"],
            entities=_json_list_or_strings(row["entities_json"]),
            description=row["description"],
            status=row["status"],
            resolution=row["resolution"],
        )
        for row in rows
    ]


def _attack_mappings(subsystems: list[ReportSubsystem]) -> list[AttackMapping]:
    mappings = []
    for subsystem in subsystems:
        rule_key = subsystem.subsystem_id
        if rule_key not in ATTACK_RULES:
            continue
        technique, technique_id = ATTACK_RULES[rule_key]
        mappings.append(
            AttackMapping(
                technique=technique,
                technique_id=technique_id,
                evidence=f"Validated {subsystem.name} subsystem with {len(subsystem.functions)} function(s).",
                functions=subsystem.functions[:5],
                confidence=subsystem.confidence,
            )
        )
    return mappings


def _limitations(
    functions: list[ReportFunction],
    contradictions: list[ReportContradiction],
    failures: list[dict],
    investigations: list[dict],
) -> list[str]:
    limitations = ["Static analysis report; runtime-only values may be unresolved."]
    unknowns = sum(len(function.unknowns) for function in functions)
    if unknowns:
        limitations.append(f"{unknowns} function-level unknown(s) remain in validated findings.")
    open_contradictions = [item for item in contradictions if item.status == "OPEN"]
    if open_contradictions:
        limitations.append(f"{len(open_contradictions)} unresolved contradiction(s) remain.")
    fatal_failures = [row for row in failures if row.get("fatal")]
    if fatal_failures:
        limitations.append(f"{len(fatal_failures)} fatal extraction failure(s) affected source evidence.")
    failed_mcp = [row for row in investigations if row.get("status") == "FAILED"]
    if failed_mcp:
        limitations.append(f"{len(failed_mcp)} MCP investigation(s) failed or remained unresolved.")
    return limitations


def _applied_idb_names(repository: AnalysisRepository, sample_id: str) -> tuple[dict[str, dict], str | None]:
    latest = repository.get_latest_enrichment_run(sample_id)
    run_id = latest["run_id"] if latest else None
    changes = repository.get_idb_change_rows(sample_id, run_id) if run_id else []
    names = {
        row["address"]: row
        for row in changes
        if row["entity"] == "function" and row["operation"] == "rename" and row["status"] == "VERIFIED" and row["applied"]
    }
    return names, latest.get("enrichment_fingerprint") if latest else None


def defang_indicator(value: str, artifact_type: str | None = None) -> str:
    if not value:
        return value
    result = value.replace("https://", "hxxps://").replace("http://", "hxxp://")
    if artifact_type in {"domain", "url", "email"} or "." in result:
        result = result.replace(".", "[.]")
    return result


def _json_dict(value: str | None) -> dict:
    if not value:
        return {}
    try:
        data = json.loads(value)
    except ValueError:
        return {}
    return data if isinstance(data, dict) else {}


def _json_list(value: str | None) -> list[dict]:
    if not value:
        return []
    try:
        data = json.loads(value)
    except ValueError:
        return []
    return data if isinstance(data, list) else []


def _json_list_or_strings(value: str | None) -> list[str]:
    if not value:
        return []
    try:
        data = json.loads(value)
    except ValueError:
        return []
    return [str(item) for item in data] if isinstance(data, list) else []


def _dict_or_none(row) -> dict | None:
    return dict(row) if row else None
