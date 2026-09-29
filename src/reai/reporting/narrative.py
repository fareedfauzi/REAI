from __future__ import annotations

import hashlib
import json

from reai.core.config import ReportConfig
from reai.reporting.schemas import ReportModel, ReportSection, ReportSectionStatus, ReportSubsystem


BEHAVIOR_SECTION_IDS = {
    "configuration": "Configuration",
    "network_c2": "Network / C2",
    "persistence": "Persistence",
    "execution": "Execution",
    "injection": "Injection",
    "discovery": "Discovery",
    "collection": "Collection",
    "credential_access": "Credential Access",
    "defense_evasion": "Defense Evasion",
    "crypto_encoding": "Crypto / Encoding",
    "command_dispatch": "Command Dispatch",
}


def build_sections(model: ReportModel, config: ReportConfig) -> list[ReportSection]:
    sections: list[ReportSection] = [
        _section("executive_summary", "Executive Summary", _executive_summary(model), _facts(model, "executive")),
        _section("sample_information", "Sample Information", "", model.sample.model_dump(mode="json")),
        _section("technical_overview", "Technical Overview", _technical_overview(model), _facts(model, "overview")),
    ]
    if model.execution_flows:
        sections.append(_section("execution_flow", "Execution Flow", _execution_flow_summary(model), _facts(model, "execution_flow")))
    if model.configuration:
        sections.append(_section("configuration", "Configuration", _configuration_summary(model), _facts(model, "configuration")))
    for subsystem in model.subsystems:
        if subsystem.subsystem_id in BEHAVIOR_SECTION_IDS and subsystem.functions:
            title = BEHAVIOR_SECTION_IDS[subsystem.subsystem_id]
            sections.append(_section(f"behavior_{subsystem.subsystem_id}", title, _subsystem_summary(subsystem), subsystem.model_dump(mode="json")))
    if model.commands:
        sections.append(_section("command_dispatch", "Command Dispatch", _command_summary(model), _facts(model, "commands")))
    if model.iocs:
        sections.append(_section("iocs", "Indicators of Compromise", "", _facts(model, "iocs")))
    if model.attack_mappings:
        sections.append(_section("mitre_attack", "MITRE ATT&CK Mapping", "", _facts(model, "attack")))
    sections.append(_section("important_functions", "Important Functions", _important_functions_summary(model, config), _facts(model, "functions")))
    if model.structures:
        sections.append(_section("recovered_structures", "Recovered Types / Structures", "", _facts(model, "structures")))
    sections.append(_section("evidence_confidence", "Evidence and Confidence", _confidence_summary(), {"labels": ["HIGH", "MEDIUM", "LOW"]}))
    if model.contradictions or model.limitations:
        sections.append(_section("limitations", "Unresolved Behavior / Limitations", _limitations_summary(model), _facts(model, "limitations")))
    sections.append(_section("appendix", "Appendix", _appendix_summary(model), _facts(model, "appendix")))
    model.sections = sections
    model.stats.sections_generated = len([section for section in sections if section.status == ReportSectionStatus.GENERATED])
    model.stats.sections_omitted = max(0, 22 - model.stats.sections_generated)
    model.stats.tables_generated = _table_count(model)
    model.stats.diagrams_generated = 1 if model.execution_flows else 0
    model.stats.functions_referenced = len({function.address for function in model.functions[: config.max_important_functions]})
    model.stats.evidence_references = sum(len(function.evidence) for function in model.functions)
    return sections


def _executive_summary(model: ReportModel) -> str:
    capabilities = ", ".join(model.capabilities[:6]) or "validated behavior"
    top_iocs = ", ".join(item.display_value for item in model.iocs[:3])
    c2 = next((subsystem for subsystem in model.subsystems if subsystem.subsystem_id == "network_c2"), None)
    persistence = next((subsystem for subsystem in model.subsystems if subsystem.subsystem_id == "persistence"), None)
    paragraphs = [
        f"The sample was analyzed statically and REAI validated {len(model.functions)} function-level finding(s). The strongest supported capabilities are {capabilities}.",
    ]
    if c2:
        paragraphs.append(f"Network/C2 behavior is supported by the {c2.name} subsystem, which contains {len(c2.functions)} validated function(s).")
    if persistence:
        paragraphs.append(f"Persistence behavior is supported by the {persistence.name} subsystem, with evidence from {len(persistence.functions)} function(s).")
    if top_iocs:
        paragraphs.append(f"Validated reportable indicators include {top_iocs}. Canonical indicator storage remains undefanged in the analysis database.")
    if model.limitations:
        paragraphs.append(f"Key limitation: {model.limitations[0]}")
    return "\n\n".join(paragraphs)


def _technical_overview(model: ReportModel) -> str:
    names = [subsystem.name for subsystem in model.subsystems[:8]]
    if not names:
        return "Validated analysis did not identify higher-level subsystems beyond individual function findings."
    return "Validated subsystems provide the high-level structure of the sample: " + " -> ".join(names) + "."


def _execution_flow_summary(model: ReportModel) -> str:
    return f"Phase 5 validated {len(model.execution_flows)} execution relationship(s) from call graph and function-finding evidence."


def _configuration_summary(model: ReportModel) -> str:
    sources = sorted({item.function.display_name for item in model.configuration if item.function})
    if sources:
        return "Recovered configuration items are tied to " + ", ".join(sources[:5]) + "."
    return "Recovered configuration items are supported by validated artifact evidence."


def _subsystem_summary(subsystem: ReportSubsystem) -> str:
    functions = ", ".join(function.display_name for function in subsystem.functions[:5])
    return f"{subsystem.name} behavior is supported by {len(subsystem.functions)} function(s): {functions}."


def _command_summary(model: ReportModel) -> str:
    return f"Phase 5 recovered {len(model.commands)} command-handler mapping(s)."


def _important_functions_summary(model: ReportModel, config: ReportConfig) -> str:
    count = min(len(model.functions), config.max_important_functions)
    return f"The table lists the top {count} analyst-relevant function(s), ranked by validated confidence."


def _confidence_summary() -> str:
    return (
        "Confidence labels are analysis confidence scores, not calibrated probabilities. "
        "HIGH indicates strong consistent evidence, MEDIUM indicates useful but incomplete support, and LOW indicates insufficient support for semantic IDB modification."
    )


def _limitations_summary(model: ReportModel) -> str:
    if model.contradictions:
        return f"The report preserves {len(model.contradictions)} contradiction(s) from validation instead of hiding unresolved behavior."
    return "Relevant limitations are listed so the analyst can prioritize follow-up review."


def _appendix_summary(model: ReportModel) -> str:
    return (
        "The accompanying ida/analyzed.i64 contains the successfully applied Phase 6 IDB changes. "
        f"Report schema: {model.schema_version}. Narrative strategy: deterministic fallback."
    )


def _section(section_id: str, title: str, narrative: str, facts: dict) -> ReportSection:
    fingerprint = hashlib.sha256(json.dumps(facts, sort_keys=True).encode("utf-8")).hexdigest()
    return ReportSection(section_id=section_id, title=title, narrative=narrative, source_facts=facts, fingerprint=fingerprint)


def _facts(model: ReportModel, name: str) -> dict:
    if name == "executive":
        return {"capabilities": model.capabilities, "iocs": [ioc.model_dump(mode="json") for ioc in model.iocs], "limitations": model.limitations}
    if name == "overview":
        return {"subsystems": [subsystem.model_dump(mode="json") for subsystem in model.subsystems]}
    if name == "execution_flow":
        return {"flows": [flow.model_dump(mode="json") for flow in model.execution_flows]}
    if name == "configuration":
        return {"configuration": [item.model_dump(mode="json") for item in model.configuration]}
    if name == "commands":
        return {"commands": [item.model_dump(mode="json") for item in model.commands]}
    if name == "iocs":
        return {"iocs": [ioc.model_dump(mode="json") for ioc in model.iocs]}
    if name == "attack":
        return {"attack": [mapping.model_dump(mode="json") for mapping in model.attack_mappings]}
    if name == "functions":
        return {"functions": [function.model_dump(mode="json") for function in model.functions]}
    if name == "structures":
        return {"structures": [item.model_dump(mode="json") for item in model.structures]}
    if name == "limitations":
        return {"contradictions": [item.model_dump(mode="json") for item in model.contradictions], "limitations": model.limitations}
    return {"fingerprint": model.fingerprint, "schema": model.schema_version}


def _table_count(model: ReportModel) -> int:
    count = 2
    count += 1 if model.configuration else 0
    count += 1 if model.commands else 0
    count += 1 if model.iocs else 0
    count += 1 if model.attack_mappings else 0
    count += 1 if model.structures else 0
    return count
