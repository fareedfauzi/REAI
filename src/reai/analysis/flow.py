from __future__ import annotations

import hashlib

from reai.analysis.schemas import CommandHandler, ConfigurationItem, CurrentFunctionFinding, DataFlow, ExecutionFlow, Subsystem, ValidatedArtifact
from reai.storage.repository import AnalysisRepository


def build_execution_flows(
    repository: AnalysisRepository,
    sample_id: str,
    findings: list[CurrentFunctionFinding],
    subsystems: list[Subsystem],
) -> list[ExecutionFlow]:
    finding_by_address = {finding.address: finding for finding in findings}
    subsystem_by_function = {
        member.function_address: subsystem.subsystem_id
        for subsystem in subsystems
        for member in subsystem.functions
    }
    flows: list[ExecutionFlow] = []
    seen_execution_flow_ids: set[str] = set()
    for row in repository.list_function_calls(sample_id):
        caller = finding_by_address.get(row["caller"])
        callee = finding_by_address.get(row["callee"])
        if caller is None or callee is None:
            continue
        if caller.confidence < 0.55 or callee.confidence < 0.55:
            continue
        confidence = min(caller.confidence, callee.confidence, 0.96)
        relationship = "calls"
        if subsystem_by_function.get(caller.address) and subsystem_by_function.get(caller.address) == subsystem_by_function.get(callee.address):
            relationship = "same_subsystem_call"
        flow_id = _id(caller.address, callee.address, relationship)
        if flow_id in seen_execution_flow_ids:
            continue
        seen_execution_flow_ids.add(flow_id)
        flows.append(
            ExecutionFlow(
                flow_id=flow_id,
                source_function=caller.address,
                target_function=callee.address,
                relationship=relationship,
                confidence=confidence,
                evidence=[
                    {"source": "IDA_OBSERVED", "description": "Call graph edge supports execution relationship.", "address": row.get("source_address")},
                    {"source": "AI_DERIVED", "description": "Both endpoints have current function findings."},
                ],
            )
        )
    return flows


def build_data_flows(artifacts: list[ValidatedArtifact]) -> list[DataFlow]:
    flows: list[DataFlow] = []
    seen_data_flow_ids: set[str] = set()
    for artifact in artifacts:
        if not artifact.function_address:
            continue
        flow_id = _id("data", artifact.artifact_id, artifact.function_address)
        if flow_id in seen_data_flow_ids:
            continue
        seen_data_flow_ids.add(flow_id)
        flows.append(
            DataFlow(
                flow_id=flow_id,
                source_entity=f"artifact:{artifact.normalized_value}",
                target_entity=artifact.function_address,
                data_name=artifact.role,
                confidence=artifact.confidence,
                evidence=artifact.evidence,
            )
        )
    return flows



def build_command_handlers(
    repository: AnalysisRepository,
    sample_id: str,
    findings: list[CurrentFunctionFinding],
) -> list[CommandHandler]:
    finding_by_address = {finding.address: finding for finding in findings}
    handlers: list[CommandHandler] = []
    for dispatcher in findings:
        text = f"{dispatcher.proposed_name or ''} {dispatcher.summary or ''}".lower()
        if "dispatch" not in text and "command" not in text:
            continue
        callees = [row["callee"] for row in repository.list_function_calls(sample_id) if row["caller"] == dispatcher.address]
        for index, callee in enumerate(callees, start=1):
            handler = finding_by_address.get(callee)
            if handler is None or handler.confidence < 0.55:
                continue
            handlers.append(
                CommandHandler(
                    dispatcher=dispatcher.address,
                    command_id=f"0x{index:02x}",
                    handler=callee,
                    handler_name=handler.proposed_name,
                    confidence=min(dispatcher.confidence, handler.confidence, 0.9),
                    evidence=[
                        {"source": "IDA_OBSERVED", "description": "Dispatcher calls handler in call graph."},
                        {"source": "AI_DERIVED", "description": "Dispatcher and handler names indicate command routing."},
                    ],
                )
            )
    return handlers


def build_configuration_items(artifacts: list[ValidatedArtifact]) -> list[ConfigurationItem]:
    items_by_id: dict[str, ConfigurationItem] = {}
    for artifact in artifacts:
        if artifact.role == "c2":
            key = "c2_domain" if artifact.artifact_type == "domain" else f"c2_{artifact.artifact_type}"
        elif artifact.role == "persistence":
            key = "persistence_artifact"
        elif artifact.role == "dropped_payload":
            key = "staged_payload_path"
        elif artifact.role == "build_artifact":
            key = "compiler_pdb_path"
        elif artifact.role == "execution" and any(k in artifact.original_value.lower() for k in ("del", "ping")):
            key = "self_deletion_command"
        else:
            continue
            
        item_id = _id("config", key, artifact.normalized_value)
        if item_id not in items_by_id:
            items_by_id[item_id] = ConfigurationItem(
                item_id=item_id,
                key=key,
                value=artifact.original_value,
                value_type=artifact.artifact_type,
                function_address=artifact.function_address,
                confidence=artifact.confidence,
                evidence=artifact.evidence,
            )
    return list(items_by_id.values())


def _id(*parts) -> str:
    return "flow_" + hashlib.sha1("|".join(str(part) for part in parts).encode("utf-8")).hexdigest()[:16]
