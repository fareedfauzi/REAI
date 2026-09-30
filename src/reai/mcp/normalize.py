from __future__ import annotations

import json

from reai.mcp.schemas import MCPCapability, MCPEvidence, MCPToolResult


def normalize_mcp_result(result: MCPToolResult) -> list[MCPEvidence]:
    if not result.success:
        return []
    evidence: list[MCPEvidence] = []
    observations = result.observations or []
    for observation in observations[:25]:
        evidence.append(_observation_to_evidence(result.capability, result.target, observation))
    if not evidence and result.raw is not None:
        value = _compact_raw(result.raw)
        evidence.append(
            MCPEvidence(
                evidence_type=result.capability.value,
                value=value,
                description=f"{result.capability.value} returned read-only data for {result.target}.",
                address=result.target,
                capability=result.capability,
                target=result.target,
                record={"raw_preview": value},
            )
        )
    return evidence


def _observation_to_evidence(capability: MCPCapability, target: str, observation: dict) -> MCPEvidence:
    obs_type = str(observation.get("type") or capability.value)
    address = observation.get("address") or observation.get("source_address") or observation.get("destination_address") or target
    if capability == MCPCapability.CALLERS:
        value = str(observation.get("source_function") or observation.get("caller") or observation)
        description = f"{value} calls or references {target}."
    elif capability == MCPCapability.CALLEES:
        value = str(observation.get("callee") or observation)
        description = f"{target} calls or references {value}."
    elif capability in {MCPCapability.XREFS, MCPCapability.XREF_TO, MCPCapability.XREF_FROM}:
        value = str(observation.get("source_address") or observation.get("destination_address") or observation)
        description = f"XREF evidence links {value} with {target}."
    elif capability == MCPCapability.DISASSEMBLE:
        value = str(observation.get("text") or observation)
        description = f"Disassembly around {target} exposes low-level behavior."
    elif capability == MCPCapability.DECOMPILE:
        value = str(observation.get("text") or observation)
        description = f"Targeted decompilation for {target} returned pseudocode."
    elif capability == MCPCapability.CFG:
        value = f"blocks={observation.get('blocks')} edges={observation.get('edges')}"
        description = f"CFG metadata for {target} clarifies branch structure."
    elif capability in {MCPCapability.MEMORY, MCPCapability.DATA}:
        value = str(observation.get("preview") or observation)
        description = f"Static data at {target} was read through MCP."
    elif capability == MCPCapability.TYPES:
        value = str(observation.get("declaration") or observation)
        description = f"Type information for {target} was retrieved."
    elif capability in {
        MCPCapability.METADATA,
        MCPCapability.FUNCTIONS,
        MCPCapability.STRINGS,
        MCPCapability.IMPORTS,
        MCPCapability.EXPORTS,
        MCPCapability.GLOBALS,
        MCPCapability.STRUCTURES,
        MCPCapability.SEGMENTS,
        MCPCapability.BASIC_BLOCKS,
    }:
        value = str(observation.get("text") or observation.get("value") or observation)
        description = f"{capability.value} context was retrieved through MCP for {target}."
    else:
        value = str(observation.get("value") or observation.get("name") or observation)
        description = f"{capability.value} returned read-only evidence for {target}."

    return MCPEvidence(
        evidence_type=obs_type,
        value=value[:1000],
        description=description[:1000],
        address=str(address) if address else None,
        capability=capability,
        target=target,
        record=observation,
    )


def _compact_raw(raw) -> str:
    try:
        text = json.dumps(raw, sort_keys=True)
    except TypeError:
        text = str(raw)
    return text[:1000]
