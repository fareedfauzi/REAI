from __future__ import annotations

import hashlib
import re

from reai.analysis.schemas import Capability, CurrentFunctionFinding, Subsystem, SubsystemFunction
from reai.analysis.taxonomy import CAPABILITY_BY_SUBSYSTEM, SUBSYSTEM_RULES
from reai.storage.repository import AnalysisRepository


def discover_subsystems(
    repository: AnalysisRepository,
    sample_id: str,
    findings: list[CurrentFunctionFinding],
) -> tuple[list[Subsystem], list[Capability]]:
    import_usage = repository.get_import_usage_by_function(sample_id)
    grouped: dict[str, list[SubsystemFunction]] = {}
    evidence_by_subsystem: dict[str, list[dict]] = {}

    for finding in findings:
        text = _semantic_text(finding, import_usage.get(finding.address, []))
        for subsystem_id, (name, keywords) in SUBSYSTEM_RULES.items():
            matches = [keyword for keyword in keywords if keyword in text]
            if not matches:
                continue
            evidence = [
                {
                    "source": "AI_DERIVED" if _name_or_summary_contains(finding, matches) else "IDA_OBSERVED",
                    "description": f"Matched subsystem signal(s): {', '.join(sorted(set(matches)))}.",
                    "function": finding.address,
                }
            ]
            confidence = _membership_confidence(finding.confidence, len(set(matches)), import_usage.get(finding.address, []))
            grouped.setdefault(subsystem_id, []).append(
                SubsystemFunction(
                    function_address=finding.address,
                    role="entry" if _looks_like_entry(finding, text) else "member",
                    confidence=confidence,
                    evidence=evidence,
                )
            )
            evidence_by_subsystem.setdefault(subsystem_id, []).extend(evidence)

    subsystems: list[Subsystem] = []
    capabilities: list[Capability] = []
    for subsystem_id, functions in sorted(grouped.items()):
        name = SUBSYSTEM_RULES[subsystem_id][0]
        confidence = _aggregate_confidence([item.confidence for item in functions])
        entries = [item.function_address for item in functions if item.role == "entry"]
        if not entries and functions:
            entries = [max(functions, key=lambda item: item.confidence).function_address]
        subsystems.append(
            Subsystem(
                subsystem_id=subsystem_id,
                name=name,
                confidence=confidence,
                functions=functions,
                entry_functions=entries,
                evidence=evidence_by_subsystem.get(subsystem_id, []),
            )
        )
        capability_name = CAPABILITY_BY_SUBSYSTEM.get(subsystem_id)
        if capability_name:
            capabilities.append(
                Capability(
                    capability_id=_slug(capability_name),
                    name=capability_name,
                    confidence=min(confidence, max(item.confidence for item in functions)),
                    functions=[item.function_address for item in functions],
                    evidence=evidence_by_subsystem.get(subsystem_id, []),
                )
            )
    return subsystems, capabilities


def _semantic_text(finding: CurrentFunctionFinding, imports: list[str]) -> str:
    values = [
        finding.proposed_name or "",
        finding.summary or "",
        " ".join(finding.behavior),
        " ".join(finding.capabilities),
        " ".join(imports),
        " ".join(str(item.get("value", "")) for item in finding.evidence),
        " ".join(str(item.get("description", "")) for item in finding.evidence),
    ]
    return " ".join(values).lower()


def _name_or_summary_contains(finding: CurrentFunctionFinding, matches: list[str]) -> bool:
    text = f"{finding.proposed_name or ''} {finding.summary or ''}".lower()
    return any(match in text for match in matches)


def _membership_confidence(function_confidence: float, match_count: int, imports: list[str]) -> float:
    diversity = 0.08 if imports else 0.0
    return round(min(function_confidence + min(0.16, match_count * 0.04) + diversity, 0.95), 4)


def _aggregate_confidence(values: list[float]) -> float:
    if not values:
        return 0.0
    average = sum(values) / len(values)
    support = min(0.08, max(0, len(values) - 1) * 0.02)
    return round(min(max(values), average + support), 4)


def _looks_like_entry(finding: CurrentFunctionFinding, text: str) -> bool:
    name = finding.proposed_name or ""
    return bool(re.search(r"^(init|initialize|setup|start|dispatch|coordinate)_", name)) or "initialize" in text


def _slug(value: str) -> str:
    text = re.sub(r"[^a-z0-9]+", "_", value.lower()).strip("_")
    return text or "capability_" + hashlib.sha1(value.encode("utf-8")).hexdigest()[:8]

