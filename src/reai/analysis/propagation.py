from __future__ import annotations

import hashlib
import json

from reai.analysis.schemas import CurrentFunctionFinding, PropagationPassStats, Subsystem
from reai.storage.repository import AnalysisRepository


def run_context_propagation(
    repository: AnalysisRepository,
    sample_id: str,
    findings: list[CurrentFunctionFinding],
    subsystems: list[Subsystem],
    *,
    max_passes: int,
    minimum_context_change: int,
    minimum_confidence_delta: float,
) -> tuple[list[CurrentFunctionFinding], list[PropagationPassStats]]:
    findings_by_address = {finding.address: finding.model_copy(deep=True) for finding in findings}
    child_map = _children_by_parent(repository.list_function_calls(sample_id))
    subsystem_by_function = {
        member.function_address: subsystem
        for subsystem in subsystems
        for member in subsystem.functions
    }
    stats: list[PropagationPassStats] = []

    for pass_number in range(1, max_passes + 1):
        reconsidered = 0
        changed = 0
        confidence_changed = 0
        for parent, children in child_map.items():
            parent_finding = findings_by_address.get(parent)
            if parent_finding is None:
                continue
            child_findings = [findings_by_address[child] for child in children if child in findings_by_address]
            strong_children = [child for child in child_findings if child.confidence >= 0.75 and child.proposed_name]
            if len(strong_children) < minimum_context_change:
                continue
            reconsidered += 1
            old_name = parent_finding.proposed_name
            old_confidence = parent_finding.confidence
            refined = _refined_parent_name(parent_finding, strong_children, subsystem_by_function.get(parent))
            if refined and refined != parent_finding.proposed_name:
                parent_finding.proposed_name = refined
                parent_finding.summary = _append_once(
                    parent_finding.summary or "",
                    "Context propagation linked this function to stronger child findings.",
                )
                parent_finding.evidence.append(
                    {
                        "source": "PROPAGATED_CONTEXT",
                        "description": "Parent interpretation refined from high-confidence child context.",
                        "children": [child.address for child in strong_children],
                    }
                )
                changed += 1
            boost = min(0.12, 0.03 * len(strong_children))
            if boost >= minimum_confidence_delta and parent_finding.confidence < 0.85:
                parent_finding.confidence = round(min(0.9, parent_finding.confidence + boost), 4)
                parent_finding.confidence_label = "HIGH" if parent_finding.confidence >= 0.85 else "MEDIUM"
                confidence_changed += int(parent_finding.confidence != old_confidence)
            if parent_finding.proposed_name != old_name or parent_finding.confidence != old_confidence:
                parent_finding.analysis_pass = max(parent_finding.analysis_pass + 1, 3)

        fingerprint = _fingerprint(findings_by_address.values(), pass_number)
        converged = changed == 0 and confidence_changed == 0
        stats.append(
            PropagationPassStats(
                pass_number=pass_number,
                functions_reconsidered=reconsidered,
                interpretations_changed=changed,
                confidence_changed=confidence_changed,
                new_relationships=0,
                new_structures=0,
                new_validated_artifacts=0,
                converged=converged,
                fingerprint=fingerprint,
            )
        )
        if converged:
            break
    return list(findings_by_address.values()), stats


def _children_by_parent(calls: list[dict]) -> dict[str, list[str]]:
    result: dict[str, list[str]] = {}
    for row in calls:
        result.setdefault(row["caller"], []).append(row["callee"])
    return result


def _refined_parent_name(
    parent: CurrentFunctionFinding,
    children: list[CurrentFunctionFinding],
    subsystem: Subsystem | None,
) -> str | None:
    current = parent.proposed_name or ""
    child_names = " ".join(child.proposed_name or "" for child in children)
    if "config" in child_names and "c2" in child_names:
        if current in {"initialize_data", "process_data", "handle_data"} or not current:
            return "initialize_c2_configuration"
    if subsystem and subsystem.subsystem_id == "network_c2" and "config" in child_names and current.startswith("initialize_"):
        return "initialize_c2_configuration"
    return None


def _append_once(value: str, note: str) -> str:
    return value if note in value else f"{value} {note}".strip()


def _fingerprint(findings, pass_number: int) -> str:
    payload = [
        {"address": finding.address, "name": finding.proposed_name, "confidence": finding.confidence}
        for finding in sorted(findings, key=lambda item: item.address)
    ]
    raw = json.dumps({"pass": pass_number, "findings": payload}, sort_keys=True)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()

