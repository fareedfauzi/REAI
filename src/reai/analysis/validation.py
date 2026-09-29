from __future__ import annotations

import hashlib
from collections import defaultdict

from reai.ai.validation import validate_proposed_name
from reai.analysis.schemas import (
    ChangeCandidate,
    Contradiction,
    CurrentFunctionFinding,
    RecoveredStructure,
    ValidationResult,
)
from reai.core.config import ValidationConfig


def validate_semantics(
    findings: list[CurrentFunctionFinding],
    structures: list[RecoveredStructure],
    validation: ValidationConfig,
) -> tuple[list[ValidationResult], list[ChangeCandidate], list[Contradiction]]:
    results: list[ValidationResult] = []
    candidates: list[ChangeCandidate] = []
    contradictions: list[Contradiction] = []

    for finding in findings:
        valid_name, reason = validate_proposed_name(finding.proposed_name)
        rename_ok = valid_name and finding.confidence >= validation.rename_confidence_threshold
        comment_ok = finding.confidence >= validation.comment_confidence_threshold and bool(finding.summary)
        results.append(
            _validation_result(
                f"function:{finding.address}",
                "function_name",
                "ELIGIBLE" if rename_ok else "REJECTED",
                finding.confidence,
                "Name is evidence-supported." if rename_ok else (reason or "Confidence below rename threshold."),
                finding.evidence,
            )
        )
        if finding.proposed_name:
            candidates.append(
                ChangeCandidate(
                    candidate_id=_id("change", finding.address, "rename", finding.proposed_name),
                    entity="function",
                    address=finding.address,
                    change_type="rename",
                    original=finding.original_name,
                    proposed=finding.proposed_name,
                    confidence=finding.confidence,
                    eligible_for_idb=rename_ok,
                    evidence=finding.evidence,
                    reason="Function rename eligibility calculated by Phase 5 validation.",
                )
            )
        if comment_ok and finding.summary:
            candidates.append(
                ChangeCandidate(
                    candidate_id=_id("change", finding.address, "comment", finding.summary),
                    entity="function",
                    address=finding.address,
                    change_type="comment",
                    original=None,
                    proposed=finding.summary,
                    confidence=finding.confidence,
                    eligible_for_idb=True,
                    evidence=finding.evidence,
                    reason="Function comment candidate from validated summary.",
                )
            )
        for variable in finding.variables:
            confidence = float(variable.get("confidence") or 0.0)
            eligible = confidence >= validation.variable_confidence_threshold
            candidates.append(
                ChangeCandidate(
                    candidate_id=_id("change", finding.address, "variable", variable.get("original"), variable.get("proposed")),
                    entity="variable",
                    address=finding.address,
                    change_type="rename",
                    original=variable.get("original"),
                    proposed=variable.get("proposed") or "",
                    confidence=confidence,
                    eligible_for_idb=eligible,
                    evidence=[{"source": "AI_DERIVED", "description": variable.get("evidence", "")}],
                    reason="Variable proposal validated independently from function confidence.",
                )
            )

    contradictions.extend(_structure_contradictions(structures))
    for structure in structures:
        for field in structure.fields:
            candidates.append(
                ChangeCandidate(
                    candidate_id=_id("change", structure.structure_id, field.offset, field.name),
                    entity="structure_field",
                    address=field.offset,
                    change_type="type",
                    original=None,
                    proposed=f"{field.field_type} {field.name}",
                    confidence=field.confidence,
                    eligible_for_idb=field.confidence >= validation.type_confidence_threshold and field.eligible_for_idb,
                    evidence=field.evidence,
                    reason="Recovered structure field eligibility calculated by Phase 5 validation.",
                )
            )
    return results, candidates, contradictions


def _validation_result(entity: str, validation_type: str, status: str, confidence: float, reason: str, evidence: list[dict]) -> ValidationResult:
    return ValidationResult(
        result_id=_id("validation", entity, validation_type),
        entity=entity,
        validation_type=validation_type,
        status=status,
        confidence=confidence,
        reason=reason,
        evidence=evidence,
    )


def _structure_contradictions(structures: list[RecoveredStructure]) -> list[Contradiction]:
    contradictions: list[Contradiction] = []
    for structure in structures:
        by_offset: dict[str, set[str]] = defaultdict(set)
        evidence: dict[str, list[dict]] = defaultdict(list)
        for field in structure.fields:
            by_offset[field.offset].add(field.field_type)
            evidence[field.offset].extend(field.evidence)
        for offset, types in by_offset.items():
            if len(types) > 1:
                contradictions.append(
                    Contradiction(
                        contradiction_id=_id("conflict", structure.structure_id, offset),
                        severity="MEDIUM",
                        entities=[f"structure:{structure.name}{offset}"],
                        description=f"Field {offset} has incompatible proposed types: {', '.join(sorted(types))}.",
                        evidence=evidence[offset],
                        status="OPEN",
                    )
                )
    return contradictions


def _id(*parts) -> str:
    raw = "|".join(str(part) for part in parts)
    return hashlib.sha1(raw.encode("utf-8")).hexdigest()[:20]

