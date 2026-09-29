from __future__ import annotations

from reai.ai.schemas import ConfidenceLabel, EvidenceSource, FunctionAnalysisResult
from reai.ai.validation import validate_proposed_name


def calibrate_confidence(result: FunctionAnalysisResult, *, decompilation_failed: bool = False) -> FunctionAnalysisResult:
    score = result.confidence
    observed_evidence = [
        item
        for item in result.evidence
        if item.source in {EvidenceSource.IDA_OBSERVED, EvidenceSource.MCP_OBSERVED}
    ]
    evidence_types = {item.type for item in observed_evidence}

    if len(observed_evidence) < 2:
        score = min(score, 0.69)
    if len(evidence_types) < 2:
        score = min(score, 0.79)
    if result.unknowns:
        score = min(score, 0.84)
    if decompilation_failed:
        score = min(score, 0.84)

    valid_name, reason = validate_proposed_name(result.proposed_name)
    if not valid_name:
        score = min(score, 0.69)
        if reason and reason not in result.unknowns:
            result.unknowns.append(reason)
        result.needs_investigation = True

    result.confidence = round(max(0.0, min(1.0, score)), 4)
    if result.confidence >= 0.85 and len(observed_evidence) >= 3 and len(evidence_types) >= 2:
        result.confidence_label = ConfidenceLabel.HIGH
    elif result.confidence >= 0.55:
        result.confidence_label = ConfidenceLabel.MEDIUM
    else:
        result.confidence_label = ConfidenceLabel.LOW

    if result.confidence_label == ConfidenceLabel.LOW or len(observed_evidence) < 2:
        result.needs_investigation = True
    return result
