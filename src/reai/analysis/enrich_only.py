from __future__ import annotations

import hashlib
import json
from typing import Callable

from reai.analysis.findings import load_current_function_findings
from reai.analysis.schemas import SemanticAnalysisStats, ValidatedAnalysisModel
from reai.analysis.validation import validate_semantics
from reai.core.config import ValidationConfig
from reai.enrichment.policy import is_placeholder_name
from reai.storage.repository import AnalysisRepository


def build_enrich_only_candidates(
    repository: AnalysisRepository,
    sample_id: str,
    validation: ValidationConfig,
    *,
    progress_callback: Callable[[str], None] | None = None,
) -> SemanticAnalysisStats | None:
    _progress(progress_callback, "loading AI function findings")
    findings = load_current_function_findings(repository, sample_id)
    if not findings:
        _progress(progress_callback, "no AI findings available for IDB enrichment")
        return None

    _progress(progress_callback, f"validating {len(findings)} rename/comment candidate functions")
    validation_results, candidates, contradictions = validate_semantics(findings, [], validation)
    candidates = [
        candidate
        for candidate in candidates
        if (
            candidate.entity == "variable"
            or (candidate.entity == "function" and candidate.change_type == "comment")
            or (
                candidate.entity == "function"
                and candidate.change_type == "rename"
                and is_placeholder_name(candidate.original)
            )
        )
    ]

    stats = SemanticAnalysisStats(
        functions_validated=len(findings),
        rename_candidates=sum(1 for item in candidates if item.entity == "function" and item.change_type == "rename"),
        comment_candidates=sum(1 for item in candidates if item.entity == "function" and item.change_type == "comment"),
        variable_candidates=sum(1 for item in candidates if item.entity == "variable"),
        contradictions=len(contradictions),
        unresolved_contradictions=sum(1 for item in contradictions if item.status == "OPEN"),
    )
    model = ValidatedAnalysisModel(
        fingerprint=_fingerprint(findings, candidates),
        functions=findings,
        validation_results=validation_results,
        change_candidates=candidates,
        contradictions=contradictions,
        stats=stats,
    )
    _progress(progress_callback, f"persisting {len(candidates)} IDB rename/comment candidates")
    repository.persist_validated_analysis(sample_id, model)
    _progress(progress_callback, "IDB enrichment candidates ready")
    return stats


def _fingerprint(findings, candidates) -> str:
    payload = {
        "schema": "enrichidb-candidates-v1",
        "functions": [
            {
                "address": finding.address,
                "original_name": finding.original_name,
                "proposed_name": finding.proposed_name,
                "summary": finding.summary,
                "confidence": finding.confidence,
            }
            for finding in sorted(findings, key=lambda item: item.address)
        ],
        "candidates": [
            {
                "candidate_id": candidate.candidate_id,
                "entity": candidate.entity,
                "address": candidate.address,
                "change_type": candidate.change_type,
                "original": candidate.original,
                "proposed": candidate.proposed,
                "eligible_for_idb": candidate.eligible_for_idb,
            }
            for candidate in sorted(candidates, key=lambda item: item.candidate_id)
        ],
    }
    return hashlib.sha256(json.dumps(payload, sort_keys=True).encode("utf-8")).hexdigest()


def _progress(callback: Callable[[str], None] | None, message: str) -> None:
    if callback is not None:
        callback(message)
