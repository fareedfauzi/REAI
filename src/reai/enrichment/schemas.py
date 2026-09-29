from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, Field


class ChangeStatus(StrEnum):
    PENDING = "PENDING"
    APPLIED = "APPLIED"
    VERIFIED = "VERIFIED"
    SKIPPED_NOT_ELIGIBLE = "SKIPPED_NOT_ELIGIBLE"
    SKIPPED_STATE_MISMATCH = "SKIPPED_STATE_MISMATCH"
    SKIPPED_CONFLICT = "SKIPPED_CONFLICT"
    FAILED = "FAILED"
    FAILED_VERIFICATION = "FAILED_VERIFICATION"
    ROLLED_BACK = "ROLLED_BACK"


class EnrichmentRunStatus(StrEnum):
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"


class EnrichmentChange(BaseModel):
    change_id: str
    candidate_id: str | None = None
    entity: str
    address: str | None = None
    operation: str
    original: str | None = None
    proposed: str
    applied: str | None = None
    confidence: float = Field(ge=0.0, le=1.0)
    eligible_for_idb: bool
    status: ChangeStatus = ChangeStatus.PENDING
    reason: str | None = None
    evidence: list[dict] = Field(default_factory=list)
    timestamp: str | None = None


class EnrichmentRun(BaseModel):
    run_id: str
    sample_id: str
    source_analysis_fingerprint: str | None = None
    enrichment_fingerprint: str
    mode: str
    ida_version: str | None = None
    reai_version: str
    status: EnrichmentRunStatus
    original_idb_path: str
    analyzed_idb_path: str
    temp_idb_path: str | None = None
    started_at: str
    completed_at: str | None = None
    error: str | None = None
    total_changes: int = 0
    applied_changes: int = 0
    verified_changes: int = 0
    skipped_changes: int = 0
    failed_changes: int = 0


class IDBVerification(BaseModel):
    verification_id: str
    change_id: str
    expected: str | None = None
    actual: str | None = None
    status: ChangeStatus
    details: str | None = None
    timestamp: str | None = None


class EnrichmentStats(BaseModel):
    total_candidates: int = 0
    eligible_candidates: int = 0
    function_renames: int = 0
    variable_renames: int = 0
    comments: int = 0
    structures: int = 0
    structure_fields: int = 0
    types: int = 0
    applied: int = 0
    verified: int = 0
    skipped: int = 0
    failed: int = 0
    verification_failures: int = 0

