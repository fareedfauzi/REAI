from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, Field

from reai.core.sample import utc_now
from reai.core.states import JobStatus


class AnalysisJob(BaseModel):
    job_id: str
    sample_id: str
    status: JobStatus
    created_at: datetime
    started_at: datetime | None = None
    updated_at: datetime
    completed_at: datetime | None = None
    error: str | None = None
    run_config: dict[str, Any] = Field(default_factory=dict)

    @classmethod
    def create(cls, sample_id: str, *, run_config: dict[str, Any] | None = None) -> "AnalysisJob":
        now = utc_now()
        return cls(
            job_id=str(uuid4()),
            sample_id=sample_id,
            status=JobStatus.CREATED,
            created_at=now,
            updated_at=now,
            run_config=run_config or {},
        )
