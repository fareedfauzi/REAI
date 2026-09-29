from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from pydantic import BaseModel, ConfigDict

from reai.core.states import SampleState
from reai.utils.hashing import FileHashes
from reai.utils.paths import WorkspacePaths


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class Sample(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True)

    sample_id: str
    filename: str
    source_path: Path
    size: int
    md5: str
    sha1: str
    sha256: str
    workspace_path: Path
    status: SampleState = SampleState.DISCOVERED
    created_at: datetime
    updated_at: datetime

    @classmethod
    def from_file_hashes(
        cls,
        *,
        source_path: Path,
        hashes: FileHashes,
        workspace: WorkspacePaths,
        status: SampleState = SampleState.DISCOVERED,
    ) -> "Sample":
        now = utc_now()
        return cls(
            sample_id=hashes.sha256,
            filename=source_path.name,
            source_path=source_path.resolve(),
            size=hashes.size,
            md5=hashes.md5,
            sha1=hashes.sha1,
            sha256=hashes.sha256,
            workspace_path=workspace.root.resolve(),
            status=status,
            created_at=now,
            updated_at=now,
        )


class StateTransition(BaseModel):
    sample_id: str
    previous_state: SampleState | None
    new_state: SampleState
    timestamp: datetime
    message: str | None = None
