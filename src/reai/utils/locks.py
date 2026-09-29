from __future__ import annotations

import json
import os
from contextlib import AbstractContextManager
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from reai.core.exceptions import WorkspaceError


@dataclass
class WorkspaceLock(AbstractContextManager["WorkspaceLock"]):
    workspace_root: Path
    stale_seconds: int = 3600

    def __post_init__(self) -> None:
        self.path = self.workspace_root / ".reai.lock"
        self.acquired = False

    def __enter__(self) -> "WorkspaceLock":
        self.workspace_root.mkdir(parents=True, exist_ok=True)
        if self.path.exists() and not self._is_stale():
            owner = self._read_owner()
            raise WorkspaceError(
                "Workspace is locked by another REAI process.\n\n"
                f"Workspace:\n{self.workspace_root}\n\n"
                f"Lock:\n{owner}"
            )
        if self.path.exists():
            self.path.unlink(missing_ok=True)
        payload = {
            "pid": os.getpid(),
            "created_at": datetime.now(timezone.utc).isoformat(),
            "workspace": str(self.workspace_root),
        }
        try:
            handle = os.open(str(self.path), os.O_CREAT | os.O_EXCL | os.O_WRONLY)
        except FileExistsError as exc:
            raise WorkspaceError(f"Workspace lock already exists:\n{self.path}") from exc
        with os.fdopen(handle, "w", encoding="utf-8") as stream:
            json.dump(payload, stream, sort_keys=True)
            stream.write("\n")
        self.acquired = True
        return self

    def __exit__(self, exc_type, exc, traceback) -> None:
        if self.acquired:
            try:
                self.path.unlink(missing_ok=True)
            finally:
                self.acquired = False

    def _is_stale(self) -> bool:
        try:
            age = datetime.now(timezone.utc).timestamp() - self.path.stat().st_mtime
        except OSError:
            return True
        return age > self.stale_seconds

    def _read_owner(self) -> str:
        try:
            return self.path.read_text(encoding="utf-8").strip()
        except OSError:
            return "<unreadable>"
