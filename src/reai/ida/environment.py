from __future__ import annotations

import os
import shutil
from pathlib import Path

from pydantic import BaseModel, ConfigDict

from reai.core.config import IDAConfig


IDA_EXECUTABLE_NAMES = (
    "ida64.exe",
    "ida.exe",
    "idat64.exe",
    "idat.exe",
    "ida64",
    "ida",
    "idat64",
    "idat",
)


class IDAEnvironment(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True)

    executable: Path | None
    configured_path: Path | None = None
    discovery_source: str = "not found"

    @property
    def available(self) -> bool:
        return self.executable is not None


def detect_ida_environment(config: IDAConfig) -> IDAEnvironment:
    if config.path is not None:
        executable = _resolve_configured_path(config.path)
        return IDAEnvironment(
            executable=executable,
            configured_path=config.path,
            discovery_source="config" if executable else "configured path not executable",
        )

    for env_name in ("REAI_IDA_PATH", "IDA_PATH"):
        value = os.environ.get(env_name)
        if value:
            path = Path(value)
            executable = _resolve_configured_path(path)
            return IDAEnvironment(
                executable=executable,
                configured_path=path,
                discovery_source=env_name if executable else f"{env_name} not executable",
            )

    for name in IDA_EXECUTABLE_NAMES:
        found = shutil.which(name)
        if found:
            return IDAEnvironment(executable=Path(found), discovery_source="PATH")

    return IDAEnvironment(executable=None)


def _resolve_configured_path(path: Path) -> Path | None:
    expanded = path.expanduser()
    if expanded.is_file():
        return expanded
    if expanded.is_dir():
        for name in IDA_EXECUTABLE_NAMES:
            candidate = expanded / name
            if candidate.is_file():
                return candidate
    return None
