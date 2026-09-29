from __future__ import annotations

import hashlib
from pathlib import Path

from pydantic import BaseModel


class FileHashes(BaseModel):
    md5: str
    sha1: str
    sha256: str
    size: int


def hash_file(path: Path, chunk_size: int = 1024 * 1024) -> FileHashes:
    md5 = hashlib.md5(usedforsecurity=False)
    sha1 = hashlib.sha1(usedforsecurity=False)
    sha256 = hashlib.sha256()
    size = 0

    with path.open("rb") as handle:
        while chunk := handle.read(chunk_size):
            size += len(chunk)
            md5.update(chunk)
            sha1.update(chunk)
            sha256.update(chunk)

    return FileHashes(
        md5=md5.hexdigest(),
        sha1=sha1.hexdigest(),
        sha256=sha256.hexdigest(),
        size=size,
    )
