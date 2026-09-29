from __future__ import annotations

import re
from pathlib import Path

from pydantic import BaseModel, ConfigDict


RESERVED_WINDOWS_NAMES = {
    "CON",
    "PRN",
    "AUX",
    "NUL",
    *(f"COM{i}" for i in range(1, 10)),
    *(f"LPT{i}" for i in range(1, 10)),
}

WORKSPACE_SUBDIRS = (
    "IDB Files",
    "REPORT",
    "Analysis Data",
    "Raw Data",
    "Extracted Codes",
    "REAI Logs",
)


class WorkspacePaths(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True)

    root: Path
    ida: Path
    report: Path
    analysis: Path
    raw: Path
    extracted_codes: Path
    pseudocode: Path
    disassembly: Path
    logs: Path
    database: Path
    sample_metadata: Path

    @classmethod
    def for_sample(cls, output_root: Path, filename: str, sha256: str) -> "WorkspacePaths":
        stem = sanitize_filename_stem(Path(filename).stem)
        root = output_root / f"{stem}_{sha256[:8]}"
        return cls.from_root(root)

    @classmethod
    def from_root(cls, root: Path) -> "WorkspacePaths":
        extracted_codes = root / "Extracted Codes"
        analysis = root / "Analysis Data"
        return cls(
            root=root,
            ida=root / "IDB Files",
            report=root / "REPORT",
            analysis=analysis,
            raw=root / "Raw Data",
            extracted_codes=extracted_codes,
            pseudocode=extracted_codes / "pseudocode",
            disassembly=extracted_codes / "disassembly",
            logs=root / "REAI Logs",
            database=analysis / "analysis.db",
            sample_metadata=analysis / "sample.json",
        )

    def create_directories(self) -> None:
        for subdir in WORKSPACE_SUBDIRS:
            (self.root / subdir).mkdir(parents=True, exist_ok=True)
        self.pseudocode.mkdir(parents=True, exist_ok=True)
        self.disassembly.mkdir(parents=True, exist_ok=True)


def sanitize_filename_stem(value: str, max_length: int = 80) -> str:
    name = Path(value).stem
    name = "".join("_" if ord(char) < 32 else char for char in name)
    name = re.sub(r'[<>:"/\\|?*\x00-\x1f]', "_", name)
    name = re.sub(r"\s+", "_", name)
    name = re.sub(r"_+", "_", name)
    name = name.strip(" ._")

    if not name or name in {".", ".."}:
        name = "sample"

    if name.upper() in RESERVED_WINDOWS_NAMES:
        name = f"{name}_sample"

    return name[:max_length].rstrip(" ._") or "sample"


def is_relative_to(path: Path, candidate_parent: Path) -> bool:
    try:
        path.resolve().relative_to(candidate_parent.resolve())
        return True
    except ValueError:
        return False


def find_workspace_by_sha256(output_root: Path, sha256: str) -> WorkspacePaths | None:
    if not output_root.exists() or not output_root.is_dir():
        return None

    for child in output_root.iterdir():
        if not child.is_dir() or child.is_symlink():
            continue
        metadata = child / "Analysis Data" / "sample.json"
        if not metadata.exists():
            metadata = child / "analysis" / "sample.json"
        if not metadata.exists():
            continue
        try:
            import json

            data = json.loads(metadata.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        if data.get("sha256") == sha256:
            return WorkspacePaths.from_root(child)
    return None
