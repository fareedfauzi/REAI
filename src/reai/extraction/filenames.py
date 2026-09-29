from __future__ import annotations

from reai.utils.paths import sanitize_filename_stem


def function_artifact_filename(address: int, name: str, extension: str) -> str:
    suffix = extension if extension.startswith(".") else f".{extension}"
    safe_name = sanitize_filename_stem(name, max_length=96)
    return f"{address:016x}_{safe_name}{suffix}"
