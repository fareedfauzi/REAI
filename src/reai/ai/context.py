from __future__ import annotations

import json
from pathlib import Path

from reai.ai.schemas import FunctionContext
from reai.storage.repository import AnalysisRepository
from reai.utils.paths import WorkspacePaths


class FunctionContextBuilder:
    def __init__(self, repository: AnalysisRepository, workspace: WorkspacePaths, *, max_text_chars: int = 24000) -> None:
        self.repository = repository
        self.workspace = workspace
        self.max_text_chars = max_text_chars

    def build(self, sample_id: str, address: str) -> FunctionContext:
        records = self.repository.build_context_records(sample_id, address)
        function = dict(records["function"])
        function_record = json.loads(function["record_json"])
        context_truncated = False

        pseudocode = self._read_artifact(function_record.get("pseudocode_path"))
        disassembly = None
        if function_record.get("decompilation_status") != "success":
            disassembly = self._read_artifact(function_record.get("disassembly_path"))
        elif not pseudocode:
            disassembly = self._read_artifact(function_record.get("disassembly_path"))

        pseudocode, truncated_a = self._truncate(pseudocode)
        disassembly, truncated_b = self._truncate(disassembly)
        context_truncated = truncated_a or truncated_b

        return FunctionContext(
            function=_compact_function(function_record),
            pseudocode=pseudocode,
            disassembly=disassembly,
            imports=[_decode_record(row) for row in records["imports"]],
            strings=[_decode_record(row) for row in records["strings"]],
            globals=[_decode_record(row) for row in records["globals"]],
            callers=[_compact_related(row) for row in records["callers"]],
            callees=[_compact_related(row) for row in records["callees"]],
            child_findings=[_compact_child(row) for row in records["child_findings"]],
            types=[_decode_record(row) for row in records["types"]],
            segments=[_decode_record(row) for row in records["segments"]],
            context_truncated=context_truncated,
        )

    def _read_artifact(self, relative_path: str | None) -> str | None:
        if not relative_path:
            return None
        path = (self.workspace.root / relative_path).resolve()
        try:
            path.relative_to(self.workspace.root.resolve())
        except ValueError:
            return None
        if not path.exists() or not path.is_file():
            return None
        return path.read_text(encoding="utf-8", errors="replace")

    def _truncate(self, text: str | None) -> tuple[str | None, bool]:
        if text is None or len(text) <= self.max_text_chars:
            return text, False
        return text[: self.max_text_chars] + "\n[TRUNCATED]\n", True


def _decode_record(row: dict) -> dict:
    if "record_json" in row and row["record_json"]:
        try:
            return json.loads(row["record_json"])
        except ValueError:
            pass
    return {key: value for key, value in row.items() if key != "record_json"}


def _compact_function(record: dict) -> dict:
    keys = (
        "address",
        "end_address",
        "name",
        "size",
        "segment",
        "prototype",
        "is_thunk",
        "is_library",
        "is_external",
        "callers",
        "callees",
        "string_refs",
        "import_refs",
        "global_refs",
        "decompilation_status",
        "disassembly_status",
        "scc_id",
        "recursive",
    )
    return {key: record.get(key) for key in keys if key in record}


def _compact_related(row: dict) -> dict:
    record = _decode_record(row)
    return {"address": record.get("address") or row.get("address"), "name": record.get("name") or row.get("name")}


def _compact_child(row: dict) -> dict:
    data = {
        "address": row.get("address"),
        "proposed_name": row.get("proposed_name"),
        "summary": row.get("summary"),
        "confidence": row.get("confidence"),
        "confidence_label": row.get("confidence_label"),
        "needs_investigation": bool(row.get("needs_investigation")),
    }
    if row.get("result_json"):
        try:
            result = json.loads(row["result_json"])
            data["behavior"] = result.get("behavior", [])
            data["unknowns"] = result.get("unknowns", [])
        except ValueError:
            pass
    return data
