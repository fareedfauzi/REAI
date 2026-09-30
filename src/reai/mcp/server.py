from __future__ import annotations

import argparse
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from reai import __version__


TOOLS: tuple[dict[str, Any], ...] = (
    {"name": "reai_database", "description": "Open or report the current REAI analysis workspace."},
    {"name": "reai_metadata", "description": "Return sample and IDA extraction metadata."},
    {"name": "reai_functions", "description": "List extracted functions."},
    {"name": "reai_function", "description": "Return one extracted function record."},
    {"name": "reai_decompile", "description": "Return extracted pseudocode for a function."},
    {"name": "reai_disassemble", "description": "Return extracted disassembly for a function."},
    {"name": "reai_xrefs", "description": "Return cross-references related to an address."},
    {"name": "reai_xref_to", "description": "Return cross-references to an address."},
    {"name": "reai_xref_from", "description": "Return cross-references from an address."},
    {"name": "reai_callers", "description": "Return callers of a function."},
    {"name": "reai_callees", "description": "Return callees of a function."},
    {"name": "reai_cfg", "description": "Return lightweight call graph context for a function."},
    {"name": "reai_basic_blocks", "description": "Return basic block metadata when available."},
    {"name": "reai_strings", "description": "List extracted strings."},
    {"name": "reai_imports", "description": "List extracted imports."},
    {"name": "reai_exports", "description": "List extracted exports."},
    {"name": "reai_globals", "description": "List extracted globals."},
    {"name": "reai_memory", "description": "Return extracted static data near an address."},
    {"name": "reai_data", "description": "Return extracted static data near an address."},
    {"name": "reai_types", "description": "List extracted type records."},
    {"name": "reai_structures", "description": "List extracted structure records."},
    {"name": "reai_segments", "description": "List extracted segments."},
    {"name": "reai_search", "description": "Search extracted function, string, import, and global records."},
)


class ArtifactQueryEngine:
    def __init__(self, workspace: Path, sample_path: Path | None = None) -> None:
        self.workspace = workspace
        self.sample_path = sample_path
        self.analysis_dir = workspace / "Analysis Data"
        self.raw_dir = workspace / "Raw Data"
        self.extracted_dir = workspace / "Extracted Codes"
        self.extraction = self._load_json(self.analysis_dir / "ida-extraction.json", {})
        self.sample = self._load_json(self.analysis_dir / "sample.json", {})
        self.functions = self._load_records("functions", self.analysis_dir / "functions.json", "functions")
        self.strings = self._load_records("strings", self.raw_dir / "strings.json", "strings")
        self.imports = self._load_records("imports", self.raw_dir / "imports.json", "imports")
        self.exports = self._load_records("exports", self.raw_dir / "exports.json", "exports")
        self.globals = self._load_records("globals", self.raw_dir / "globals.json", "globals")
        self.segments = self._load_records("segments", self.raw_dir / "segments.json", "segments")
        self.types = self._load_records("types", self.raw_dir / "types.json", "types")
        self.xrefs = list(self.extraction.get("xrefs") or [])
        self.function_by_address = {_address_key(item.get("address")): item for item in self.functions if item.get("address") is not None}
        self.function_by_name = {str(item.get("name", "")).lower(): item for item in self.functions if item.get("name")}

    def tool(self, name: str, args: dict[str, Any]) -> dict[str, Any]:
        lowered = name.lower()
        if "database" in lowered:
            return self.database(args)
        if "metadata" in lowered or lowered.endswith("info"):
            return self.metadata()
        if "list_functions" in lowered or lowered.endswith("functions"):
            return self.list_functions(args)
        if "decompile" in lowered or "pseudocode" in lowered:
            return self.code_text(args, "pseudocode_path", "pseudocode")
        if "disassemble" in lowered or "disasm" in lowered:
            return self.code_text(args, "disassembly_path", "disassembly")
        if "xref_to" in lowered or "xrefs_to" in lowered or "references_to" in lowered:
            return self.xrefs_for(args, direction="to")
        if "xref_from" in lowered or "xrefs_from" in lowered or "references_from" in lowered:
            return self.xrefs_for(args, direction="from")
        if "xrefs" in lowered or "references" in lowered:
            return self.xrefs_for(args, direction="both")
        if "callers" in lowered or "called_by" in lowered:
            return self.call_edges(args, "callers")
        if "callees" in lowered or "calls" in lowered:
            return self.call_edges(args, "callees")
        if "cfg" in lowered or "control_flow" in lowered:
            return self.cfg(args)
        if "basic_blocks" in lowered or "blocks" in lowered:
            return self.basic_blocks(args)
        if "strings" in lowered:
            return _content(self._page(self.strings, args, "value"))
        if "imports" in lowered:
            return _content(self._page(self.imports, args, "name"))
        if "exports" in lowered:
            return _content(self._page(self.exports, args, "name"))
        if "globals" in lowered or "global_variables" in lowered:
            return _content(self._page(self.globals, args, "name"))
        if "memory" in lowered or "data" in lowered or "bytes" in lowered:
            return self.data(args)
        if "types" in lowered or lowered.endswith("type"):
            return _content(self._page(self.types, args, "name"))
        if "structures" in lowered or "structs" in lowered:
            return _content([item for item in self.types if str(item.get("kind", "")).lower() in {"struct", "structure"}])
        if "segments" in lowered:
            return _content(self._page(self.segments, args, "name"))
        if "search" in lowered or "find" in lowered:
            return self.search(args)
        if "function" in lowered:
            return self.function(args)
        raise ValueError(f"Unsupported REAI MCP tool: {name}")

    def database(self, args: dict[str, Any]) -> dict[str, Any]:
        database_id = args.get("preferred_session_id") or self.sample.get("sha256") or self.workspace.name
        return _content(
            [
                {
                    "type": "database",
                    "database": database_id,
                    "workspace": str(self.workspace),
                    "sample_path": str(self.sample_path or self.sample.get("source_path") or ""),
                    "read_only": True,
                }
            ]
        )

    def metadata(self) -> dict[str, Any]:
        metadata = dict(self.extraction.get("metadata") or self._load_json(self.analysis_dir / "binary_metadata.json", {}))
        metadata.update(
            {
                "type": "metadata",
                "workspace": str(self.workspace),
                "sample_path": str(self.sample_path or self.sample.get("source_path") or ""),
                "sha256": self.sample.get("sha256"),
                "reai_mcp_version": __version__,
            }
        )
        return _content([metadata])

    def list_functions(self, args: dict[str, Any]) -> dict[str, Any]:
        query = args.get("filter") or (args.get("queries") or {}).get("filter") or "*"
        offset = int(args.get("offset") or (args.get("queries") or {}).get("offset") or 0)
        count = int(args.get("count") or (args.get("queries") or {}).get("count") or 50)
        records = self.functions
        if query and query != "*":
            needle = str(query).lower()
            records = [item for item in records if needle in str(item.get("name", "")).lower() or needle in _address_key(item.get("address"))]
        return _content(records[offset : offset + count])

    def function(self, args: dict[str, Any]) -> dict[str, Any]:
        record = self._function_for_args(args)
        return _content([record] if record else [])

    def code_text(self, args: dict[str, Any], path_key: str, obs_type: str) -> dict[str, Any]:
        target = _target_from_args(args)
        record = self._function_for_args(args)
        if not record:
            return _content([])
        rel_path = record.get(path_key)
        text = self._read_workspace_text(rel_path)
        if not text:
            status_key = "decompilation_status" if path_key == "pseudocode_path" else "disassembly_status"
            text = f"{obs_type} unavailable: {record.get(status_key) or 'missing artifact'}"
        return _content(
            [
                {
                    "type": obs_type,
                    "address": _address_key(record.get("address")) or target,
                    "name": record.get("name"),
                    "text": text[:20000],
                }
            ]
        )

    def xrefs_for(self, args: dict[str, Any], *, direction: str) -> dict[str, Any]:
        target = _address_key(_target_from_args(args))
        records: list[dict[str, Any]] = []
        for item in self.xrefs:
            source = _address_key(item.get("source_address"))
            destination = _address_key(item.get("destination_address"))
            if direction in {"from", "both"} and source == target:
                records.append({"type": "xref", **item})
            if direction in {"to", "both"} and destination == target:
                records.append({"type": "xref", **item})
        for function in self.functions:
            address = _address_key(function.get("address"))
            if direction in {"to", "both"} and target in {_address_key(value) for value in function.get("callees", [])}:
                records.append({"type": "call_xref", "source_function": address, "destination_address": target, "xref_type": "code"})
            if direction in {"from", "both"} and address == target:
                for callee in function.get("callees", []):
                    records.append({"type": "call_xref", "source_function": target, "destination_address": _address_key(callee), "xref_type": "code"})
        return _content(records[:100])

    def call_edges(self, args: dict[str, Any], edge_name: str) -> dict[str, Any]:
        record = self._function_for_args(args)
        if not record:
            return _content([])
        source = _address_key(record.get("address"))
        records = []
        for address in record.get(edge_name, []):
            related = self.function_by_address.get(_address_key(address), {})
            key = "caller" if edge_name == "callers" else "callee"
            records.append(
                {
                    "type": key,
                    key: _address_key(address),
                    "name": related.get("name"),
                    "source_function": _address_key(address) if edge_name == "callers" else source,
                    "target": source,
                }
            )
        return _content(records)

    def cfg(self, args: dict[str, Any]) -> dict[str, Any]:
        record = self._function_for_args(args)
        if not record:
            return _content([])
        callers = record.get("callers", [])
        callees = record.get("callees", [])
        return _content(
            [
                {
                    "type": "cfg",
                    "address": _address_key(record.get("address")),
                    "name": record.get("name"),
                    "blocks": None,
                    "edges": len(callers) + len(callees),
                    "callers": [_address_key(item) for item in callers],
                    "callees": [_address_key(item) for item in callees],
                    "recursive": bool(record.get("recursive")),
                }
            ]
        )

    def basic_blocks(self, args: dict[str, Any]) -> dict[str, Any]:
        record = self._function_for_args(args)
        return _content(
            [
                {
                    "type": "basic_blocks",
                    "address": _address_key(record.get("address")) if record else _address_key(_target_from_args(args)),
                    "available": False,
                    "reason": "Phase 2 extraction does not currently persist basic block boundaries.",
                }
            ]
        )

    def data(self, args: dict[str, Any]) -> dict[str, Any]:
        target = _address_key(_target_from_args(args))
        records = []
        for collection, kind in ((self.strings, "string"), (self.globals, "global"), (self.imports, "import")):
            for item in collection:
                if _address_key(item.get("address")) == target:
                    records.append({"type": kind, "address": target, "value": item.get("value") or item.get("name"), **item})
        return _content(records)

    def search(self, args: dict[str, Any]) -> dict[str, Any]:
        query = str(args.get("query") or args.get("targets") or args.get("filter") or "").lower()
        if not query:
            return _content([])
        records = []
        for kind, collection, fields in (
            ("function", self.functions, ("address", "name", "prototype")),
            ("string", self.strings, ("address", "value")),
            ("import", self.imports, ("address", "module", "name")),
            ("global", self.globals, ("address", "name", "type")),
        ):
            for item in collection:
                haystack = " ".join(str(item.get(field, "")) for field in fields).lower()
                if query in haystack:
                    records.append({"type": kind, **item})
        return _content(records[:100])

    def _function_for_args(self, args: dict[str, Any]) -> dict[str, Any] | None:
        target = _target_from_args(args)
        key = _address_key(target)
        if key in self.function_by_address:
            return self.function_by_address[key]
        return self.function_by_name.get(str(target).lower())

    def _page(self, records: list[dict[str, Any]], args: dict[str, Any], filter_field: str) -> list[dict[str, Any]]:
        offset = int(args.get("offset") or 0)
        count = int(args.get("count") or 50)
        query = str(args.get("filter") or "").lower()
        filtered = records
        if query and query != "*":
            filtered = [item for item in records if query in str(item.get(filter_field, "")).lower()]
        return filtered[offset : offset + count]

    def _load_records(self, extraction_key: str, fallback_path: Path, fallback_key: str) -> list[dict[str, Any]]:
        records = self.extraction.get(extraction_key)
        if records is None:
            records = self._load_json(fallback_path, {}).get(fallback_key, [])
        return [_normalize_record(item) for item in records or [] if isinstance(item, dict)]

    def _read_workspace_text(self, rel_path: Any) -> str | None:
        if not rel_path:
            return None
        path = self.workspace / Path(str(rel_path))
        try:
            resolved = path.resolve()
            resolved.relative_to(self.workspace.resolve())
            if resolved.is_file():
                return resolved.read_text(encoding="utf-8", errors="replace")
        except (OSError, ValueError):
            return None
        return None

    @staticmethod
    def _load_json(path: Path, default: Any) -> Any:
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return default


def run_http_server(*, workspace: Path, sample_path: Path | None, host: str, port: int) -> None:
    engine = ArtifactQueryEngine(workspace=workspace, sample_path=sample_path)

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:  # noqa: N802
            length = int(self.headers.get("Content-Length", "0"))
            raw = self.rfile.read(length).decode("utf-8", errors="replace")
            try:
                request = json.loads(raw or "{}")
                response = _handle_json_rpc(engine, request)
                status = 200
            except Exception as exc:
                response = {"jsonrpc": "2.0", "id": None, "error": {"code": -32000, "message": str(exc)}}
                status = 500
            payload = json.dumps(response, default=str).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def log_message(self, format: str, *args: Any) -> None:
            return

    server = ThreadingHTTPServer((host, port), Handler)
    server.serve_forever()


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="REAI read-only MCP server")
    parser.add_argument("sample", nargs="?", help="Sample path associated with the workspace.")
    parser.add_argument("--workspace", required=True, help="REAI sample workspace root.")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8745)
    args = parser.parse_args(argv)
    run_http_server(
        workspace=Path(args.workspace),
        sample_path=Path(args.sample) if args.sample else None,
        host=args.host,
        port=args.port,
    )


def _handle_json_rpc(engine: ArtifactQueryEngine, request: dict[str, Any]) -> dict[str, Any]:
    request_id = request.get("id")
    method = request.get("method")
    if method == "ping":
        result: Any = {}
    elif method == "initialize":
        result = {
            "protocolVersion": request.get("params", {}).get("protocolVersion", "2025-06-18"),
            "serverInfo": {"name": "reai-mcp", "version": __version__},
            "capabilities": {"tools": {}},
        }
    elif method == "notifications/initialized":
        return {"jsonrpc": "2.0", "result": {}}
    elif method == "tools/list":
        result = {"tools": list(TOOLS)}
    elif method == "tools/call":
        params = request.get("params") or {}
        result = engine.tool(str(params.get("name")), params.get("arguments") or {})
    else:
        return {"jsonrpc": "2.0", "id": request_id, "error": {"code": -32601, "message": f"Unknown method: {method}"}}
    return {"jsonrpc": "2.0", "id": request_id, "result": result}


def _content(records: list[dict[str, Any]]) -> dict[str, Any]:
    return {"content": records}


def _target_from_args(args: dict[str, Any]) -> Any:
    for key in ("addr", "address", "target", "database"):
        if args.get(key) not in (None, ""):
            return args[key]
    addrs = args.get("addrs")
    if isinstance(addrs, list) and addrs:
        return addrs[0]
    if isinstance(addrs, str):
        return addrs
    regions = args.get("regions")
    if isinstance(regions, dict):
        return regions.get("addr") or regions.get("address")
    return ""


def _address_key(value: Any) -> str:
    if value in (None, ""):
        return ""
    if isinstance(value, int):
        return hex(value).lower()
    text = str(value).strip().lower()
    try:
        return hex(int(text, 16 if text.startswith("0x") else 10)).lower()
    except ValueError:
        return text


def _normalize_record(record: dict[str, Any]) -> dict[str, Any]:
    normalized = dict(record)
    for key, value in list(normalized.items()):
        if key.endswith("address") or key == "address" or key in {"callers", "callees", "string_refs", "import_refs"}:
            if isinstance(value, list):
                normalized[key] = [_address_key(item) for item in value]
            else:
                normalized[key] = _address_key(value)
    return normalized


if __name__ == "__main__":
    main()
