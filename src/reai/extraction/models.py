from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_serializer

from reai.utils.address import format_address


class HexAddressModel(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True)

    @staticmethod
    def _hex(value: int | None) -> str | None:
        return format_address(value)


class BinaryMetadata(HexAddressModel):
    architecture: str | None = None
    bitness: int | None = None
    endianness: str | None = None
    image_base: int | None = None
    entry_points: list[int] = Field(default_factory=list)
    file_type: str | None = None
    loader: str | None = None
    processor: str | None = None
    min_address: int | None = None
    max_address: int | None = None
    ida_version: str | None = None
    python_version: str | None = None
    reai_version: str | None = None
    analysis_started_at: datetime | None = None
    analysis_completed_at: datetime | None = None

    @field_serializer("image_base", "min_address", "max_address")
    def _serialize_addr(self, value: int | None) -> str | None:
        return self._hex(value)

    @field_serializer("entry_points")
    def _serialize_entry_points(self, value: list[int]) -> list[str]:
        return [self._hex(item) or "0x0" for item in value]


class SegmentRecord(HexAddressModel):
    name: str
    start: int
    end: int
    size: int
    permissions: str | None = None
    segment_class: str | None = None
    segment_type: str | None = None

    @field_serializer("start", "end")
    def _serialize_addr(self, value: int) -> str:
        return self._hex(value) or "0x0"


class ReferenceRecord(HexAddressModel):
    source_address: int
    destination_address: int
    xref_type: str | None = None
    source_function: int | None = None
    destination_entity: str | None = None

    @field_serializer("source_address", "destination_address", "source_function")
    def _serialize_addr(self, value: int | None) -> str | None:
        return self._hex(value)


class FunctionRecord(HexAddressModel):
    address: int
    end_address: int
    name: str
    size: int
    segment: str | None = None
    flags: int | None = None
    prototype: str | None = None
    is_thunk: bool = False
    is_library: bool = False
    is_external: bool = False
    callers: list[int] = Field(default_factory=list)
    callees: list[int] = Field(default_factory=list)
    string_refs: list[int] = Field(default_factory=list)
    import_refs: list[int] = Field(default_factory=list)
    global_refs: list[int] = Field(default_factory=list)
    decompilation_status: Literal["not_attempted", "success", "failed", "unavailable"] = "not_attempted"
    decompilation_error: str | None = None
    pseudocode_path: str | None = None
    disassembly_status: Literal["not_attempted", "success", "failed", "skipped"] = "not_attempted"
    disassembly_path: str | None = None
    scc_id: int | None = None
    recursive: bool = False

    @field_serializer("address", "end_address")
    def _serialize_addr(self, value: int) -> str:
        return self._hex(value) or "0x0"

    @field_serializer("callers", "callees", "string_refs", "import_refs", "global_refs")
    def _serialize_addrs(self, value: list[int]) -> list[str]:
        return [self._hex(item) or "0x0" for item in value]


class StringRecord(HexAddressModel):
    address: int
    value: str
    encoding: str | None = None
    length: int | None = None
    xrefs: list[ReferenceRecord] = Field(default_factory=list)
    referencing_functions: list[int] = Field(default_factory=list)

    @field_serializer("address")
    def _serialize_addr(self, value: int) -> str:
        return self._hex(value) or "0x0"

    @field_serializer("referencing_functions")
    def _serialize_funcs(self, value: list[int]) -> list[str]:
        return [self._hex(item) or "0x0" for item in value]


class ImportRecord(HexAddressModel):
    module: str | None = None
    name: str | None = None
    ordinal: int | None = None
    address: int | None = None
    xrefs: list[ReferenceRecord] = Field(default_factory=list)
    referencing_functions: list[int] = Field(default_factory=list)

    @field_serializer("address")
    def _serialize_addr(self, value: int | None) -> str | None:
        return self._hex(value)

    @field_serializer("referencing_functions")
    def _serialize_funcs(self, value: list[int]) -> list[str]:
        return [self._hex(item) or "0x0" for item in value]


class ExportRecord(HexAddressModel):
    name: str | None = None
    address: int
    ordinal: int | None = None

    @field_serializer("address")
    def _serialize_addr(self, value: int) -> str:
        return self._hex(value) or "0x0"


class GlobalRecord(HexAddressModel):
    address: int
    name: str
    size: int | None = None
    type: str | None = None
    segment: str | None = None
    xrefs: list[ReferenceRecord] = Field(default_factory=list)
    referencing_functions: list[int] = Field(default_factory=list)

    @field_serializer("address")
    def _serialize_addr(self, value: int) -> str:
        return self._hex(value) or "0x0"

    @field_serializer("referencing_functions")
    def _serialize_funcs(self, value: list[int]) -> list[str]:
        return [self._hex(item) or "0x0" for item in value]


class TypeRecord(BaseModel):
    name: str
    kind: str
    declaration: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class ExtractorFailure(BaseModel):
    extractor: str
    address: int | None = None
    name: str | None = None
    reason: str
    fatal: bool = False

    @field_serializer("address")
    def _serialize_addr(self, value: int | None) -> str | None:
        return format_address(value)


class CallEdge(HexAddressModel):
    caller: int
    callee: int
    type: str = "direct"
    source_address: int | None = None

    @field_serializer("caller", "callee", "source_address")
    def _serialize_addr(self, value: int | None) -> str | None:
        return self._hex(value)


class CallGraphNode(HexAddressModel):
    address: int
    name: str
    scc_id: int | None = None
    recursive: bool = False

    @field_serializer("address")
    def _serialize_addr(self, value: int) -> str:
        return self._hex(value) or "0x0"


class StronglyConnectedComponent(BaseModel):
    scc_id: int
    nodes: list[int]
    recursive: bool = False

    @field_serializer("nodes")
    def _serialize_nodes(self, value: list[int]) -> list[str]:
        return [format_address(item) or "0x0" for item in value]


class CallGraph(BaseModel):
    nodes: list[CallGraphNode]
    edges: list[CallEdge]
    components: list[StronglyConnectedComponent] = Field(default_factory=list)


class ExtractionStats(BaseModel):
    total_functions: int = 0
    sub_functions: int = 0
    named_functions: int = 0
    library_functions: int = 0
    thunks: int = 0
    decompiled_successfully: int = 0
    decompilation_failures: int = 0
    strings: int = 0
    imports: int = 0
    exports: int = 0
    globals: int = 0
    segments: int = 0
    types: int = 0
    call_edges: int = 0
    recursive_components: int = 0
    partial_failures: int = 0


class ExtractionBundle(BaseModel):
    metadata: BinaryMetadata = Field(default_factory=BinaryMetadata)
    functions: list[FunctionRecord] = Field(default_factory=list)
    strings: list[StringRecord] = Field(default_factory=list)
    imports: list[ImportRecord] = Field(default_factory=list)
    exports: list[ExportRecord] = Field(default_factory=list)
    globals: list[GlobalRecord] = Field(default_factory=list)
    segments: list[SegmentRecord] = Field(default_factory=list)
    types: list[TypeRecord] = Field(default_factory=list)
    xrefs: list[ReferenceRecord] = Field(default_factory=list)
    callgraph: CallGraph = Field(default_factory=lambda: CallGraph(nodes=[], edges=[]))
    failures: list[ExtractorFailure] = Field(default_factory=list)
    stats: ExtractionStats = Field(default_factory=ExtractionStats)
