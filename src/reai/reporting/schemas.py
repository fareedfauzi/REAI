from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class ReportRunStatus(StrEnum):
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    PARTIAL = "PARTIAL"


class ReportSectionStatus(StrEnum):
    GENERATED = "GENERATED"
    OMITTED = "OMITTED"


class ReportSampleInfo(BaseModel):
    sample_id: str
    filename: str
    source_path: str
    size: int
    md5: str
    sha1: str
    sha256: str
    architecture: str | None = None
    bitness: int | None = None
    processor: str | None = None
    file_type: str | None = None
    image_base: str | None = None
    ida_version: str | None = None
    reai_version: str
    analysis_timestamp: str


class ReportFunction(BaseModel):
    address: str
    original_name: str
    semantic_name: str | None = None
    idb_name: str | None = None
    display_name: str
    summary: str | None = None
    confidence: float
    confidence_label: str
    capabilities: list[str] = Field(default_factory=list)
    behavior: list[str] = Field(default_factory=list)
    evidence: list[dict[str, Any]] = Field(default_factory=list)
    unknowns: list[str] = Field(default_factory=list)
    imports: list[str] = Field(default_factory=list)
    idb_status: str | None = None


class ReportArtifact(BaseModel):
    artifact_id: str
    original_value: str
    normalized_value: str
    display_value: str
    artifact_type: str
    role: str
    function_address: str | None = None
    address: str | None = None
    usage: str | None = None
    confidence: float
    is_ioc: bool
    evidence: list[dict[str, Any]] = Field(default_factory=list)


class ReportSubsystem(BaseModel):
    subsystem_id: str
    name: str
    confidence: float
    functions: list[ReportFunction] = Field(default_factory=list)
    evidence: list[dict[str, Any]] = Field(default_factory=list)


class ReportFlow(BaseModel):
    flow_id: str
    source: ReportFunction
    target: ReportFunction
    relationship: str
    confidence: float
    evidence: list[dict[str, Any]] = Field(default_factory=list)


class ReportDataFlow(BaseModel):
    flow_id: str
    source_entity: str
    target: ReportFunction | None = None
    data_name: str | None = None
    confidence: float
    evidence: list[dict[str, Any]] = Field(default_factory=list)


class ReportConfigItem(BaseModel):
    key: str
    value: str | None
    display_value: str | None
    value_type: str
    function: ReportFunction | None = None
    confidence: float
    evidence: list[dict[str, Any]] = Field(default_factory=list)


class ReportCommand(BaseModel):
    command_id: str
    dispatcher: ReportFunction | None = None
    handler: ReportFunction | None = None
    handler_name: str | None = None
    confidence: float
    evidence: list[dict[str, Any]] = Field(default_factory=list)


class ReportStructureField(BaseModel):
    offset: str
    name: str
    field_type: str
    confidence: float


class ReportStructure(BaseModel):
    structure_id: str
    name: str
    confidence: float
    size: int | None = None
    fields: list[ReportStructureField] = Field(default_factory=list)
    eligible_for_idb: bool = False


class ReportContradiction(BaseModel):
    contradiction_id: str
    severity: str
    entities: list[str] = Field(default_factory=list)
    description: str
    status: str
    resolution: str | None = None


class AttackMapping(BaseModel):
    technique: str
    technique_id: str
    evidence: str
    functions: list[ReportFunction] = Field(default_factory=list)
    confidence: float


class ReportSection(BaseModel):
    section_id: str
    title: str
    status: ReportSectionStatus = ReportSectionStatus.GENERATED
    fingerprint: str
    source_facts: dict[str, Any] = Field(default_factory=dict)
    narrative: str = ""


class ReportStats(BaseModel):
    sections_generated: int = 0
    sections_omitted: int = 0
    tables_generated: int = 0
    diagrams_generated: int = 0
    iocs_rendered: int = 0
    functions_referenced: int = 0
    evidence_references: int = 0
    validation_failures: int = 0
    markdown_generated: bool = False
    html_generated: bool = False
    pdf_generated: bool = False


class ReportRun(BaseModel):
    run_id: str
    sample_id: str
    source_analysis_fingerprint: str | None = None
    enrichment_fingerprint: str | None = None
    report_fingerprint: str
    schema_version: str
    prompt_version: str
    formats: list[str]
    status: ReportRunStatus
    started_at: str
    completed_at: str | None = None
    error: str | None = None
    stats: ReportStats = Field(default_factory=ReportStats)
    markdown_path: str | None = None
    html_path: str | None = None
    pdf_path: str | None = None


class ReportModel(BaseModel):
    schema_version: str
    prompt_version: str
    fingerprint: str
    sample: ReportSampleInfo
    source_analysis_fingerprint: str | None = None
    enrichment_fingerprint: str | None = None
    sections: list[ReportSection] = Field(default_factory=list)
    functions: list[ReportFunction] = Field(default_factory=list)
    subsystems: list[ReportSubsystem] = Field(default_factory=list)
    capabilities: list[str] = Field(default_factory=list)
    execution_flows: list[ReportFlow] = Field(default_factory=list)
    data_flows: list[ReportDataFlow] = Field(default_factory=list)
    configuration: list[ReportConfigItem] = Field(default_factory=list)
    commands: list[ReportCommand] = Field(default_factory=list)
    iocs: list[ReportArtifact] = Field(default_factory=list)
    artifacts: list[ReportArtifact] = Field(default_factory=list)
    attack_mappings: list[AttackMapping] = Field(default_factory=list)
    structures: list[ReportStructure] = Field(default_factory=list)
    contradictions: list[ReportContradiction] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)
    stats: ReportStats = Field(default_factory=ReportStats)
