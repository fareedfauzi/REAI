from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class ImportanceLevel(StrEnum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    SUPPORTING = "SUPPORTING"


class ConfidenceDisplay(StrEnum):
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class IOCType(StrEnum):
    NETWORK_IOC = "NETWORK IOC"
    HOST_IOC = "HOST IOC"
    BUILD_ARTIFACT = "BUILD ARTIFACT"
    COMMAND_LINE_ARTIFACT = "COMMAND-LINE ARTIFACT"
    CONTEXTUAL_ARTIFACT = "CONTEXTUAL ARTIFACT"


class SampleProfile(BaseModel):
    filename: str
    sha256: str
    sha1: str
    md5: str
    size: int
    file_type: str | None = "Portable executable (PE)"
    architecture: str | None = "x86"
    bitness: int | None = 32
    image_base: str | None = "0x400000"
    analysis_timestamp: str
    classification_badges: list[str] = Field(default_factory=list)
    observed_role: str = "Downloader / Stager"
    primary_objective: str = "Retrieve and execute secondary payload"
    delivery_mechanism: str = "Not established from static sample"
    c2_retrieval_protocol: str = "HTTP / WinINet"
    persistence_status: str = "Not observed in static analysis"
    evasion_status: str = "Timing delay loop observed"
    impact_assessment: str = "Dependent on retrieved secondary payload"
    attribution_status: str = "Not established"
    confidence_overall: str = "HIGH"


class KeyFinding(BaseModel):
    number: str
    title: str
    summary: str
    confidence_label: str = "HIGH"
    evidence_summary: str = ""


class ExecutionChainStage(BaseModel):
    step_number: int
    stage_name: str
    description: str
    apis: list[str] = Field(default_factory=list)
    artifacts: list[str] = Field(default_factory=list)
    functions: list[str] = Field(default_factory=list)
    is_failure_path: bool = False


class TechnicalBehaviorSection(BaseModel):
    section_id: str
    title: str
    narrative: str
    functions: list[str] = Field(default_factory=list)
    apis: list[str] = Field(default_factory=list)
    artifacts: list[str] = Field(default_factory=list)
    confidence_label: str = "HIGH"
    evidence: list[dict[str, Any]] = Field(default_factory=list)


class KeyFunctionCard(BaseModel):
    address: str
    original_name: str
    applied_name: str | None = None
    display_name: str
    role: str
    importance_score: float
    importance_label: str
    confidence_label: str
    confidence_score: float
    summary: str
    behaviors: list[str] = Field(default_factory=list)
    key_apis: list[str] = Field(default_factory=list)
    artifacts: list[str] = Field(default_factory=list)
    related_functions: list[str] = Field(default_factory=list)
    pseudocode_snippet: str | None = None
    idb_status: str | None = None


class APISequence(BaseModel):
    name: str
    description: str
    apis: list[str] = Field(default_factory=list)
    function: str = ""


class RecoveredStructure(BaseModel):
    name: str
    size: int | None = None
    fields: list[dict[str, Any]] = Field(default_factory=list)
    confidence_label: str = "HIGH"


class ThreatIntelligenceModel(BaseModel):
    network_infrastructure: list[dict[str, Any]] = Field(default_factory=list)
    host_artifacts: list[dict[str, Any]] = Field(default_factory=list)
    build_artifacts: list[dict[str, Any]] = Field(default_factory=list)
    behavioral_characteristics: list[dict[str, Any]] = Field(default_factory=list)
    development_context: str = ""
    campaign_assessment: str = "Not established from static analysis"
    actor_assessment: str = "Not established"
    attribution_status: str = "NOT ESTABLISHED"


class IOCItem(BaseModel):
    ioc_type: str
    value: str
    display_value: str
    role: str
    source: str
    function: str
    confidence_label: str = "HIGH"


class AttackMappingDetail(BaseModel):
    tactic: str
    technique: str
    technique_id: str
    observed_behavior: str
    evidence: str
    functions: list[str] = Field(default_factory=list)
    confidence_label: str = "HIGH"


class HuntingLead(BaseModel):
    category: str
    lead_title: str
    artifact_or_behavior: str
    detection_guidance: str


class YaraRuleModel(BaseModel):
    rule_name: str
    status: str = "ANALYST REVIEW REQUIRED"
    rule_text: str
    rationale: str


class AnalyticalGap(BaseModel):
    title: str
    description: str
    known_evidence: str
    missing_evidence: str
    recommended_action: str


class AppendixModel(BaseModel):
    companion_idb: str = "IDB Files/analyzed.i64"
    runtime_helpers: list[dict[str, Any]] = Field(default_factory=list)
    full_functions: list[dict[str, Any]] = Field(default_factory=list)
    report_schema: str = "report-engine-v2"
    source_analysis_fingerprint: str | None = None
    enrichment_fingerprint: str | None = None
    report_fingerprint: str = ""


class ReportStatsV2(BaseModel):
    sections_generated: int = 11
    sections_omitted: int = 0
    tables_generated: int = 0
    diagrams_generated: int = 1
    iocs_rendered: int = 0
    functions_referenced: int = 0
    evidence_references: int = 0
    validation_failures: int = 0
    markdown_generated: bool = False
    html_generated: bool = False
    pdf_generated: bool = False


class ReportModelV2(BaseModel):
    schema_version: str = "report-engine-v2"
    prompt_version: str = "reai-v2"
    fingerprint: str
    source_analysis_fingerprint: str | None = None
    enrichment_fingerprint: str | None = None

    sample: SampleProfile
    executive_assessment: str
    key_findings: list[KeyFinding] = Field(default_factory=list)
    execution_chain: list[ExecutionChainStage] = Field(default_factory=list)
    technical_analysis: list[TechnicalBehaviorSection] = Field(default_factory=list)
    key_functions: list[KeyFunctionCard] = Field(default_factory=list)
    api_sequences: list[APISequence] = Field(default_factory=list)
    structures: list[RecoveredStructure] = Field(default_factory=list)
    threat_intelligence: ThreatIntelligenceModel = Field(default_factory=ThreatIntelligenceModel)
    indicators: list[IOCItem] = Field(default_factory=list)
    attack_mappings: list[AttackMappingDetail] = Field(default_factory=list)
    hunting_leads: list[HuntingLead] = Field(default_factory=list)
    yara_rule: YaraRuleModel | None = None
    analytical_gaps: list[AnalyticalGap] = Field(default_factory=list)
    appendix: AppendixModel = Field(default_factory=AppendixModel)
    stats: ReportStatsV2 = Field(default_factory=ReportStatsV2)

    # Legacy/compatibility bridges for older tests/callers:
    @property
    def iocs(self) -> list[IOCItem]:
        return [i for i in self.indicators if i.ioc_type in {IOCType.NETWORK_IOC, IOCType.HOST_IOC}]

    @property
    def functions(self) -> list[KeyFunctionCard]:
        return self.key_functions

    @property
    def capabilities(self) -> list[str]:
        return [b.title for b in self.technical_analysis]
