from __future__ import annotations

from enum import StrEnum
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator


SCHEMA_VERSION = "phase3-function-analysis-v1"


class ConfidenceLabel(StrEnum):
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class EvidenceSource(StrEnum):
    IDA_OBSERVED = "IDA_OBSERVED"
    MCP_OBSERVED = "MCP_OBSERVED"
    AI_DERIVED = "AI_DERIVED"


class EvidenceItem(BaseModel):
    type: str
    value: str
    description: str
    address: str | None = None
    source: EvidenceSource = EvidenceSource.IDA_OBSERVED


class VariableProposal(BaseModel):
    original: str
    proposed: str
    confidence: float = Field(ge=0.0, le=1.0)
    evidence: str


class TypeSuggestion(BaseModel):
    target: str
    proposed_type: str
    confidence: float = Field(ge=0.0, le=1.0)
    evidence: str


class ArtifactCandidate(BaseModel):
    value: str
    type: str
    address: str | None = None
    usage: str | None = None
    confidence: float = Field(ge=0.0, le=1.0)


class FunctionAnalysisResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    address: str
    proposed_name: str | None = None
    summary: str
    behavior: list[str] = Field(default_factory=list)
    confidence: float = Field(ge=0.0, le=1.0)
    confidence_label: ConfidenceLabel
    evidence: list[EvidenceItem] = Field(default_factory=list)
    variables: list[VariableProposal] = Field(default_factory=list)
    types: list[TypeSuggestion] = Field(default_factory=list)
    capabilities: list[str] = Field(default_factory=list)
    artifacts: list[ArtifactCandidate] = Field(default_factory=list)
    unknowns: list[str] = Field(default_factory=list)
    reasoning_summary: str
    analysis_pass: int = Field(ge=1)
    needs_investigation: bool = False

    @field_validator("proposed_name")
    @classmethod
    def _empty_name_to_none(cls, value: str | None) -> str | None:
        if value is None:
            return None
        stripped = value.strip()
        return stripped or None


class FunctionContext(BaseModel):
    function: dict
    pseudocode: str | None = None
    disassembly: str | None = None
    imports: list[dict] = Field(default_factory=list)
    strings: list[dict] = Field(default_factory=list)
    globals: list[dict] = Field(default_factory=list)
    callers: list[dict] = Field(default_factory=list)
    callees: list[dict] = Field(default_factory=list)
    child_findings: list[dict] = Field(default_factory=list)
    types: list[dict] = Field(default_factory=list)
    segments: list[dict] = Field(default_factory=list)
    context_truncated: bool = False


class AIRequestMetadata(BaseModel):
    request_id: str
    provider: str
    model: str | None = None
    timestamp: str
    task: str
    function_address: str | None = None
    analysis_pass: int
    input_tokens: int | None = None
    output_tokens: int | None = None
    latency_ms: int | None = None
    retry_count: int = 0
    success: bool
    error: str | None = None


class AIProviderResponse(BaseModel):
    result: FunctionAnalysisResult
    request: AIRequestMetadata


class AIAnalysisStats(BaseModel):
    target_functions: int = 0
    analyzed: int = 0
    failed: int = 0
    high_confidence: int = 0
    medium_confidence: int = 0
    low_confidence: int = 0
    proposed_function_names: int = 0
    variable_proposals: int = 0
    needs_investigation: int = 0
    context_truncated: int = 0
    ai_requests: int = 0
    total_input_tokens: int = 0
    total_output_tokens: int = 0
    generic_name_rate: float = 0.0


AnalysisStatus = Literal["COMPLETED", "FAILED"]
