from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class SemanticProvenance(StrEnum):
    IDA_OBSERVED = "IDA_OBSERVED"
    MCP_OBSERVED = "MCP_OBSERVED"
    AI_DERIVED = "AI_DERIVED"
    PROPAGATED_CONTEXT = "PROPAGATED_CONTEXT"
    VALIDATION_DERIVED = "VALIDATION_DERIVED"


class RelationshipType(StrEnum):
    CALLS = "CALLS"
    CALLED_BY = "CALLED_BY"
    REFERENCES_STRING = "REFERENCES_STRING"
    REFERENCES_GLOBAL = "REFERENCES_GLOBAL"
    USES_IMPORT = "USES_IMPORT"
    RELATED_ARTIFACT = "RELATED_ARTIFACT"
    SUBSYSTEM_MEMBER = "SUBSYSTEM_MEMBER"
    CAPABILITY_SUPPORT = "CAPABILITY_SUPPORT"


class CurrentFunctionFinding(BaseModel):
    address: str
    original_name: str
    proposed_name: str | None = None
    summary: str | None = None
    confidence: float = 0.0
    confidence_label: str = "LOW"
    capabilities: list[str] = Field(default_factory=list)
    behavior: list[str] = Field(default_factory=list)
    evidence: list[dict[str, Any]] = Field(default_factory=list)
    unknowns: list[str] = Field(default_factory=list)
    variables: list[dict[str, Any]] = Field(default_factory=list)
    types: list[dict[str, Any]] = Field(default_factory=list)
    artifacts: list[dict[str, Any]] = Field(default_factory=list)
    analysis_pass: int = 1
    needs_investigation: bool = False


class SemanticRelationship(BaseModel):
    relationship_id: str
    source_entity: str
    target_entity: str
    relationship_type: RelationshipType
    confidence: float = Field(ge=0.0, le=1.0)
    evidence: list[dict[str, Any]] = Field(default_factory=list)
    provenance: SemanticProvenance = SemanticProvenance.IDA_OBSERVED


class SubsystemFunction(BaseModel):
    function_address: str
    role: str = "member"
    confidence: float = Field(ge=0.0, le=1.0)
    evidence: list[dict[str, Any]] = Field(default_factory=list)


class Subsystem(BaseModel):
    subsystem_id: str
    name: str
    confidence: float = Field(ge=0.0, le=1.0)
    functions: list[SubsystemFunction] = Field(default_factory=list)
    entry_functions: list[str] = Field(default_factory=list)
    relationships: list[str] = Field(default_factory=list)
    evidence: list[dict[str, Any]] = Field(default_factory=list)


class ValidatedArtifact(BaseModel):
    artifact_id: str
    original_value: str
    normalized_value: str
    artifact_type: str
    role: str
    function_address: str | None = None
    address: str | None = None
    usage: str | None = None
    confidence: float = Field(ge=0.0, le=1.0)
    is_ioc: bool = False
    evidence: list[dict[str, Any]] = Field(default_factory=list)


class Capability(BaseModel):
    capability_id: str
    name: str
    confidence: float = Field(ge=0.0, le=1.0)
    functions: list[str] = Field(default_factory=list)
    evidence: list[dict[str, Any]] = Field(default_factory=list)


class RecoveredStructureField(BaseModel):
    offset: str
    name: str
    field_type: str
    confidence: float = Field(ge=0.0, le=1.0)
    evidence: list[dict[str, Any]] = Field(default_factory=list)
    eligible_for_idb: bool = False


class RecoveredStructure(BaseModel):
    structure_id: str
    name: str
    confidence: float = Field(ge=0.0, le=1.0)
    size: int | None = None
    fields: list[RecoveredStructureField] = Field(default_factory=list)
    evidence: list[dict[str, Any]] = Field(default_factory=list)
    eligible_for_idb: bool = False


class ExecutionFlow(BaseModel):
    flow_id: str
    source_function: str
    target_function: str
    relationship: str = "calls"
    confidence: float = Field(ge=0.0, le=1.0)
    evidence: list[dict[str, Any]] = Field(default_factory=list)


class DataFlow(BaseModel):
    flow_id: str
    source_entity: str
    target_entity: str
    data_name: str | None = None
    confidence: float = Field(ge=0.0, le=1.0)
    evidence: list[dict[str, Any]] = Field(default_factory=list)


class CommandHandler(BaseModel):
    dispatcher: str
    command_id: str
    handler: str
    handler_name: str | None = None
    confidence: float = Field(ge=0.0, le=1.0)
    evidence: list[dict[str, Any]] = Field(default_factory=list)


class ConfigurationItem(BaseModel):
    item_id: str
    key: str
    value: str | None = None
    value_type: str
    function_address: str | None = None
    confidence: float = Field(ge=0.0, le=1.0)
    evidence: list[dict[str, Any]] = Field(default_factory=list)


class Contradiction(BaseModel):
    contradiction_id: str
    severity: str
    entities: list[str]
    description: str
    evidence: list[dict[str, Any]] = Field(default_factory=list)
    status: str = "OPEN"
    resolution: str | None = None


class ValidationResult(BaseModel):
    result_id: str
    entity: str
    validation_type: str
    status: str
    confidence: float = Field(ge=0.0, le=1.0)
    reason: str
    evidence: list[dict[str, Any]] = Field(default_factory=list)


class ChangeCandidate(BaseModel):
    candidate_id: str
    entity: str
    address: str | None = None
    change_type: str
    original: str | None = None
    proposed: str
    confidence: float = Field(ge=0.0, le=1.0)
    eligible_for_idb: bool
    evidence: list[dict[str, Any]] = Field(default_factory=list)
    reason: str | None = None


class PropagationPassStats(BaseModel):
    pass_number: int
    functions_reconsidered: int = 0
    interpretations_changed: int = 0
    confidence_changed: int = 0
    new_relationships: int = 0
    new_structures: int = 0
    new_validated_artifacts: int = 0
    converged: bool = False
    fingerprint: str


class SemanticAnalysisStats(BaseModel):
    functions_validated: int = 0
    rename_candidates: int = 0
    comment_candidates: int = 0
    variable_candidates: int = 0
    type_candidates: int = 0
    subsystems: int = 0
    capabilities: int = 0
    recovered_structures: int = 0
    recovered_fields: int = 0
    command_handlers: int = 0
    configuration_items: int = 0
    validated_artifacts: int = 0
    validated_iocs: int = 0
    contradictions: int = 0
    unresolved_contradictions: int = 0
    propagation_passes: int = 0
    semantic_relationships: int = 0


class ValidatedAnalysisModel(BaseModel):
    fingerprint: str
    functions: list[CurrentFunctionFinding] = Field(default_factory=list)
    relationships: list[SemanticRelationship] = Field(default_factory=list)
    subsystems: list[Subsystem] = Field(default_factory=list)
    execution_flows: list[ExecutionFlow] = Field(default_factory=list)
    data_flows: list[DataFlow] = Field(default_factory=list)
    recovered_structures: list[RecoveredStructure] = Field(default_factory=list)
    validated_artifacts: list[ValidatedArtifact] = Field(default_factory=list)
    capabilities: list[Capability] = Field(default_factory=list)
    command_handlers: list[CommandHandler] = Field(default_factory=list)
    configuration_items: list[ConfigurationItem] = Field(default_factory=list)
    contradictions: list[Contradiction] = Field(default_factory=list)
    validation_results: list[ValidationResult] = Field(default_factory=list)
    change_candidates: list[ChangeCandidate] = Field(default_factory=list)
    propagation_passes: list[PropagationPassStats] = Field(default_factory=list)
    stats: SemanticAnalysisStats = Field(default_factory=SemanticAnalysisStats)
