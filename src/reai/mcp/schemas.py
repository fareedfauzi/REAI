from __future__ import annotations

import hashlib
import json
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class MCPCapability(StrEnum):
    DECOMPILE = "decompile"
    DISASSEMBLE = "disassemble"
    XREFS = "xrefs"
    CALLERS = "callers"
    CALLEES = "callees"
    CFG = "cfg"
    MEMORY = "memory"
    DATA = "data"
    TYPES = "types"
    FUNCTION = "function"
    SEARCH = "search"


READ_ONLY_CAPABILITIES = frozenset(capability.value for capability in MCPCapability)


class InvestigationStatus(StrEnum):
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    INTERRUPTED = "INTERRUPTED"


class InvestigationOutcome(StrEnum):
    RESOLVED_HIGH = "RESOLVED_HIGH"
    RESOLVED_MEDIUM = "RESOLVED_MEDIUM"
    UNRESOLVED = "UNRESOLVED"
    BUDGET_EXHAUSTED = "BUDGET_EXHAUSTED"
    NO_USEFUL_ACTION = "NO_USEFUL_ACTION"
    MCP_UNAVAILABLE = "MCP_UNAVAILABLE"
    FAILED = "FAILED"


class MCPCallStatus(StrEnum):
    SUCCESS = "SUCCESS"
    FAILED = "FAILED"
    UNAVAILABLE = "UNAVAILABLE"
    TIMEOUT = "TIMEOUT"
    DEDUPED = "DEDUPED"


class InvestigationTarget(BaseModel):
    sample_id: str
    address: str
    current_name: str
    proposed_name: str | None = None
    summary: str | None = None
    confidence: float = Field(ge=0.0, le=1.0)
    confidence_label: str
    unknowns: list[str] = Field(default_factory=list)
    evidence: list[dict] = Field(default_factory=list)
    investigation_reasons: list[str] = Field(default_factory=list)
    analysis_pass: int = 1
    caller_count: int = 0
    callee_count: int = 0
    function: dict = Field(default_factory=dict)
    priority_score: float = 0.0
    priority_reason: str = ""


class InvestigationAction(BaseModel):
    capability: MCPCapability
    target: str
    reason: str
    parameters: dict[str, Any] = Field(default_factory=dict)
    depth: int = 0

    def fingerprint(self) -> str:
        payload = {
            "capability": self.capability.value,
            "target": self.target.lower(),
            "parameters": self.parameters,
            "depth": self.depth,
        }
        raw = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()


class InvestigationPlan(BaseModel):
    function_address: str
    goal: str
    actions: list[InvestigationAction] = Field(default_factory=list)
    expected_information_gain: str = ""
    stop_if: list[str] = Field(default_factory=list)


class MCPToolResult(BaseModel):
    capability: MCPCapability
    target: str
    success: bool
    observations: list[dict[str, Any]] = Field(default_factory=list)
    raw: dict[str, Any] | list[Any] | str | None = None
    error: str | None = None
    duration_ms: int = 0
    result_size: int = 0


class MCPEvidence(BaseModel):
    evidence_type: str
    value: str
    description: str
    address: str | None = None
    source: str = "MCP_OBSERVED"
    capability: MCPCapability
    target: str
    record: dict[str, Any] = Field(default_factory=dict)

    def fingerprint(self) -> str:
        payload = {
            "source": self.source,
            "type": self.evidence_type,
            "value": self.value,
            "address": self.address,
            "capability": self.capability.value,
            "target": self.target.lower(),
        }
        raw = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()


class MCPInvestigationStats(BaseModel):
    candidates: int = 0
    attempted: int = 0
    completed: int = 0
    resolved_high: int = 0
    resolved_medium: int = 0
    unresolved: int = 0
    budget_exhausted: int = 0
    mcp_unavailable: int = 0
    failed: int = 0
    rounds: int = 0
    mcp_calls: int = 0
    tool_failures: int = 0
    confidence_improved: int = 0
    confidence_reduced: int = 0
    interpretation_changed: int = 0
    average_confidence_before: float = 0.0
    average_confidence_after: float = 0.0

