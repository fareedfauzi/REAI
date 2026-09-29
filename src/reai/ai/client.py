from __future__ import annotations

import time
from datetime import datetime, timezone
from typing import Protocol
from uuid import uuid4

from reai.core.config import AIConfig
from reai.core.exceptions import AIProviderError
from reai.ai.prompts import SYSTEM_PROMPT, build_function_prompt
from reai.ai.schemas import (
    AIProviderResponse,
    AIRequestMetadata,
    ConfidenceLabel,
    EvidenceItem,
    EvidenceSource,
    FunctionAnalysisResult,
    FunctionContext,
)


class AIClient(Protocol):
    def analyze_function(self, context: FunctionContext, *, analysis_pass: int, retry_count: int = 0) -> AIProviderResponse:
        ...

    def model_info(self) -> dict:
        ...


def create_ai_client(config: AIConfig) -> AIClient | None:
    provider = config.provider.lower()
    if provider == "disabled":
        return None
    if provider in {"simulation", "mock"}:
        return SimulationAIClient(config)
    if provider == "openai":
        return OpenAIClient(config)
    raise AIProviderError(f"Unsupported AI provider:\n{config.provider}")


class SimulationAIClient:
    def __init__(self, config: AIConfig) -> None:
        self.config = config


    def analyze_function(self, context: FunctionContext, *, analysis_pass: int, retry_count: int = 0) -> AIProviderResponse:
        start = time.perf_counter()
        function = context.function
        address = function["address"]
        name = function["name"]
        child_names = [
            child.get("proposed_name")
            for child in context.child_findings
            if child.get("confidence_label") in {"HIGH", "MEDIUM"} and child.get("proposed_name")
        ]
        imports = [item.get("name") for item in context.imports if item.get("name")]
        strings = [item.get("value") for item in context.strings if item.get("value")]

        if child_names:
            proposed = f"coordinate_{child_names[0]}"
            summary = f"Coordinates child behavior involving {', '.join(child_names[:3])}."
            confidence = 0.78
            evidence_value = child_names[0]
            evidence_type = "child_analysis"
        elif imports:
            proposed = f"use_{_snake(imports[0])}"
            summary = f"Uses imported API {imports[0]} with local function context."
            confidence = 0.82
            evidence_value = imports[0]
            evidence_type = "api_call"
        elif strings:
            proposed = f"reference_{_snake(strings[0])[:32]}"
            summary = f"References string data: {strings[0][:80]}."
            confidence = 0.68
            evidence_value = strings[0]
            evidence_type = "string_reference"
        else:
            proposed = None
            summary = "Insufficient static context for a specific semantic interpretation."
            confidence = 0.35
            evidence_value = name
            evidence_type = "function_metadata"

        result = FunctionAnalysisResult(
            address=address,
            proposed_name=proposed,
            summary=summary,
            behavior=[summary],
            confidence=confidence,
            confidence_label=ConfidenceLabel.MEDIUM if confidence >= 0.55 else ConfidenceLabel.LOW,
            evidence=[
                EvidenceItem(
                    type=evidence_type,
                    value=evidence_value,
                    address=address,
                    description="Deterministic mock provider evidence derived from supplied context.",
                    source=EvidenceSource.IDA_OBSERVED,
                )
            ],
            variables=[],
            types=[],
            capabilities=["unknown"] if proposed is None else [],
            artifacts=[],
            unknowns=[] if proposed else ["Static context did not expose imports, strings, or analyzed children."],
            reasoning_summary=summary,
            analysis_pass=analysis_pass,
            needs_investigation=proposed is None,
        )
        request = AIRequestMetadata(
            request_id=str(uuid4()),
            provider="mock",
            model=self.config.model or "mock-phase3",
            timestamp=datetime.now(timezone.utc).isoformat(),
            task="function_analysis",
            function_address=address,
            analysis_pass=analysis_pass,
            input_tokens=_estimate_tokens(build_function_prompt(context)),
            output_tokens=_estimate_tokens(result.model_dump_json()),
            latency_ms=int((time.perf_counter() - start) * 1000),
            retry_count=retry_count,
            success=True,
        )
        return AIProviderResponse(result=result, request=request)

    def model_info(self) -> dict:
        return {"provider": "simulation", "model": self.config.model or "simulation-phase3"}


# Backward-compatibility alias
MockAIClient = SimulationAIClient


class OpenAIClient:

    def __init__(self, config: AIConfig) -> None:
        self.config = config
        if not config.model:
            raise AIProviderError("OpenAI provider requires [ai].model.")
        try:
            from openai import OpenAI
        except ImportError as exc:
            raise AIProviderError("OpenAI Python SDK is not installed.") from exc
        kwargs = {}
        if self.config.api_key:
            kwargs["api_key"] = self.config.api_key
        self._client = OpenAI(**kwargs)

    def analyze_function(self, context: FunctionContext, *, analysis_pass: int, retry_count: int = 0) -> AIProviderResponse:
        start = time.perf_counter()
        prompt = build_function_prompt(context)
        try:
            response = self._client.responses.parse(
                model=self.config.model,
                instructions=SYSTEM_PROMPT,
                input=prompt,
                text_format=FunctionAnalysisResult,
            )
        except Exception as exc:
            raise AIProviderError(f"OpenAI request failed:\n{exc}") from exc

        parsed = getattr(response, "output_parsed", None)
        if parsed is None:
            raise AIProviderError("OpenAI response did not contain a parsed function analysis result.")

        usage = getattr(response, "usage", None)
        request = AIRequestMetadata(
            request_id=getattr(response, "id", str(uuid4())),
            provider="openai",
            model=self.config.model,
            timestamp=datetime.now(timezone.utc).isoformat(),
            task="function_analysis",
            function_address=context.function["address"],
            analysis_pass=analysis_pass,
            input_tokens=getattr(usage, "input_tokens", None) if usage else None,
            output_tokens=getattr(usage, "output_tokens", None) if usage else None,
            latency_ms=int((time.perf_counter() - start) * 1000),
            retry_count=retry_count,
            success=True,
        )
        return AIProviderResponse(result=parsed, request=request)

    def model_info(self) -> dict:
        return {"provider": "openai", "model": self.config.model}


def _estimate_tokens(text: str) -> int:
    return max(1, len(text) // 4)


def _snake(value: str) -> str:
    import re

    text = re.sub(r"[^A-Za-z0-9]+", "_", value).strip("_").lower()
    return text or "unknown"
