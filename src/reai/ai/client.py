from __future__ import annotations

import json
import time
from datetime import datetime, timezone
from typing import Protocol
from uuid import uuid4

from reai.core.config import AIConfig
from reai.core.exceptions import AIProviderError
from reai.ai.prompts import SYSTEM_PROMPT, build_function_batch_prompt, build_function_prompt
from reai.ai.schemas import (
    AIProviderBatchResponse,
    AIProviderResponse,
    AIRequestMetadata,
    ConfidenceLabel,
    EvidenceItem,
    EvidenceSource,
    FunctionAnalysisBatchResult,
    FunctionAnalysisResult,
    FunctionContext,
)


class AIClient(Protocol):
    def analyze_function(self, context: FunctionContext, *, analysis_pass: int, retry_count: int = 0) -> AIProviderResponse:
        ...

    def analyze_functions(self, contexts: list[FunctionContext], *, analysis_pass: int, retry_count: int = 0) -> AIProviderBatchResponse:
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
    if provider == "anthropic":
        return AnthropicClient(config)
    if provider in {"openai-compatible", "lmstudio", "ollama", "hermes"}:
        return OpenAICompatibleClient(config)
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

    def analyze_functions(self, contexts: list[FunctionContext], *, analysis_pass: int, retry_count: int = 0) -> AIProviderBatchResponse:
        start = time.perf_counter()
        results = [
            self.analyze_function(context, analysis_pass=analysis_pass, retry_count=retry_count).result
            for context in contexts
        ]
        request = AIRequestMetadata(
            request_id=str(uuid4()),
            provider="mock",
            model=self.config.model or "mock-phase3",
            timestamp=datetime.now(timezone.utc).isoformat(),
            task="function_analysis_batch",
            function_address=None,
            analysis_pass=analysis_pass,
            input_tokens=_estimate_tokens(build_function_batch_prompt(contexts)),
            output_tokens=_estimate_tokens(json.dumps([result.model_dump(mode="json") for result in results])),
            latency_ms=int((time.perf_counter() - start) * 1000),
            retry_count=retry_count,
            success=True,
        )
        return AIProviderBatchResponse(results=results, request=request)

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
        if self.config.base_url:
            kwargs["base_url"] = self.config.base_url
        kwargs["timeout"] = self.config.timeout_seconds
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

    def analyze_functions(self, contexts: list[FunctionContext], *, analysis_pass: int, retry_count: int = 0) -> AIProviderBatchResponse:
        start = time.perf_counter()
        prompt = build_function_batch_prompt(contexts)
        try:
            response = self._client.responses.parse(
                model=self.config.model,
                instructions=SYSTEM_PROMPT,
                input=prompt,
                text_format=FunctionAnalysisBatchResult,
            )
        except Exception as exc:
            raise AIProviderError(f"OpenAI batch request failed:\n{exc}") from exc

        parsed = getattr(response, "output_parsed", None)
        if parsed is None:
            raise AIProviderError("OpenAI response did not contain a parsed function batch analysis result.")

        usage = getattr(response, "usage", None)
        request = AIRequestMetadata(
            request_id=getattr(response, "id", str(uuid4())),
            provider="openai",
            model=self.config.model,
            timestamp=datetime.now(timezone.utc).isoformat(),
            task="function_analysis_batch",
            function_address=None,
            analysis_pass=analysis_pass,
            input_tokens=getattr(usage, "input_tokens", None) if usage else None,
            output_tokens=getattr(usage, "output_tokens", None) if usage else None,
            latency_ms=int((time.perf_counter() - start) * 1000),
            retry_count=retry_count,
            success=True,
        )
        return AIProviderBatchResponse(results=parsed.results, request=request)

    def model_info(self) -> dict:
        return {"provider": "openai", "model": self.config.model}


class OpenAICompatibleClient:
    def __init__(self, config: AIConfig) -> None:
        self.config = config
        if not config.model:
            raise AIProviderError(f"{config.provider} provider requires [ai].model.")
        try:
            from openai import OpenAI
        except ImportError as exc:
            raise AIProviderError("OpenAI Python SDK is required for OpenAI-compatible providers.") from exc
        kwargs = {
            "base_url": _openai_compatible_base_url(config),
            "api_key": config.api_key or _default_local_api_key(config.provider),
            "timeout": config.timeout_seconds,
        }
        self._client = OpenAI(**kwargs)

    def analyze_function(self, context: FunctionContext, *, analysis_pass: int, retry_count: int = 0) -> AIProviderResponse:
        start = time.perf_counter()
        prompt = build_function_prompt(context)
        content = self._complete_json(prompt)
        response = content["response"]
        result = _parse_function_analysis(content["text"])
        usage = getattr(response, "usage", None)
        request = AIRequestMetadata(
            request_id=getattr(response, "id", str(uuid4())),
            provider=self.config.provider,
            model=self.config.model,
            timestamp=datetime.now(timezone.utc).isoformat(),
            task="function_analysis",
            function_address=context.function["address"],
            analysis_pass=analysis_pass,
            input_tokens=getattr(usage, "prompt_tokens", None) if usage else None,
            output_tokens=getattr(usage, "completion_tokens", None) if usage else None,
            latency_ms=int((time.perf_counter() - start) * 1000),
            retry_count=retry_count,
            success=True,
        )
        return AIProviderResponse(result=result, request=request)

    def analyze_functions(self, contexts: list[FunctionContext], *, analysis_pass: int, retry_count: int = 0) -> AIProviderBatchResponse:
        start = time.perf_counter()
        prompt = build_function_batch_prompt(contexts)
        content = self._complete_batch_json(prompt)
        response = content["response"]
        result = _parse_function_batch_analysis(content["text"])
        usage = getattr(response, "usage", None)
        request = AIRequestMetadata(
            request_id=getattr(response, "id", str(uuid4())),
            provider=self.config.provider,
            model=self.config.model,
            timestamp=datetime.now(timezone.utc).isoformat(),
            task="function_analysis_batch",
            function_address=None,
            analysis_pass=analysis_pass,
            input_tokens=getattr(usage, "prompt_tokens", None) if usage else None,
            output_tokens=getattr(usage, "completion_tokens", None) if usage else None,
            latency_ms=int((time.perf_counter() - start) * 1000),
            retry_count=retry_count,
            success=True,
        )
        return AIProviderBatchResponse(results=result.results, request=request)

    def model_info(self) -> dict:
        return {"provider": self.config.provider, "model": self.config.model, "base_url": _openai_compatible_base_url(self.config)}

    def _complete_json(self, prompt: str) -> dict:
        messages = [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": f"{prompt}\n\nReturn only one JSON object matching the requested schema."},
        ]
        schema = FunctionAnalysisResult.model_json_schema()
        try:
            response = self._client.chat.completions.create(
                model=self.config.model,
                messages=messages,
                temperature=0,
                response_format={
                    "type": "json_schema",
                    "json_schema": {
                        "name": "FunctionAnalysisResult",
                        "schema": schema,
                        "strict": False,
                    },
                },
            )
        except Exception:
            response = self._client.chat.completions.create(
                model=self.config.model,
                messages=messages,
                temperature=0,
                response_format={"type": "json_object"},
            )
        choice = response.choices[0]
        content = getattr(choice.message, "content", None)
        if not content:
            raise AIProviderError(f"{self.config.provider} returned an empty response.")
        return {"text": content, "response": response}

    def _complete_batch_json(self, prompt: str) -> dict:
        messages = [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": f"{prompt}\n\nReturn only one JSON object matching the requested batch schema."},
        ]
        schema = FunctionAnalysisBatchResult.model_json_schema()
        try:
            response = self._client.chat.completions.create(
                model=self.config.model,
                messages=messages,
                temperature=0,
                response_format={
                    "type": "json_schema",
                    "json_schema": {
                        "name": "FunctionAnalysisBatchResult",
                        "schema": schema,
                        "strict": False,
                    },
                },
            )
        except Exception:
            response = self._client.chat.completions.create(
                model=self.config.model,
                messages=messages,
                temperature=0,
                response_format={"type": "json_object"},
            )
        choice = response.choices[0]
        content = getattr(choice.message, "content", None)
        if not content:
            raise AIProviderError(f"{self.config.provider} returned an empty response.")
        return {"text": content, "response": response}


class AnthropicClient:
    def __init__(self, config: AIConfig) -> None:
        self.config = config
        if not config.model:
            raise AIProviderError("Anthropic provider requires [ai].model.")
        try:
            from anthropic import Anthropic
        except ImportError as exc:
            raise AIProviderError("Anthropic Python SDK is not installed.") from exc
        kwargs = {"timeout": config.timeout_seconds}
        if config.api_key:
            kwargs["api_key"] = config.api_key
        if config.base_url:
            kwargs["base_url"] = config.base_url
        self._client = Anthropic(**kwargs)

    def analyze_function(self, context: FunctionContext, *, analysis_pass: int, retry_count: int = 0) -> AIProviderResponse:
        start = time.perf_counter()
        prompt = build_function_prompt(context)
        try:
            response = self._client.messages.create(
                model=self.config.model,
                max_tokens=4096,
                temperature=0,
                system=SYSTEM_PROMPT,
                messages=[
                    {
                        "role": "user",
                        "content": f"{prompt}\n\nReturn only one JSON object matching the FunctionAnalysisResult schema.",
                    }
                ],
            )
        except Exception as exc:
            raise AIProviderError(f"Anthropic request failed:\n{exc}") from exc
        content = _anthropic_text(response)
        result = _parse_function_analysis(content)
        usage = getattr(response, "usage", None)
        request = AIRequestMetadata(
            request_id=getattr(response, "id", str(uuid4())),
            provider="anthropic",
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
        return AIProviderResponse(result=result, request=request)

    def analyze_functions(self, contexts: list[FunctionContext], *, analysis_pass: int, retry_count: int = 0) -> AIProviderBatchResponse:
        start = time.perf_counter()
        prompt = build_function_batch_prompt(contexts)
        try:
            response = self._client.messages.create(
                model=self.config.model,
                max_tokens=12000,
                temperature=0,
                system=SYSTEM_PROMPT,
                messages=[
                    {
                        "role": "user",
                        "content": f"{prompt}\n\nReturn only one JSON object matching the FunctionAnalysisBatchResult schema.",
                    }
                ],
            )
        except Exception as exc:
            raise AIProviderError(f"Anthropic batch request failed:\n{exc}") from exc
        content = _anthropic_text(response)
        result = _parse_function_batch_analysis(content)
        usage = getattr(response, "usage", None)
        request = AIRequestMetadata(
            request_id=getattr(response, "id", str(uuid4())),
            provider="anthropic",
            model=self.config.model,
            timestamp=datetime.now(timezone.utc).isoformat(),
            task="function_analysis_batch",
            function_address=None,
            analysis_pass=analysis_pass,
            input_tokens=getattr(usage, "input_tokens", None) if usage else None,
            output_tokens=getattr(usage, "output_tokens", None) if usage else None,
            latency_ms=int((time.perf_counter() - start) * 1000),
            retry_count=retry_count,
            success=True,
        )
        return AIProviderBatchResponse(results=result.results, request=request)

    def model_info(self) -> dict:
        return {"provider": "anthropic", "model": self.config.model}


def _estimate_tokens(text: str) -> int:
    return max(1, len(text) // 4)


def _openai_compatible_base_url(config: AIConfig) -> str:
    if config.base_url:
        return config.base_url
    defaults = {
        "lmstudio": "http://localhost:1234/v1",
        "ollama": "http://localhost:11434/v1",
        "hermes": "http://localhost:8080/v1",
    }
    if config.provider in defaults:
        return defaults[config.provider]
    raise AIProviderError("OpenAI-compatible provider requires [ai].base_url unless provider is lmstudio, ollama, or hermes.")


def _default_local_api_key(provider: str) -> str:
    return "ollama" if provider == "ollama" else "reai-local"


def _parse_function_analysis(content: str) -> FunctionAnalysisResult:
    try:
        return FunctionAnalysisResult.model_validate_json(content)
    except ValueError:
        start = content.find("{")
        end = content.rfind("}")
        if start == -1 or end == -1 or end <= start:
            raise AIProviderError("AI provider did not return a JSON object.")
        try:
            data = json.loads(content[start : end + 1])
            return FunctionAnalysisResult.model_validate(data)
        except ValueError as exc:
            raise AIProviderError(f"AI provider returned invalid function-analysis JSON:\n{exc}") from exc


def _parse_function_batch_analysis(content: str) -> FunctionAnalysisBatchResult:
    try:
        return FunctionAnalysisBatchResult.model_validate_json(content)
    except ValueError:
        start = content.find("{")
        end = content.rfind("}")
        if start == -1 or end == -1 or end <= start:
            raise AIProviderError("AI provider did not return a JSON object.")
        try:
            data = json.loads(content[start : end + 1])
            return FunctionAnalysisBatchResult.model_validate(data)
        except ValueError as exc:
            raise AIProviderError(f"AI provider returned invalid function batch-analysis JSON:\n{exc}") from exc


def _anthropic_text(response) -> str:
    chunks = []
    for block in getattr(response, "content", []) or []:
        text = getattr(block, "text", None)
        if text:
            chunks.append(text)
        elif isinstance(block, dict) and block.get("text"):
            chunks.append(str(block["text"]))
    text = "\n".join(chunks).strip()
    if not text:
        raise AIProviderError("Anthropic response did not contain text content.")
    return text


def _snake(value: str) -> str:
    import re

    text = re.sub(r"[^A-Za-z0-9]+", "_", value).strip("_").lower()
    return text or "unknown"
