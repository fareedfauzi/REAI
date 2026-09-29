from __future__ import annotations

import hashlib
import json
import time
from datetime import datetime, timezone
from uuid import uuid4

from reai.ai.client import AIClient, create_ai_client
from reai.ai.confidence import calibrate_confidence
from reai.ai.context import FunctionContextBuilder
from reai.ai.export import export_ai_artifacts
from reai.ai.ordering import build_bottom_up_groups, select_target_addresses
from reai.ai.prompts import build_function_prompt
from reai.ai.schemas import (
    AIAnalysisStats,
    AIProviderResponse,
    AIRequestMetadata,
    ConfidenceLabel,
    EvidenceItem,
    EvidenceSource,
    FunctionAnalysisResult,
)
from reai.core.config import AIConfig
from reai.core.exceptions import AIProviderError
from reai.storage.repository import AnalysisRepository
from reai.utils.paths import WorkspacePaths
from reai.utils.retry import RetryClass, classify_exception


class BottomUpAIAnalyzer:
    def __init__(self, config: AIConfig, repository: AnalysisRepository, workspace: WorkspacePaths) -> None:
        self.config = config
        self.repository = repository
        self.workspace = workspace
        self.context_builder = FunctionContextBuilder(
            repository,
            workspace,
        )

    def run(self, sample_id: str) -> AIAnalysisStats | None:
        client = create_ai_client(self.config)
        if client is None:
            return None

        target_rows = self.repository.list_ai_targets(sample_id)
        target_addresses = select_target_addresses(target_rows, max_functions=self.config.max_functions)
        target_by_address = {row["address"]: row for row in target_rows if row["address"] in target_addresses}
        calls = self.repository.list_function_calls(sample_id)
        components = self.repository.list_callgraph_components(sample_id)
        groups = build_bottom_up_groups(target_addresses, calls, components)
        context_truncated = 0

        for group in groups:
            for address in group:
                existing = self.repository.get_function_ai_analysis(sample_id, address)
                if existing and existing["status"] == "COMPLETED":
                    continue
                context = self.context_builder.build(sample_id, address)
                if context.context_truncated:
                    context_truncated += 1
                function_row = target_by_address[address]
                self._analyze_one(sample_id, function_row, context, client)

        stats = self.repository.calculate_ai_stats(sample_id, target_count=len(target_addresses))
        stats.context_truncated = context_truncated
        export_ai_artifacts(self.repository, sample_id, self.workspace, stats)
        return stats

    def _analyze_one(self, sample_id: str, function_row: dict, context, client: AIClient) -> None:
        address = function_row["address"]
        original_name = function_row["name"]
        fingerprint = _fingerprint_context(context)
        last_error: Exception | None = None
        for retry in range(self.config.max_retries + 1):
            try:
                response = client.analyze_function(context, analysis_pass=1, retry_count=retry)
                response.result.address = address
                self.repository.persist_ai_request(sample_id, response.request)
                calibrated = calibrate_confidence(
                    response.result,
                    decompilation_failed=context.function.get("decompilation_status") == "failed",
                )
                self.repository.persist_ai_analysis(
                    sample_id,
                    original_name,
                    calibrated,
                    status="COMPLETED",
                    prompt_version=self.config.prompt_version,
                    schema_version=self.config.schema_version,
                    confidence_policy_version=self.config.confidence_policy_version,
                    context_builder_version=self.config.context_builder_version,
                    analysis_fingerprint=fingerprint,
                )
                return
            except Exception as exc:
                last_error = exc
                try:
                    self.repository.persist_ai_request(
                        sample_id,
                        AIRequestMetadata(
                            request_id=str(uuid4()),
                            provider=self.config.provider,
                            model=self.config.model,
                            timestamp=datetime.now(timezone.utc).isoformat(),
                            task="function_analysis",
                            function_address=address,
                            analysis_pass=1,
                            retry_count=retry,
                            success=False,
                            error=_safe_error(exc),
                        ),
                    )
                except Exception:
                    pass  # Persistence failure must not abort the retry loop.
                if classify_exception(exc) == RetryClass.AUTHENTICATION:
                    raise AIProviderError(_safe_error(exc)) from exc
                if retry < self.config.max_retries:
                    # Exponential backoff: 2**retry seconds, capped at 64s.
                    backoff = min(64, 2 ** retry)
                    time.sleep(backoff)


        failure = FunctionAnalysisResult(
            address=address,
            proposed_name=None,
            summary="AI analysis failed; deterministic context remains available for future investigation.",
            behavior=[],
            confidence=0.0,
            confidence_label=ConfidenceLabel.LOW,
            evidence=[
                EvidenceItem(
                    type="analysis_failure",
                    value=type(last_error).__name__ if last_error else "unknown",
                    address=address,
                    description=_safe_error(last_error) if last_error else "Unknown AI analysis failure.",
                    source=EvidenceSource.AI_DERIVED,
                )
            ],
            variables=[],
            types=[],
            capabilities=["unknown"],
            artifacts=[],
            unknowns=[_safe_error(last_error) if last_error else "AI analysis failed."],
            reasoning_summary="AI analysis failed; no semantic conclusion was stored.",
            analysis_pass=1,
            needs_investigation=True,
        )
        self.repository.persist_ai_analysis(
            sample_id,
            original_name,
            failure,
            status="FAILED",
            prompt_version=self.config.prompt_version,
            schema_version=self.config.schema_version,
            confidence_policy_version=self.config.confidence_policy_version,
            context_builder_version=self.config.context_builder_version,
            analysis_fingerprint=fingerprint,
        )


def _fingerprint_context(context) -> str:
    prompt = build_function_prompt(context)
    return hashlib.sha256(prompt.encode("utf-8")).hexdigest()


def _safe_error(error: Exception | None) -> str:
    if error is None:
        return "Unknown error."
    message = str(error)
    return message[:1000] if message else type(error).__name__
