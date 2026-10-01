from __future__ import annotations

import hashlib
import json
import re
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from threading import Lock
from typing import Callable
from uuid import uuid4

from reai.ai.client import AIClient, create_ai_client
from reai.ai.confidence import calibrate_confidence
from reai.ai.context import FunctionContextBuilder
from reai.ai.export import export_ai_artifacts
from reai.ai.ordering import build_bottom_up_groups, include_target_callees, select_target_addresses
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
    def __init__(
        self,
        config: AIConfig,
        repository: AnalysisRepository,
        workspace: WorkspacePaths,
        *,
        progress_callback: Callable[[str], None] | None = None,
    ) -> None:
        self.config = config
        self.repository = repository
        self.workspace = workspace
        self.progress_callback = progress_callback
        self._progress_lock = Lock()
        self._rate_limit_lock = Lock()
        self._rate_limit_until = 0.0
        self.context_builder = FunctionContextBuilder(
            repository,
            workspace,
        )

    def run(self, sample_id: str) -> AIAnalysisStats | None:
        self._progress("creating AI client")
        client = create_ai_client(self.config)
        if client is None:
            self._progress("AI provider disabled; skipping")
            return None

        self._progress("selecting target functions")
        target_rows = self.repository.list_ai_targets(sample_id)
        all_target_addresses = select_target_addresses(target_rows)
        seed_addresses = select_target_addresses(target_rows, max_functions=self.config.max_functions)
        self._progress("loading call graph order")
        calls = self.repository.list_function_calls(sample_id)
        target_addresses = include_target_callees(seed_addresses, all_target_addresses, calls)
        if len(target_addresses) > len(seed_addresses):
            self._progress(
                f"selected {len(seed_addresses)} seed functions plus "
                f"{len(target_addresses) - len(seed_addresses)} target callee dependencies"
            )
        else:
            self._progress(f"selected {len(target_addresses)} target functions")
        target_by_address = {row["address"]: row for row in target_rows if row["address"] in target_addresses}
        components = self.repository.list_callgraph_components(sample_id)
        groups = build_bottom_up_groups(target_addresses, calls, components)
        context_truncated = 0
        worker_count = max(1, int(self.config.max_concurrent_requests or 1))
        if worker_count > 1:
            self._progress(f"using up to {worker_count} concurrent AI requests per dependency group")

        analyzed_index = 0
        for group in groups:
            pending = []
            for address in group:
                analyzed_index += 1
                existing = self.repository.get_function_ai_analysis(sample_id, address)
                if existing and existing["status"] == "COMPLETED":
                    self._progress(f"skipping already analyzed function {analyzed_index}/{len(target_addresses)}: {address}")
                    continue
                function_row = target_by_address[address]
                self._progress(
                    f"queueing function {analyzed_index}/{len(target_addresses)}: "
                    f"{function_row['name']} ({address})"
                )
                context = self.context_builder.build(sample_id, address)
                if context.context_truncated:
                    context_truncated += 1
                pending.append((analyzed_index, function_row, context))

            if not pending:
                continue
            if worker_count == 1 or len(pending) == 1:
                for index, function_row, context in pending:
                    self._progress(
                        f"analyzing function {index}/{len(target_addresses)}: "
                        f"{function_row['name']} ({function_row['address']})"
                    )
                    self._analyze_one(sample_id, function_row, context, client)
                continue

            self._progress(f"analyzing {len(pending)} functions concurrently")
            with ThreadPoolExecutor(max_workers=min(worker_count, len(pending))) as executor:
                futures = {
                    executor.submit(self._analyze_one, sample_id, function_row, context, client): (index, function_row)
                    for index, function_row, context in pending
                }
                for future in as_completed(futures):
                    index, function_row = futures[future]
                    future.result()
                    self._progress(
                        f"completed function {index}/{len(target_addresses)}: "
                        f"{function_row['name']} ({function_row['address']})"
                    )

        self._progress("exporting AI findings")
        stats = self.repository.calculate_ai_stats(sample_id, target_count=len(target_addresses))
        stats.context_truncated = context_truncated
        export_ai_artifacts(self.repository, sample_id, self.workspace, stats)
        self._progress("AI function analysis complete")
        return stats

    def run_batched(self, sample_id: str, *, batch_size: int = 5, max_workers: int = 2) -> AIAnalysisStats | None:
        self._progress("creating AI client")
        client = create_ai_client(self.config)
        if client is None:
            self._progress("AI provider disabled; skipping")
            return None

        self._progress("selecting target functions")
        target_rows = self.repository.list_ai_targets(sample_id)
        all_target_addresses = select_target_addresses(target_rows)
        seed_addresses = select_target_addresses(target_rows, max_functions=self.config.max_functions)
        self._progress("loading call graph order")
        calls = self.repository.list_function_calls(sample_id)
        target_addresses = include_target_callees(seed_addresses, all_target_addresses, calls)
        if len(target_addresses) > len(seed_addresses):
            self._progress(
                f"selected {len(seed_addresses)} seed functions plus "
                f"{len(target_addresses) - len(seed_addresses)} target callee dependencies"
            )
        else:
            self._progress(f"selected {len(target_addresses)} target functions")
        target_by_address = {row["address"]: row for row in target_rows if row["address"] in target_addresses}
        components = self.repository.list_callgraph_components(sample_id)
        groups = build_bottom_up_groups(target_addresses, calls, components)
        context_truncated = 0
        batch_size = max(1, int(batch_size))
        worker_count = max(1, int(max_workers))
        self._progress(f"using AI batches of up to {batch_size} functions with {worker_count} concurrent batch workers")

        analyzed_index = 0
        for group in groups:
            pending = []
            for address in group:
                analyzed_index += 1
                existing = self.repository.get_function_ai_analysis(sample_id, address)
                if existing and existing["status"] == "COMPLETED":
                    self._progress(f"skipping already analyzed function {analyzed_index}/{len(target_addresses)}: {address}")
                    continue
                function_row = target_by_address[address]
                self._progress(
                    f"queueing function {analyzed_index}/{len(target_addresses)} for batch analysis: "
                    f"{function_row['name']} ({address})"
                )
                context = self.context_builder.build(sample_id, address)
                if context.context_truncated:
                    context_truncated += 1
                pending.append((analyzed_index, function_row, context))

            if not pending:
                continue

            batches = list(_chunks(pending, batch_size))
            if worker_count == 1 or len(batches) == 1:
                for batch_number, batch in enumerate(batches, start=1):
                    self._progress(_batch_progress_message(batch, batch_number, len(batches)))
                    self._analyze_batch(sample_id, batch, client)
                continue

            self._progress(f"analyzing {len(batches)} batches concurrently")
            with ThreadPoolExecutor(max_workers=min(worker_count, len(batches))) as executor:
                futures = {
                    executor.submit(self._analyze_batch, sample_id, batch, client): (batch_number, batch)
                    for batch_number, batch in enumerate(batches, start=1)
                }
                for future in as_completed(futures):
                    batch_number, batch = futures[future]
                    future.result()
                    self._progress(
                        f"completed batch {batch_number}/{len(batches)} "
                        f"({len(batch)} functions)"
                    )

        self._progress("exporting AI findings")
        stats = self.repository.calculate_ai_stats(sample_id, target_count=len(target_addresses))
        stats.context_truncated = context_truncated
        export_ai_artifacts(self.repository, sample_id, self.workspace, stats)
        self._progress("AI function analysis complete")
        return stats

    def _analyze_one(self, sample_id: str, function_row: dict, context, client: AIClient) -> None:
        address = function_row["address"]
        original_name = function_row["name"]
        fingerprint = _fingerprint_context(context)
        last_error: Exception | None = None
        for retry in range(self.config.max_retries + 1):
            try:
                self._wait_for_rate_limit_window(address)
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
                    retry_class = classify_exception(exc)
                    if retry_class == RetryClass.RATE_LIMITED:
                        backoff = self._rate_limit_delay_seconds(exc)
                        self._set_rate_limit_window(backoff)
                        self._progress(
                            f"rate limited while analyzing {address}; "
                            f"waiting {int(backoff)}s before retry {retry + 1}/{self.config.max_retries}"
                        )
                    else:
                        # Exponential backoff: 2**retry seconds, capped at 64s.
                        backoff = min(64, 2 ** retry)
                        self._progress(f"retrying {address} after provider error ({retry + 1}/{self.config.max_retries})")
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

    def _analyze_batch(self, sample_id: str, batch: list[tuple[int, dict, object]], client: AIClient) -> None:
        contexts = [context for _, _, context in batch]
        addresses = [function_row["address"] for _, function_row, _ in batch]
        batch_label = f"{addresses[0]}..{addresses[-1]}" if len(addresses) > 1 else addresses[0]
        fingerprints = {
            function_row["address"]: _fingerprint_context(context)
            for _, function_row, context in batch
        }
        last_error: Exception | None = None
        for retry in range(self.config.max_retries + 1):
            try:
                self._wait_for_rate_limit_window(f"batch {batch_label}")
                response = client.analyze_functions(contexts, analysis_pass=1, retry_count=retry)
                self.repository.persist_ai_request(sample_id, response.request)
                results_by_address = {result.address: result for result in response.results}
                for _, function_row, context in batch:
                    address = function_row["address"]
                    result = results_by_address.get(address)
                    if result is None:
                        self._persist_failure(
                            sample_id,
                            function_row,
                            fingerprints[address],
                            AIProviderError(f"Batch response did not include result for {address}."),
                        )
                        continue
                    result.address = address
                    calibrated = calibrate_confidence(
                        result,
                        decompilation_failed=context.function.get("decompilation_status") == "failed",
                    )
                    self.repository.persist_ai_analysis(
                        sample_id,
                        function_row["name"],
                        calibrated,
                        status="COMPLETED",
                        prompt_version=self.config.prompt_version,
                        schema_version=self.config.schema_version,
                        confidence_policy_version=self.config.confidence_policy_version,
                        context_builder_version=self.config.context_builder_version,
                        analysis_fingerprint=fingerprints[address],
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
                            task="function_analysis_batch",
                            function_address=None,
                            analysis_pass=1,
                            retry_count=retry,
                            success=False,
                            error=_safe_error(exc),
                        ),
                    )
                except Exception:
                    pass
                if classify_exception(exc) == RetryClass.AUTHENTICATION:
                    raise AIProviderError(_safe_error(exc)) from exc
                if retry < self.config.max_retries:
                    retry_class = classify_exception(exc)
                    if retry_class == RetryClass.RATE_LIMITED:
                        backoff = self._rate_limit_delay_seconds(exc)
                        self._set_rate_limit_window(backoff)
                        self._progress(
                            f"rate limited while analyzing batch {batch_label}; "
                            f"waiting {int(backoff)}s before retry {retry + 1}/{self.config.max_retries}"
                        )
                    else:
                        backoff = min(64, 2 ** retry)
                        self._progress(
                            f"retrying batch {batch_label} after provider error "
                            f"({retry + 1}/{self.config.max_retries})"
                        )
                    time.sleep(backoff)

        for _, function_row, _ in batch:
            self._persist_failure(
                sample_id,
                function_row,
                fingerprints[function_row["address"]],
                last_error,
            )

    def _persist_failure(self, sample_id: str, function_row: dict, fingerprint: str, error: Exception | None) -> None:
        address = function_row["address"]
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
                    value=type(error).__name__ if error else "unknown",
                    address=address,
                    description=_safe_error(error) if error else "Unknown AI analysis failure.",
                    source=EvidenceSource.AI_DERIVED,
                )
            ],
            variables=[],
            types=[],
            capabilities=["unknown"],
            artifacts=[],
            unknowns=[_safe_error(error) if error else "AI analysis failed."],
            reasoning_summary="AI analysis failed; no semantic conclusion was stored.",
            analysis_pass=1,
            needs_investigation=True,
        )
        self.repository.persist_ai_analysis(
            sample_id,
            function_row["name"],
            failure,
            status="FAILED",
            prompt_version=self.config.prompt_version,
            schema_version=self.config.schema_version,
            confidence_policy_version=self.config.confidence_policy_version,
            context_builder_version=self.config.context_builder_version,
            analysis_fingerprint=fingerprint,
        )

    def _progress(self, message: str) -> None:
        if self.progress_callback is not None:
            with self._progress_lock:
                self.progress_callback(message)

    def _wait_for_rate_limit_window(self, address: str) -> None:
        while True:
            with self._rate_limit_lock:
                delay = max(0.0, self._rate_limit_until - time.monotonic())
            if delay <= 0:
                return
            self._progress(f"waiting {int(delay)}s for AI rate-limit cooldown before {address}")
            time.sleep(min(delay, 30.0))

    def _set_rate_limit_window(self, delay_seconds: float) -> None:
        until = time.monotonic() + max(1.0, delay_seconds)
        with self._rate_limit_lock:
            self._rate_limit_until = max(self._rate_limit_until, until)

    def _rate_limit_delay_seconds(self, exc: Exception) -> float:
        provider_delay = extract_retry_after_seconds(exc)
        if provider_delay is not None:
            return provider_delay
        return float(self.config.rate_limit_cooldown_seconds)


def _fingerprint_context(context) -> str:
    prompt = build_function_prompt(context)
    return hashlib.sha256(prompt.encode("utf-8")).hexdigest()


def _chunks(items: list, size: int) -> list[list]:
    return [items[index : index + size] for index in range(0, len(items), size)]


def _batch_progress_message(batch: list[tuple[int, dict, object]], batch_number: int, total_batches: int) -> str:
    first_index = batch[0][0]
    last_index = batch[-1][0]
    return f"analyzing batch {batch_number}/{total_batches}: functions {first_index}-{last_index} ({len(batch)} functions)"


def _safe_error(error: Exception | None) -> str:
    if error is None:
        return "Unknown error."
    message = str(error)
    return message[:1000] if message else type(error).__name__


def extract_retry_after_seconds(error: Exception) -> float | None:
    cause = getattr(error, "__cause__", None)
    if isinstance(cause, Exception):
        parsed = extract_retry_after_seconds(cause)
        if parsed is not None:
            return parsed

    direct = getattr(error, "retry_after", None)
    parsed = _coerce_retry_after(direct)
    if parsed is not None:
        return parsed

    response = getattr(error, "response", None)
    headers = getattr(response, "headers", None) if response is not None else None
    parsed = _retry_after_from_headers(headers)
    if parsed is not None:
        return parsed

    headers = getattr(error, "headers", None)
    parsed = _retry_after_from_headers(headers)
    if parsed is not None:
        return parsed

    match = re.search(r"retry(?:\s|-)?after[^\d]*(\d+(?:\.\d+)?)", str(error), flags=re.IGNORECASE)
    if match:
        return max(1.0, float(match.group(1)))
    return None


def _retry_after_from_headers(headers) -> float | None:
    if not headers:
        return None
    for key in ("retry-after", "Retry-After", "x-ratelimit-reset-after", "X-RateLimit-Reset-After"):
        try:
            value = headers.get(key)
        except AttributeError:
            value = headers[key] if key in headers else None
        parsed = _coerce_retry_after(value)
        if parsed is not None:
            return parsed
    return None


def _coerce_retry_after(value) -> float | None:
    if value is None:
        return None
    try:
        return max(1.0, float(value))
    except (TypeError, ValueError):
        return None
