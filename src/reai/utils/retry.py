from __future__ import annotations

import random
import time
from collections.abc import Callable
from dataclasses import dataclass
from enum import StrEnum
from typing import TypeVar


class RetryClass(StrEnum):
    TRANSIENT = "TRANSIENT"
    RATE_LIMITED = "RATE_LIMITED"
    PERMANENT = "PERMANENT"
    AUTHENTICATION = "AUTHENTICATION"
    RESOURCE_UNAVAILABLE = "RESOURCE_UNAVAILABLE"


@dataclass(frozen=True)
class RetryPolicy:
    attempts: int = 3
    initial_delay_seconds: float = 1.0
    max_delay_seconds: float = 8.0
    jitter_seconds: float = 0.25


T = TypeVar("T")


def classify_exception(exc: BaseException) -> RetryClass:
    text = str(exc).lower()
    name = exc.__class__.__name__.lower()
    if "auth" in text or "api key" in text or "permission" in text or "unauthorized" in text:
        return RetryClass.AUTHENTICATION
    if "rate" in text or "429" in text:
        return RetryClass.RATE_LIMITED
    if "timeout" in text or "temporar" in text or "connection" in text or "500" in text or "502" in text or "503" in text:
        return RetryClass.TRANSIENT
    if "unavailable" in text or "not found" in text or "missing" in text or "idaunavailable" in name:
        return RetryClass.RESOURCE_UNAVAILABLE
    return RetryClass.PERMANENT


def run_with_retry(
    operation: Callable[[], T],
    *,
    policy: RetryPolicy,
    classifier: Callable[[BaseException], RetryClass] = classify_exception,
    sleep: Callable[[float], None] = time.sleep,
) -> T:
    last_exc: BaseException | None = None
    for attempt in range(1, policy.attempts + 1):
        try:
            return operation()
        except BaseException as exc:
            last_exc = exc
            retry_class = classifier(exc)
            if retry_class in {RetryClass.PERMANENT, RetryClass.AUTHENTICATION, RetryClass.RESOURCE_UNAVAILABLE}:
                raise
            if attempt >= policy.attempts:
                raise
            delay = min(policy.max_delay_seconds, policy.initial_delay_seconds * (2 ** (attempt - 1)))
            if policy.jitter_seconds:
                delay += random.uniform(0, policy.jitter_seconds)
            sleep(delay)
    assert last_exc is not None
    raise last_exc
