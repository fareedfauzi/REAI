from __future__ import annotations

import re


SECRET_PATTERNS = [
    re.compile(r"sk-[A-Za-z0-9_-]{12,}"),
    re.compile(r"(api[-_]?key\s*[=:]\s*)['\"]?[^'\"\s]+", re.IGNORECASE),
    re.compile(r"(authorization\s*:\s*bearer\s+)[A-Za-z0-9._-]+", re.IGNORECASE),
]


def redact_secrets(value: object) -> str:
    text = str(value)
    for pattern in SECRET_PATTERNS:
        if pattern.pattern.startswith("(api"):
            text = pattern.sub(r"\1<redacted>", text)
        elif pattern.pattern.startswith("(authorization"):
            text = pattern.sub(r"\1<redacted>", text)
        else:
            text = pattern.sub("sk-<redacted>", text)
    return text
