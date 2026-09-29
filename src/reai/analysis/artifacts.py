from __future__ import annotations

import hashlib
import re
from urllib.parse import urlparse

from reai.analysis.schemas import CurrentFunctionFinding, ValidatedArtifact

DOMAIN_RE = re.compile(r"(?i)^(?:[a-z0-9-]+\.)+[a-z]{2,}$")
IP_RE = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")
GENERIC_PATHS = {"c:\\windows\\system32", "c:/windows/system32", "c:\\windows", "c:/windows"}


def validate_artifacts(findings: list[CurrentFunctionFinding]) -> list[ValidatedArtifact]:
    artifacts: dict[str, ValidatedArtifact] = {}
    for finding in findings:
        candidates = list(finding.artifacts)
        for evidence in finding.evidence:
            value = evidence.get("value")
            if isinstance(value, str) and _looks_artifact_like(value):
                candidates.append({"value": value, "type": _classify_value(value), "address": evidence.get("address"), "usage": evidence.get("description"), "confidence": finding.confidence})
        for candidate in candidates:
            value = str(candidate.get("value") or "").strip()
            if not value:
                continue
            normalized = _normalize(value)
            artifact_type = str(candidate.get("type") or _classify_value(value)).lower()
            if normalized.lower() in GENERIC_PATHS:
                continue
            context = _context_role(finding, value, artifact_type)
            if context is None:
                continue
            role, usage, is_ioc, context_bonus = context
            confidence = round(min(float(candidate.get("confidence") or finding.confidence) + context_bonus, 0.97), 4)
            artifact_id = "artifact_" + hashlib.sha1(f"{artifact_type}|{normalized}|{finding.address}".encode("utf-8")).hexdigest()[:16]
            artifacts[artifact_id] = ValidatedArtifact(
                artifact_id=artifact_id,
                original_value=value,
                normalized_value=normalized,
                artifact_type=artifact_type,
                role=role,
                function_address=finding.address,
                address=candidate.get("address"),
                usage=str(candidate.get("usage") or usage),
                confidence=confidence,
                is_ioc=is_ioc,
                evidence=[
                    {"source": "IDA_OBSERVED", "description": "Artifact candidate observed in static context.", "value": value},
                    {"source": "AI_DERIVED", "description": f"Function context supports role: {role}.", "function": finding.address},
                ],
            )
    return list(artifacts.values())


def _looks_artifact_like(value: str) -> bool:
    return bool(value.startswith(("http://", "https://")) or DOMAIN_RE.match(value) or IP_RE.match(value) or "\\" in value or "/" in value)


def _classify_value(value: str) -> str:
    parsed = urlparse(value)
    if parsed.scheme in {"http", "https"} and parsed.netloc:
        return "url"
    if IP_RE.match(value):
        return "ip"
    if DOMAIN_RE.match(value):
        return "domain"
    if value.lower().startswith(("hkcu\\", "hklm\\", "registry:")):
        return "registry_path"
    if "\\" in value or "/" in value:
        return "file_path"
    return "artifact"


def _normalize(value: str) -> str:
    parsed = urlparse(value)
    if parsed.scheme and parsed.netloc:
        return parsed._replace(scheme=parsed.scheme.lower(), netloc=parsed.netloc.lower()).geturl()
    return value.lower() if DOMAIN_RE.match(value) else value


def _context_role(finding: CurrentFunctionFinding, value: str, artifact_type: str) -> tuple[str, str, bool, float] | None:
    text = f"{finding.proposed_name or ''} {finding.summary or ''} {' '.join(finding.behavior)} {' '.join(finding.capabilities)}".lower()
    if artifact_type in {"domain", "url", "ip"} and any(word in text for word in ("c2", "beacon", "http", "network", "connect", "request")):
        return "c2", "Network/C2 function references this artifact.", True, 0.12
    if artifact_type == "registry_path" and any(word in text for word in ("persistence", "run", "registry", "startup")):
        return "persistence", "Persistence or registry function references this artifact.", False, 0.1
    if artifact_type == "file_path" and any(word in text for word in ("file", "download", "write", "path", "loader")):
        return "file_operation", "File operation function references this path.", False, 0.08
    if "mutex" in text:
        return "mutex", "Mutex-related function references this artifact.", True, 0.1
    return None

