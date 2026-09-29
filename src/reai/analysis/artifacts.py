from __future__ import annotations

import hashlib
import re
from urllib.parse import urlparse

from reai.analysis.schemas import CurrentFunctionFinding, ValidatedArtifact

DOMAIN_RE = re.compile(r"(?i)^(?:[a-z0-9-]+\.)+[a-z]{2,}$")
IP_RE = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")
GENERIC_PATHS = {"c:\\windows\\system32", "c:/windows/system32", "c:\\windows", "c:/windows"}


def validate_artifacts(
    findings: list[CurrentFunctionFinding],
    extracted_strings: list[dict] | None = None,
) -> list[ValidatedArtifact]:
    artifacts: dict[str, ValidatedArtifact] = {}
    finding_by_address = {finding.address: finding for finding in findings}

    for finding in findings:
        candidates = list(finding.artifacts)
        for evidence in finding.evidence:
            value = evidence.get("value")
            if isinstance(value, str) and _looks_artifact_like(value):
                candidates.append({
                    "value": value,
                    "type": _classify_value(value),
                    "address": evidence.get("address"),
                    "usage": evidence.get("description"),
                    "confidence": finding.confidence,
                })
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

    if extracted_strings:
        for s in extracted_strings:
            value = str(s.get("value") or "").strip()
            if not value or not _looks_artifact_like(value):
                continue
            normalized = _normalize(value)
            if normalized.lower() in GENERIC_PATHS:
                continue
            artifact_type = _classify_value(value)
            func_addr = s.get("function_address")
            finding = finding_by_address.get(func_addr) if func_addr else None
            context = _context_role(finding, value, artifact_type)
            if context is None:
                continue
            role, usage, is_ioc, context_bonus = context
            base_confidence = finding.confidence if finding else 0.85
            confidence = round(min(base_confidence + context_bonus, 0.97), 4)
            artifact_id = "artifact_" + hashlib.sha1(f"{artifact_type}|{normalized}|{func_addr or 'global'}".encode("utf-8")).hexdigest()[:16]
            if artifact_id not in artifacts:
                artifacts[artifact_id] = ValidatedArtifact(
                    artifact_id=artifact_id,
                    original_value=value,
                    normalized_value=normalized,
                    artifact_type=artifact_type,
                    role=role,
                    function_address=func_addr,
                    address=s.get("address"),
                    usage=usage,
                    confidence=confidence,
                    is_ioc=is_ioc,
                    evidence=[
                        {"source": "IDA_OBSERVED", "description": "String observed in binary static data.", "address": s.get("address"), "value": value},
                        *([{"source": "AI_DERIVED", "description": f"Function context supports role: {role}.", "function": func_addr}] if func_addr else []),
                    ],
                )

    return list(artifacts.values())


COMMON_LIBRARY_EXTENSIONS = {".dll", ".sys", ".drv", ".ocx", ".lib"}


def _looks_artifact_like(value: str) -> bool:
    val_lower = value.lower()
    if any(val_lower.endswith(ext) for ext in COMMON_LIBRARY_EXTENSIONS):
        return False
    return bool(
        value.startswith(("http://", "https://"))
        or DOMAIN_RE.match(value)
        or IP_RE.match(value)
        or val_lower.endswith(".pdb")
        or any(cmd in val_lower for cmd in ("cmd.exe", "powershell", "ping ", "del /f"))
        or value.startswith("Mozilla/")
        or "\\" in value
        or "/" in value
    )


def _classify_value(value: str) -> str:
    parsed = urlparse(value)
    if parsed.scheme in {"http", "https"} and parsed.netloc:
        return "url"
    if IP_RE.match(value):
        return "ip"
    val_lower = value.lower()
    if DOMAIN_RE.match(value) and not any(val_lower.endswith(ext) for ext in COMMON_LIBRARY_EXTENSIONS):
        return "domain"
    if val_lower.endswith(".pdb"):
        return "pdb_path"
    if any(cmd in val_lower for cmd in ("cmd.exe", "powershell", "ping ", "del /f")):
        return "command_line"
    if val_lower.startswith(("hkcu\\", "hklm\\", "registry:")):
        return "registry_path"
    if value.startswith("Mozilla/"):
        return "user_agent"
    if "\\" in value or "/" in value:
        return "file_path"
    return "artifact"


def _normalize(value: str) -> str:
    parsed = urlparse(value)
    if parsed.scheme and parsed.netloc:
        return parsed._replace(scheme=parsed.scheme.lower(), netloc=parsed.netloc.lower()).geturl()
    return value.lower() if DOMAIN_RE.match(value) else value


def _context_role(finding: CurrentFunctionFinding | None, value: str, artifact_type: str) -> tuple[str, str, bool, float] | None:
    text = ""
    if finding:
        text = f"{finding.proposed_name or ''} {finding.summary or ''} {' '.join(finding.behavior)} {' '.join(finding.capabilities)}".lower()

    if artifact_type in {"domain", "url", "ip"}:
        return "c2", "Network communication or download endpoint.", True, 0.12

    if artifact_type == "pdb_path" or value.lower().endswith(".pdb"):
        return "build_artifact", "Compiler PDB debug symbol path providing build context.", True, 0.15

    if artifact_type == "command_line" or any(cmd in value.lower() for cmd in ("cmd.exe", "powershell", "ping ", "del /f")):
        return "execution", "Execution or anti-forensic self-deletion command line.", True, 0.12

    if artifact_type == "file_path":
        val_lower = value.lower()
        if val_lower.endswith((".exe", ".dll", ".dat.exe")) or any(p in val_lower for p in ("users\\public", "\\temp\\", "\\appdata\\", "\\documents\\")):
            return "dropped_payload", "Dropped or staged payload file path.", True, 0.12
        if any(word in text for word in ("file", "download", "write", "path", "loader")):
            return "file_operation", "File operation function references this path.", False, 0.08
        return None

    if artifact_type == "registry_path" and any(word in text for word in ("persistence", "run", "registry", "startup")):
        return "persistence", "Persistence or registry function references this artifact.", False, 0.1

    if artifact_type == "user_agent" or value.startswith("Mozilla/"):
        return "user_agent", "HTTP User-Agent network header.", False, 0.08

    if "mutex" in text:
        return "mutex", "Mutex-related function references this artifact.", True, 0.1

    return None


