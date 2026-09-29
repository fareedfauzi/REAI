from __future__ import annotations

import hashlib
import re

from reai.analysis.schemas import CurrentFunctionFinding, RecoveredStructure, RecoveredStructureField

OFFSET_RE = re.compile(r"(?:\+|offset\s+)(0x[0-9a-fA-F]+|\d+)")


def recover_structures(findings: list[CurrentFunctionFinding]) -> list[RecoveredStructure]:
    fields: dict[str, RecoveredStructureField] = {}
    evidence: list[dict] = []
    for finding in findings:
        text_items = [finding.summary or "", *finding.behavior]
        text_items.extend(str(item.get("evidence", "")) for item in finding.types)
        text_items.extend(str(item.get("description", "")) for item in finding.evidence)
        text = " ".join(text_items).lower()
        if "config" not in text and "c2" not in text:
            continue
        for match in OFFSET_RE.finditer(text):
            offset = _normalize_offset(match.group(1))
            context = text[max(0, match.start() - 80) : match.end() + 80]
            field_name, field_type = _field_for_context(offset, context)
            if field_name is None:
                continue
            item = fields.get(offset)
            field_evidence = {"source": "AI_DERIVED", "description": f"Offset {offset} associated with {field_name}.", "function": finding.address}
            if item is None:
                fields[offset] = RecoveredStructureField(
                    offset=offset,
                    name=field_name,
                    field_type=field_type,
                    confidence=min(finding.confidence, 0.88),
                    evidence=[field_evidence],
                    eligible_for_idb=False,
                )
            else:
                item.evidence.append(field_evidence)
                item.confidence = min(0.95, max(item.confidence, finding.confidence) + 0.04)
            evidence.append(field_evidence)
    if len(fields) < 2:
        return []
    ordered = sorted(fields.values(), key=lambda field: int(field.offset, 16))
    for field in ordered:
        field.eligible_for_idb = field.confidence >= 0.9 and len(field.evidence) >= 2
    structure_id = "struct_" + hashlib.sha1("configuration_t".encode("utf-8")).hexdigest()[:8]
    confidence = round(min(0.95, sum(field.confidence for field in ordered) / len(ordered)), 4)
    return [
        RecoveredStructure(
            structure_id=structure_id,
            name="configuration_t",
            confidence=confidence,
            size=max(int(field.offset, 16) for field in ordered) + 8,
            fields=ordered,
            evidence=evidence,
            eligible_for_idb=confidence >= 0.9 and all(field.eligible_for_idb for field in ordered),
        )
    ]


def _normalize_offset(value: str) -> str:
    return f"0x{int(value, 16 if value.lower().startswith('0x') else 10):x}"


def _field_for_context(offset: str, text: str) -> tuple[str | None, str | None]:
    if "domain" in text or "winhttpconnect" in text or "c2" in text:
        if offset in {"0x10", "0x20"}:
            return "c2_domain", "char *"
    if "port" in text:
        return "c2_port", "uint32_t"
    if "campaign" in text:
        return "campaign_id", "char *"
    if "sleep" in text or "interval" in text:
        return "sleep_interval", "uint32_t"
    return None, None
