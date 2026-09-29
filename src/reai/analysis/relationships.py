from __future__ import annotations

import hashlib
import json

from reai.analysis.schemas import RelationshipType, SemanticProvenance, SemanticRelationship
from reai.storage.repository import AnalysisRepository


def build_semantic_relationships(repository: AnalysisRepository, sample_id: str) -> list[SemanticRelationship]:
    relationships: dict[str, SemanticRelationship] = {}
    for row in repository.list_function_calls(sample_id):
        _add(
            relationships,
            row["caller"],
            row["callee"],
            RelationshipType.CALLS,
            0.98,
            [{"source": "IDA_OBSERVED", "description": "Direct call graph edge.", "address": row.get("source_address")}],
            SemanticProvenance.IDA_OBSERVED,
        )
        _add(
            relationships,
            row["callee"],
            row["caller"],
            RelationshipType.CALLED_BY,
            0.98,
            [{"source": "IDA_OBSERVED", "description": "Reverse call graph edge.", "address": row.get("source_address")}],
            SemanticProvenance.IDA_OBSERVED,
        )

    records = repository.build_relationship_source_records(sample_id)
    for row in records["imports"]:
        target = f"import:{row.get('module') or ''}!{row.get('name') or row.get('import_address')}"
        _add(
            relationships,
            row["function_address"],
            target,
            RelationshipType.USES_IMPORT,
            0.96,
            [{"source": "IDA_OBSERVED", "description": "Import referenced by function.", "address": row.get("source_address")}],
            SemanticProvenance.IDA_OBSERVED,
        )
    for row in records["strings"]:
        target = f"string:{row['string_address']}"
        _add(
            relationships,
            row["function_address"],
            target,
            RelationshipType.REFERENCES_STRING,
            0.9,
            [{"source": "IDA_OBSERVED", "description": "String referenced by function.", "value": row.get("value")}],
            SemanticProvenance.IDA_OBSERVED,
        )
    for row in records["globals"]:
        target = f"global:{row['global_address']}"
        _add(
            relationships,
            row["function_address"],
            target,
            RelationshipType.REFERENCES_GLOBAL,
            0.9,
            [{"source": "IDA_OBSERVED", "description": "Global referenced by function.", "address": row.get("source_address")}],
            SemanticProvenance.IDA_OBSERVED,
        )
    for row in repository.get_mcp_evidence_rows(sample_id):
        if row.get("value"):
            _add(
                relationships,
                row["function_address"],
                f"mcp:{row['capability']}:{row['target']}",
                RelationshipType.RELATED_ARTIFACT,
                0.72,
                [{"source": row["source"], "description": row["description"], "address": row.get("address")}],
                SemanticProvenance.MCP_OBSERVED,
            )
    return list(relationships.values())


def _add(
    relationships: dict[str, SemanticRelationship],
    source: str,
    target: str,
    relationship_type: RelationshipType,
    confidence: float,
    evidence: list[dict],
    provenance: SemanticProvenance,
) -> None:
    payload = f"{source}|{target}|{relationship_type.value}"
    relationship_id = "rel_" + hashlib.sha1(payload.encode("utf-8")).hexdigest()[:16]
    if relationship_id not in relationships:
        relationships[relationship_id] = SemanticRelationship(
            relationship_id=relationship_id,
            source_entity=source,
            target_entity=target,
            relationship_type=relationship_type,
            confidence=confidence,
            evidence=evidence,
            provenance=provenance,
        )
    else:
        existing = relationships[relationship_id]
        existing.evidence.extend(evidence)
        existing.evidence = _dedupe_evidence(existing.evidence)
        existing.confidence = max(existing.confidence, confidence)


def _dedupe_evidence(items: list[dict]) -> list[dict]:
    seen = set()
    deduped = []
    for item in items:
        key = json.dumps(item, sort_keys=True)
        if key not in seen:
            seen.add(key)
            deduped.append(item)
    return deduped

