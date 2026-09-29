from __future__ import annotations

import json

from reai.enrichment.schemas import EnrichmentRun, EnrichmentStats
from reai.extraction.serialization import atomic_write_text
from reai.storage.repository import AnalysisRepository
from reai.utils.paths import WorkspacePaths


def export_changes(
    workspace: WorkspacePaths,
    repository: AnalysisRepository,
    sample_id: str,
    run: EnrichmentRun,
    stats: EnrichmentStats,
) -> None:
    payload = {
        "schema": "phase6-idb-enrichment-v1",
        "sample_id": sample_id,
        "run": run.model_dump(mode="json"),
        "stats": stats.model_dump(mode="json"),
        "changes": repository.get_idb_change_rows(sample_id, run.run_id),
        "verification": repository.get_idb_verification_rows(sample_id, run.run_id),
    }
    path = workspace.analysis / "changes.json"
    atomic_write_text(path, json.dumps(payload, indent=2, sort_keys=True) + "\n")
