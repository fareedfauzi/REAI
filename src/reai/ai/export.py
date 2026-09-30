from __future__ import annotations

import json

from reai.ai.schemas import AIAnalysisStats
from reai.extraction.serialization import write_json
from reai.reporting.findings import write_ai_findings
from reai.storage.repository import AnalysisRepository
from reai.utils.paths import WorkspacePaths


def export_ai_artifacts(repository: AnalysisRepository, sample_id: str, workspace: WorkspacePaths, stats: AIAnalysisStats) -> None:
    rows = repository.get_ai_analysis_rows(sample_id)
    function_analysis = []
    findings = []
    for row in rows:
        result = json.loads(row["result_json"])
        function_analysis.append(result)
        findings.append(
            {
                "address": row["address"],
                "original_name": row["original_name"],
                "proposed_name": row["proposed_name"],
                "summary": row["summary"],
                "confidence": row["confidence"],
                "confidence_label": row["confidence_label"],
                "needs_investigation": bool(row["needs_investigation"]),
                "evidence": result.get("evidence", []),
                "unknowns": result.get("unknowns", []),
            }
        )

    write_json(workspace.analysis / "function_analysis.json", {"functions": function_analysis, "stats": stats})
    write_json(workspace.analysis / "findings.json", {"findings": findings})
    write_json(workspace.analysis / "artifact_candidates.json", {"artifacts": repository.get_ai_artifact_rows(sample_id)})
    write_json(workspace.analysis / "ai_usage.json", {"requests": repository.get_ai_request_rows(sample_id), "stats": stats})
    write_ai_findings(workspace, repository, sample_id, stats)
