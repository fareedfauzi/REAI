from __future__ import annotations

from reai.extraction.serialization import write_json
from reai.mcp.schemas import MCPInvestigationStats
from reai.storage.repository import AnalysisRepository
from reai.utils.paths import WorkspacePaths


def export_mcp_artifacts(
    repository: AnalysisRepository,
    sample_id: str,
    workspace: WorkspacePaths,
    stats: MCPInvestigationStats,
) -> None:
    write_json(
        workspace.analysis / "mcp_investigations.json",
        {
            "investigations": repository.get_mcp_investigation_rows(sample_id),
            "stats": stats,
        },
    )
    write_json(
        workspace.analysis / "mcp_evidence.json",
        {"evidence": repository.get_mcp_evidence_rows(sample_id)},
    )
    write_json(
        workspace.analysis / "mcp_usage.json",
        {"calls": repository.get_mcp_call_rows(sample_id), "stats": stats},
    )

