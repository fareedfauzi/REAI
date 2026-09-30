from __future__ import annotations

from reai.analysis.schemas import ValidatedAnalysisModel
from reai.extraction.serialization import write_json
from reai.reporting.findings import write_semantic_findings
from reai.utils.paths import WorkspacePaths


def export_validated_analysis(workspace: WorkspacePaths, model: ValidatedAnalysisModel) -> None:
    write_json(workspace.analysis / "validated_analysis.json", model)
    write_json(workspace.analysis / "semantic_relationships.json", {"relationships": model.relationships})
    write_json(workspace.analysis / "subsystems.json", {"subsystems": model.subsystems})
    write_json(workspace.analysis / "capabilities.json", {"capabilities": model.capabilities})
    write_json(workspace.analysis / "validated_artifacts.json", {"artifacts": model.validated_artifacts})
    write_json(workspace.analysis / "iocs.json", {"iocs": [item for item in model.validated_artifacts if item.is_ioc]})
    write_json(workspace.analysis / "recovered_structures.json", {"structures": model.recovered_structures})
    write_json(workspace.analysis / "execution_flows.json", {"flows": model.execution_flows})
    write_json(workspace.analysis / "contradictions.json", {"contradictions": model.contradictions})
    write_json(workspace.analysis / "change_candidates.json", {"changes": model.change_candidates})
    write_json(workspace.analysis / "propagation.json", {"passes": model.propagation_passes})
    write_semantic_findings(workspace, model)
