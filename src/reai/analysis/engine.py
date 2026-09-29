from __future__ import annotations

import hashlib
import json

from reai.analysis.artifacts import validate_artifacts
from reai.analysis.export import export_validated_analysis
from reai.analysis.findings import load_current_function_findings
from reai.analysis.flow import build_command_handlers, build_configuration_items, build_data_flows, build_execution_flows
from reai.analysis.propagation import run_context_propagation
from reai.analysis.relationships import build_semantic_relationships
from reai.analysis.schemas import SemanticAnalysisStats, ValidatedAnalysisModel
from reai.analysis.subsystems import discover_subsystems
from reai.analysis.types import recover_structures
from reai.analysis.validation import validate_semantics
from reai.core.config import AnalysisConfig
from reai.storage.repository import AnalysisRepository
from reai.utils.paths import WorkspacePaths


class MalwareUnderstandingEngine:
    def __init__(self, config: AnalysisConfig, repository: AnalysisRepository, workspace: WorkspacePaths) -> None:
        self.config = config
        self.repository = repository
        self.workspace = workspace

    def run(self, sample_id: str) -> SemanticAnalysisStats | None:
        if not self.config.enabled:
            return None
        findings = load_current_function_findings(self.repository, sample_id)
        if not findings:
            return None

        relationships = build_semantic_relationships(self.repository, sample_id)
        subsystems, capabilities = discover_subsystems(self.repository, sample_id, findings)
        propagated_findings, propagation_passes = run_context_propagation(
            self.repository,
            sample_id,
            findings,
            subsystems,
            max_passes=self.config.propagation.max_passes,
            minimum_context_change=self.config.propagation.minimum_context_change,
            minimum_confidence_delta=self.config.propagation.minimum_confidence_delta,
        )
        # Recluster after propagation because parent semantics may have improved.
        subsystems, capabilities = discover_subsystems(self.repository, sample_id, propagated_findings)
        extracted_strings = self.repository.list_strings_with_xrefs(sample_id)
        artifacts = validate_artifacts(propagated_findings, extracted_strings)
        structures = recover_structures(propagated_findings)
        execution_flows = build_execution_flows(self.repository, sample_id, propagated_findings, subsystems)
        data_flows = build_data_flows(artifacts)
        command_handlers = build_command_handlers(self.repository, sample_id, propagated_findings)
        configuration_items = build_configuration_items(artifacts)
        validation_results, change_candidates, contradictions = validate_semantics(
            propagated_findings,
            structures,
            self.config.validation,
        )
        fingerprint = _phase5_fingerprint(
            propagated_findings,
            relationships,
            artifacts,
            self.config.schema_version,
            self.config.taxonomy_version,
        )
        stats = SemanticAnalysisStats(
            functions_validated=len(propagated_findings),
            rename_candidates=sum(1 for item in change_candidates if item.change_type == "rename" and item.entity == "function"),
            comment_candidates=sum(1 for item in change_candidates if item.change_type == "comment"),
            variable_candidates=sum(1 for item in change_candidates if item.entity == "variable"),
            type_candidates=sum(1 for item in change_candidates if item.entity.startswith("structure")),
            subsystems=len(subsystems),
            capabilities=len(capabilities),
            recovered_structures=len(structures),
            recovered_fields=sum(len(item.fields) for item in structures),
            command_handlers=len(command_handlers),
            configuration_items=len(configuration_items),
            validated_artifacts=len(artifacts),
            validated_iocs=sum(1 for item in artifacts if item.is_ioc),
            contradictions=len(contradictions),
            unresolved_contradictions=sum(1 for item in contradictions if item.status == "OPEN"),
            propagation_passes=len(propagation_passes),
            semantic_relationships=len(relationships),
        )
        model = ValidatedAnalysisModel(
            fingerprint=fingerprint,
            functions=propagated_findings,
            relationships=relationships,
            subsystems=subsystems,
            execution_flows=execution_flows,
            data_flows=data_flows,
            recovered_structures=structures,
            validated_artifacts=artifacts,
            capabilities=capabilities,
            command_handlers=command_handlers,
            configuration_items=configuration_items,
            contradictions=contradictions,
            validation_results=validation_results,
            change_candidates=change_candidates,
            propagation_passes=propagation_passes,
            stats=stats,
        )
        self.repository.persist_validated_analysis(sample_id, model)
        export_validated_analysis(self.workspace, model)
        return stats


def _phase5_fingerprint(findings, relationships, artifacts, schema_version: str, taxonomy_version: str) -> str:
    payload = {
        "schema": schema_version,
        "taxonomy": taxonomy_version,
        "findings": [
            {
                "address": finding.address,
                "name": finding.proposed_name,
                "confidence": finding.confidence,
                "pass": finding.analysis_pass,
            }
            for finding in sorted(findings, key=lambda item: item.address)
        ],
        "relationships": sorted(item.relationship_id for item in relationships),
        "artifacts": sorted(item.artifact_id for item in artifacts),
    }
    return hashlib.sha256(json.dumps(payload, sort_keys=True).encode("utf-8")).hexdigest()
