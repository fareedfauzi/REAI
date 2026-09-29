from __future__ import annotations

import json
from uuid import uuid4

from reai.ai.confidence import calibrate_confidence
from reai.ai.export import export_ai_artifacts
from reai.ai.schemas import ConfidenceLabel, EvidenceItem, EvidenceSource, FunctionAnalysisResult
from reai.core.config import MCPConfig
from reai.mcp.client import MCPError, ReadOnlyMCPSession, create_mcp_client
from reai.mcp.export import export_mcp_artifacts
from reai.mcp.normalize import normalize_mcp_result
from reai.mcp.planner import InvestigationPlanner
from reai.mcp.schemas import (
    MCPCallStatus,
    MCPEvidence,
    MCPInvestigationStats,
    InvestigationOutcome,
    InvestigationStatus,
    InvestigationTarget,
)
from reai.storage.repository import AnalysisRepository
from reai.utils.paths import WorkspacePaths


class MCPInvestigator:
    def __init__(self, config: MCPConfig, repository: AnalysisRepository, workspace: WorkspacePaths) -> None:
        self.config = config
        self.repository = repository
        self.workspace = workspace
        self.planner = InvestigationPlanner()

    def run(self, sample_id: str) -> MCPInvestigationStats | None:
        client = create_mcp_client(self.config)
        if client is None:
            return None

        targets = self.repository.list_mcp_targets(sample_id, max_functions=self.config.max_functions)
        if not targets:
            stats = self.repository.calculate_mcp_stats(sample_id, candidate_count=0)
            export_mcp_artifacts(self.repository, sample_id, self.workspace, stats)
            return stats

        session = ReadOnlyMCPSession(
            client,
            allowlist=self.config.allowlist,
            timeout_seconds=self.config.timeout_seconds,
        )
        try:
            session.connect()
        except Exception:
            for target in targets:
                self.repository.start_mcp_investigation(target)
                self.repository.complete_mcp_investigation(
                    sample_id,
                    target.address,
                    outcome=InvestigationOutcome.MCP_UNAVAILABLE,
                    confidence_after=target.confidence,
                    interpretation_changed=False,
                    error="MCP session could not be started.",
                )
            stats = self.repository.calculate_mcp_stats(sample_id, candidate_count=len(targets))
            export_mcp_artifacts(self.repository, sample_id, self.workspace, stats)
            return stats

        try:
            for target in targets:
                existing = self.repository.get_mcp_investigation(sample_id, target.address)
                if existing and existing["status"] == InvestigationStatus.COMPLETED.value:
                    continue
                if self._total_budget_exhausted(sample_id):
                    break
                self._investigate_target(sample_id, target, session)
        finally:
            session.close()

        stats = self.repository.calculate_mcp_stats(sample_id, candidate_count=len(targets))
        export_mcp_artifacts(self.repository, sample_id, self.workspace, stats)
        ai_stats = self.repository.calculate_ai_stats(sample_id)
        export_ai_artifacts(self.repository, sample_id, self.workspace, ai_stats)
        return stats

    def _investigate_target(
        self,
        sample_id: str,
        target: InvestigationTarget,
        session: ReadOnlyMCPSession,
    ) -> None:
        self.repository.start_mcp_investigation(target)
        original_name = target.current_name
        initial_proposed = target.proposed_name
        current_confidence = target.confidence
        current_unknowns = list(target.unknowns)
        outcome = InvestigationOutcome.UNRESOLVED

        for _ in range(self.config.max_rounds_per_function):
            calls_used = self.repository.count_mcp_calls_for_function(sample_id, target.address)
            remaining_calls = self.config.max_tool_calls_per_function - calls_used
            if remaining_calls <= 0:
                outcome = InvestigationOutcome.BUDGET_EXHAUSTED
                break
            if self._total_budget_exhausted(sample_id):
                outcome = InvestigationOutcome.BUDGET_EXHAUSTED
                break

            completed = self.repository.get_completed_mcp_action_fingerprints(sample_id, target.address)
            plan = self.planner.plan(
                target.model_copy(update={"unknowns": current_unknowns, "confidence": current_confidence}),
                available_capabilities=session.capabilities,
                completed_fingerprints=completed,
                remaining_tool_calls=remaining_calls,
            )
            if not plan.actions:
                outcome = InvestigationOutcome.NO_USEFUL_ACTION
                break

            round_number = self.repository.next_mcp_round_number(sample_id, target.address)
            round_id = self.repository.create_mcp_round(
                sample_id,
                target.address,
                round_number=round_number,
                goal=plan.goal,
                plan_json=plan.model_dump_json(),
                confidence_before=current_confidence,
                unknowns_before=current_unknowns,
            )
            new_evidence: list[MCPEvidence] = []
            for action in plan.actions:
                fingerprint = action.fingerprint()
                if fingerprint in completed:
                    continue
                try:
                    result = session.execute(action.capability, action.target, action.parameters)
                except MCPError as exc:
                    from reai.mcp.schemas import MCPToolResult

                    result = MCPToolResult(
                        capability=action.capability,
                        target=action.target,
                        success=False,
                        error=str(exc),
                    )
                status = MCPCallStatus.SUCCESS.value if result.success else MCPCallStatus.FAILED.value
                if result.error and "unavailable" in result.error.lower():
                    status = MCPCallStatus.UNAVAILABLE.value
                self.repository.persist_mcp_call(
                    sample_id,
                    target.address,
                    round_number=round_number,
                    call_id=str(uuid4()),
                    fingerprint=fingerprint,
                    result=result,
                    parameters=action.parameters,
                    status=status,
                )
                for evidence in normalize_mcp_result(result):
                    if self.repository.persist_mcp_evidence(
                        sample_id,
                        target.address,
                        round_number=round_number,
                        evidence=evidence,
                    ):
                        new_evidence.append(evidence)

            if new_evidence:
                reassessed = self._reassess_with_mcp_evidence(
                    sample_id,
                    target,
                    round_number=round_number,
                    evidence=new_evidence,
                )
                current_confidence = reassessed.confidence
                current_unknowns = reassessed.unknowns
            self.repository.complete_mcp_round(
                round_id,
                status=InvestigationStatus.COMPLETED,
                confidence_after=current_confidence,
                unknowns_after=current_unknowns,
            )
            self.repository.increment_mcp_rounds(sample_id, target.address)

            if not new_evidence:
                outcome = InvestigationOutcome.NO_USEFUL_ACTION
                break
            if current_confidence >= 0.85 and not current_unknowns:
                outcome = InvestigationOutcome.RESOLVED_HIGH
                break
            if current_confidence >= 0.55 and (
                current_confidence > target.confidence or len(current_unknowns) < len(target.unknowns)
            ):
                outcome = InvestigationOutcome.RESOLVED_MEDIUM
                break
        else:
            outcome = InvestigationOutcome.BUDGET_EXHAUSTED

        final_row = self.repository.get_function_ai_analysis(sample_id, target.address)
        confidence_after = float(final_row["confidence"]) if final_row else current_confidence
        proposed_after = final_row["proposed_name"] if final_row else target.proposed_name
        self.repository.complete_mcp_investigation(
            sample_id,
            target.address,
            outcome=outcome,
            confidence_after=confidence_after,
            interpretation_changed=bool(proposed_after and proposed_after != initial_proposed),
        )
        if final_row is None:
            self.repository.complete_mcp_investigation(
                sample_id,
                target.address,
                outcome=InvestigationOutcome.FAILED,
                confidence_after=current_confidence,
                interpretation_changed=False,
                error=f"Unable to retrieve final AI finding for {original_name}.",
            )

    def _reassess_with_mcp_evidence(
        self,
        sample_id: str,
        target: InvestigationTarget,
        *,
        round_number: int,
        evidence: list[MCPEvidence],
    ) -> FunctionAnalysisResult:
        row = self.repository.get_function_ai_analysis(sample_id, target.address)
        if row is None:
            raise KeyError(f"Missing Phase 3 result for {target.address}")
        previous = FunctionAnalysisResult.model_validate(json.loads(row["result_json"]))
        self.repository.persist_ai_analysis_version(
            sample_id,
            target.address,
            source="BOTTOM_UP_OR_PREVIOUS",
            analysis_pass=previous.analysis_pass,
            investigation_round=round_number,
            result_json=row["result_json"],
            confidence=previous.confidence,
            confidence_label=previous.confidence_label.value,
            needs_investigation=previous.needs_investigation,
        )

        existing_keys = {
            (item.source.value, item.type, item.value, item.address)
            for item in previous.evidence
        }
        added = 0
        capabilities = {item.capability.value for item in evidence}
        for item in evidence:
            ai_item = EvidenceItem(
                type=item.evidence_type,
                value=item.value,
                description=item.description,
                address=item.address,
                source=EvidenceSource.MCP_OBSERVED,
            )
            key = (ai_item.source.value, ai_item.type, ai_item.value, ai_item.address)
            if key not in existing_keys:
                previous.evidence.append(ai_item)
                added += 1

        previous.analysis_pass = max(previous.analysis_pass + 1, target.analysis_pass + 1)
        previous.summary = _append_mcp_summary(previous.summary, capabilities, added)
        previous.reasoning_summary = _append_mcp_summary(previous.reasoning_summary, capabilities, added)

        # Only pass the set of capabilities that actually returned evidence items.
        # Capabilities invoked but returning nothing must NOT resolve unknowns —
        # that was the original P0 fake-resolution bug.
        capabilities_with_evidence = {item.capability.value for item in evidence}
        previous.unknowns = _resolve_unknowns(previous.unknowns, capabilities_with_evidence)

        if added:
            # Evidence-proportional confidence boost: small per-item increment
            # capped so that many weak items cannot reach HIGH without calibration.
            # calibrate_confidence below applies further evidence-quality constraints.
            boost = round(min(0.12, 0.03 * added), 4)
            previous.confidence = round(min(0.90, previous.confidence + boost), 4)
        previous.needs_investigation = bool(previous.unknowns)
        if previous.confidence >= 0.85 and not previous.unknowns:
            previous.confidence_label = ConfidenceLabel.HIGH
        elif previous.confidence >= 0.55:
            previous.confidence_label = ConfidenceLabel.MEDIUM
        else:
            previous.confidence_label = ConfidenceLabel.LOW
        previous = calibrate_confidence(
            previous,
            decompilation_failed=target.function.get("decompilation_status") == "failed",
        )
        # Re-apply unknown resolution after calibration (calibrate may alter state).
        previous.unknowns = _resolve_unknowns(previous.unknowns, capabilities_with_evidence)
        previous.needs_investigation = bool(previous.unknowns) or previous.confidence_label == ConfidenceLabel.LOW
        if previous.confidence >= 0.85 and not previous.unknowns:
            previous.confidence_label = ConfidenceLabel.HIGH
        elif previous.confidence >= 0.55:
            previous.confidence_label = ConfidenceLabel.MEDIUM
        else:
            previous.confidence_label = ConfidenceLabel.LOW


        self.repository.persist_ai_analysis(
            sample_id,
            target.current_name,
            previous,
            status="COMPLETED",
            prompt_version="phase4-mcp-reanalysis-v1",
            schema_version="phase3-function-analysis-v1",
            confidence_policy_version="phase3-confidence-v1",
            context_builder_version="phase4-mcp-context-v1",
            analysis_fingerprint=f"mcp-round-{round_number}-{target.address}",
        )
        self.repository.persist_ai_analysis_version(
            sample_id,
            target.address,
            source="MCP_INVESTIGATION",
            analysis_pass=previous.analysis_pass,
            investigation_round=round_number,
            result_json=previous.model_dump_json(),
            confidence=previous.confidence,
            confidence_label=previous.confidence_label.value,
            needs_investigation=previous.needs_investigation,
        )
        return previous

    def _total_budget_exhausted(self, sample_id: str) -> bool:
        if self.config.max_total_tool_calls is None:
            return False
        return self.repository.count_mcp_calls_for_sample(sample_id) >= self.config.max_total_tool_calls


def _append_mcp_summary(summary: str, capabilities: set[str], added: int) -> str:
    if not added:
        return summary
    tools = ", ".join(sorted(capabilities))
    note = f"MCP investigation added {added} read-only evidence item(s) from {tools}."
    if note in summary:
        return summary
    return f"{summary} {note}".strip()


def _resolve_unknowns(unknowns: list[str], capabilities_with_evidence: set[str]) -> list[str]:
    """Remove unknowns ONLY when evidence was actually returned by a matching capability.

    ``capabilities_with_evidence`` must contain only the capabilities that
    produced at least one non-empty evidence item in this round.  Capabilities
    that were invoked but returned nothing are excluded by the caller so that
    unknowns are not silently discarded due to empty tool responses.
    """
    remaining: list[str] = []
    for unknown in unknowns:
        text = unknown.lower()
        resolved = (
            ("caller" in text and "callers" in capabilities_with_evidence)
            or ("callee" in text and "callees" in capabilities_with_evidence)
            or ("indirect" in text and "disassemble" in capabilities_with_evidence)
            or ("call target" in text and "disassemble" in capabilities_with_evidence)
            or ("decompiler" in text and "disassemble" in capabilities_with_evidence)
            or ("disassembly" in text and "disassemble" in capabilities_with_evidence)
            or ("xref" in text and "xrefs" in capabilities_with_evidence)
            or ("reference" in text and "xrefs" in capabilities_with_evidence)
            or ("global" in text and "xrefs" in capabilities_with_evidence)
            or ("data" in text and ("data" in capabilities_with_evidence or "memory" in capabilities_with_evidence))
            or ("type" in text and "types" in capabilities_with_evidence)
            or ("prototype" in text and "types" in capabilities_with_evidence)
            or ("control" in text and "cfg" in capabilities_with_evidence)
        )
        if not resolved:
            remaining.append(unknown)
    return remaining

