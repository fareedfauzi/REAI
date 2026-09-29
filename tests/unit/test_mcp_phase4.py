import json
import sqlite3

from reai.ai.schemas import ConfidenceLabel, EvidenceItem, EvidenceSource, FunctionAnalysisResult
from reai.core.config import MCPConfig
from reai.core.sample import Sample
from reai.extraction.models import BinaryMetadata, CallEdge, CallGraph, CallGraphNode, ExtractionBundle, FunctionRecord
from reai.mcp.investigator import MCPInvestigator
from reai.mcp.planner import InvestigationPlanner
from reai.mcp.schemas import MCPCapability, InvestigationTarget
from reai.storage.database import initialize_database
from reai.storage.repository import AnalysisRepository
from reai.utils.hashing import hash_file
from reai.utils.paths import WorkspacePaths


def _workspace_with_uncertain_phase3(tmp_path, *, unknown: str = "Unknown caller context."):
    source = tmp_path / "sample.bin"
    source.write_bytes(b"payload")
    hashes = hash_file(source)
    workspace = WorkspacePaths.for_sample(tmp_path / "out", source.name, hashes.sha256)
    workspace.create_directories()
    initialize_database(workspace.database)
    repository = AnalysisRepository(workspace.database)
    sample = Sample.from_file_hashes(source_path=source, hashes=hashes, workspace=workspace)
    repository.create_sample(sample)

    functions = [
        FunctionRecord(
            address=0x1000,
            end_address=0x1010,
            name="sub_1000",
            size=0x10,
            decompilation_status="failed",
            disassembly_status="success",
        ),
        FunctionRecord(address=0x2000, end_address=0x2010, name="sub_2000", size=0x10, callees=[0x1000]),
    ]
    repository.persist_extraction(
        sample.sample_id,
        ExtractionBundle(
            metadata=BinaryMetadata(architecture="x86-64"),
            functions=functions,
            callgraph=CallGraph(
                nodes=[CallGraphNode(address=f.address, name=f.name) for f in functions],
                edges=[CallEdge(caller=0x2000, callee=0x1000)],
            ),
        ),
    )
    result = FunctionAnalysisResult(
        address="0x1000",
        proposed_name=None,
        summary="Static context is insufficient.",
        behavior=[],
        confidence=0.52,
        confidence_label=ConfidenceLabel.LOW,
        evidence=[
            EvidenceItem(
                type="function_metadata",
                value="sub_1000",
                description="Only basic metadata was available.",
                address="0x1000",
                source=EvidenceSource.IDA_OBSERVED,
            )
        ],
        unknowns=[unknown],
        reasoning_summary="Insufficient context.",
        analysis_pass=1,
        needs_investigation=True,
    )
    repository.persist_ai_analysis(
        sample.sample_id,
        "sub_1000",
        result,
        status="COMPLETED",
        prompt_version="test",
        schema_version="test",
        confidence_policy_version="test",
        context_builder_version="test",
        analysis_fingerprint="test",
    )
    return sample, workspace, repository


def test_planner_maps_unknowns_and_skips_unavailable_capabilities():
    target = InvestigationTarget(
        sample_id="s",
        address="0x1000",
        current_name="sub_1000",
        confidence=0.4,
        confidence_label="LOW",
        unknowns=["Unknown indirect call target.", "Unknown caller context."],
        investigation_reasons=["Resolve indirect call."],
    )

    plan = InvestigationPlanner().plan(
        target,
        available_capabilities={MCPCapability.CALLERS},
        completed_fingerprints=set(),
        remaining_tool_calls=5,
    )

    assert [action.capability for action in plan.actions] == [MCPCapability.CALLERS]


def test_investigator_persists_mcp_evidence_versions_and_exports(tmp_path):
    sample, workspace, repository = _workspace_with_uncertain_phase3(tmp_path)
    investigator = MCPInvestigator(
        MCPConfig(enabled=True, provider="mock", max_rounds_per_function=2, max_tool_calls_per_function=3),
        repository,
        workspace,
    )

    stats = investigator.run(sample.sample_id)

    assert stats is not None
    assert stats.candidates == 1
    assert stats.mcp_calls >= 1
    assert stats.resolved_medium == 1
    evidence_rows = repository.get_mcp_evidence_rows(sample.sample_id, "0x1000")
    assert evidence_rows
    ai_result = json.loads(repository.get_function_ai_analysis(sample.sample_id, "0x1000")["result_json"])
    assert any(item["source"] == "MCP_OBSERVED" for item in ai_result["evidence"])
    assert (workspace.analysis / "mcp_investigations.json").is_file()
    assert (workspace.analysis / "mcp_evidence.json").is_file()
    assert (workspace.analysis / "mcp_usage.json").is_file()
    with sqlite3.connect(workspace.database) as connection:
        version_count = connection.execute("SELECT COUNT(*) FROM ai_analysis_versions").fetchone()[0]
    assert version_count >= 2


def test_budget_enforced_when_planner_wants_more_actions(tmp_path):
    sample, workspace, repository = _workspace_with_uncertain_phase3(tmp_path, unknown="Unknown indirect call target.")
    investigator = MCPInvestigator(
        MCPConfig(enabled=True, provider="mock", max_rounds_per_function=3, max_tool_calls_per_function=1),
        repository,
        workspace,
    )

    investigator.run(sample.sample_id)

    investigation = repository.get_mcp_investigation(sample.sample_id, "0x1000")
    assert len(repository.get_mcp_call_rows(sample.sample_id)) == 1
    assert investigation["outcome"] in {"RESOLVED_MEDIUM", "BUDGET_EXHAUSTED"}


def test_completed_investigation_resume_skips_repeated_mcp_calls(tmp_path):
    sample, workspace, repository = _workspace_with_uncertain_phase3(tmp_path)
    investigator = MCPInvestigator(
        MCPConfig(enabled=True, provider="mock", max_rounds_per_function=2, max_tool_calls_per_function=3),
        repository,
        workspace,
    )
    investigator.run(sample.sample_id)
    first_calls = len(repository.get_mcp_call_rows(sample.sample_id))

    investigator.run(sample.sample_id)

    assert len(repository.get_mcp_call_rows(sample.sample_id)) == first_calls
