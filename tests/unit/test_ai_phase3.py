import json

import pytest

from reai.ai.analyzer import BottomUpAIAnalyzer
from reai.ai.client import MockAIClient
from reai.ai.confidence import calibrate_confidence
from reai.ai.context import FunctionContextBuilder
from reai.ai.ordering import build_bottom_up_groups, select_target_addresses
from reai.ai.prompts import build_function_prompt
from reai.ai.schemas import ConfidenceLabel, EvidenceItem, FunctionAnalysisResult
from reai.ai.validation import is_generic_name, validate_proposed_name
from reai.core.config import AIConfig
from reai.core.sample import Sample
from reai.extraction.models import (
    BinaryMetadata,
    CallEdge,
    CallGraph,
    CallGraphNode,
    ExtractionBundle,
    FunctionRecord,
    ImportRecord,
    ReferenceRecord,
    StringRecord,
)
from reai.storage.database import initialize_database
from reai.storage.repository import AnalysisRepository
from reai.utils.hashing import hash_file
from reai.utils.paths import WorkspacePaths


def _workspace_with_phase2(tmp_path):
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
        FunctionRecord(address=0x1000, end_address=0x1010, name="sub_1000", size=0x10, callees=[0x2000, 0x3000]),
        FunctionRecord(address=0x2000, end_address=0x2010, name="sub_2000", size=0x10, callers=[0x1000], callees=[0x4000]),
        FunctionRecord(address=0x3000, end_address=0x3010, name="sub_3000", size=0x10, callers=[0x1000]),
        FunctionRecord(address=0x4000, end_address=0x4010, name="sub_4000", size=0x10, callers=[0x2000], import_refs=[0x9000]),
        FunctionRecord(address=0x5000, end_address=0x5010, name="named_helper", size=0x10),
    ]
    imports = [
        ImportRecord(
            module="kernel32",
            name="DecodeConfig",
            address=0x9000,
            xrefs=[
                ReferenceRecord(
                    source_address=0x4001,
                    destination_address=0x9000,
                    source_function=0x4000,
                    destination_entity="import",
                    xref_type="code",
                )
            ],
            referencing_functions=[0x4000],
        )
    ]
    strings = [
        StringRecord(
            address=0xA000,
            value="http://example.test",
            xrefs=[
                ReferenceRecord(
                    source_address=0x3001,
                    destination_address=0xA000,
                    source_function=0x3000,
                    destination_entity="string",
                    xref_type="data",
                )
            ],
            referencing_functions=[0x3000],
        )
    ]
    callgraph = CallGraph(
        nodes=[CallGraphNode(address=f.address, name=f.name) for f in functions],
        edges=[
            CallEdge(caller=0x1000, callee=0x2000),
            CallEdge(caller=0x1000, callee=0x3000),
            CallEdge(caller=0x2000, callee=0x4000),
        ],
    )
    repository.persist_extraction(
        sample.sample_id,
        ExtractionBundle(
            metadata=BinaryMetadata(architecture="x86-64"),
            functions=functions,
            imports=imports,
            strings=strings,
            callgraph=callgraph,
        ),
    )
    return sample, workspace, repository


def test_target_selection_excludes_named_functions(tmp_path):
    sample, workspace, repository = _workspace_with_phase2(tmp_path)
    _add_function(repository, sample.sample_id, "subsystem_init")
    _add_function(repository, sample.sample_id, "sub_parse_config")

    targets = repository.list_ai_targets(sample.sample_id)

    assert [row["name"] for row in targets] == ["sub_1000", "sub_2000", "sub_3000", "sub_4000"]
    assert select_target_addresses(targets, max_functions=2) == ["0x1000", "0x2000"]


def test_bottom_up_order_analyzes_callees_before_parents(tmp_path):
    sample, workspace, repository = _workspace_with_phase2(tmp_path)

    groups = build_bottom_up_groups(
        select_target_addresses(repository.list_ai_targets(sample.sample_id)),
        repository.list_function_calls(sample.sample_id),
        repository.list_callgraph_components(sample.sample_id),
    )

    flat = [address for group in groups for address in group]
    assert flat.index("0x4000") < flat.index("0x2000")
    assert flat.index("0x2000") < flat.index("0x1000")


def test_context_builder_includes_relevant_prompt_sections(tmp_path):
    sample, workspace, repository = _workspace_with_phase2(tmp_path)
    context = FunctionContextBuilder(repository, workspace).build(sample.sample_id, "0x4000")
    prompt = build_function_prompt(context)

    assert "sub_4000" in prompt
    assert "DecodeConfig" in prompt
    assert "evidence_policy" in prompt
    assert "uncertainty_policy" in prompt


def test_name_validation_and_confidence_calibration():
    assert is_generic_name("process_data")
    assert validate_proposed_name("decrypt_config")[0] is True
    assert validate_proposed_name("process_data")[0] is False
    result = FunctionAnalysisResult(
        address="0x1000",
        proposed_name="process_data",
        summary="Generic claim.",
        behavior=["Generic claim."],
        confidence=0.99,
        confidence_label=ConfidenceLabel.HIGH,
        evidence=[EvidenceItem(type="prototype", value="void f()", description="Only weak evidence.")],
        reasoning_summary="Weak evidence.",
        analysis_pass=1,
    )

    calibrated = calibrate_confidence(result)

    assert calibrated.confidence_label != ConfidenceLabel.HIGH
    assert calibrated.needs_investigation is True


def test_bottom_up_mock_provider_persists_child_context_and_exports(tmp_path):
    sample, workspace, repository = _workspace_with_phase2(tmp_path)
    analyzer = BottomUpAIAnalyzer(AIConfig(provider="mock"), repository, workspace)

    stats = analyzer.run(sample.sample_id)

    assert stats is not None
    assert stats.target_functions == 4
    assert stats.analyzed == 4
    rows = {row["address"]: row for row in repository.get_ai_analysis_rows(sample.sample_id)}
    parent = json.loads(rows["0x1000"]["result_json"])
    assert parent["proposed_name"].startswith("coordinate_")
    assert parent["evidence"][0]["type"] == "child_analysis"
    assert (workspace.analysis / "function_analysis.json").is_file()
    assert (workspace.analysis / "findings.json").is_file()
    assert (workspace.analysis / "ai_usage.json").is_file()


def test_resume_skips_completed_ai_analysis(tmp_path):
    sample, workspace, repository = _workspace_with_phase2(tmp_path)
    analyzer = BottomUpAIAnalyzer(AIConfig(provider="mock"), repository, workspace)
    analyzer.run(sample.sample_id)
    first_request_count = len(repository.get_ai_request_rows(sample.sample_id))

    analyzer.run(sample.sample_id)

    assert len(repository.get_ai_request_rows(sample.sample_id)) == first_request_count


def test_invalid_provider_response_records_failure(tmp_path, monkeypatch):
    sample, workspace, repository = _workspace_with_phase2(tmp_path)

    class BadClient:
        def analyze_function(self, context, *, analysis_pass, retry_count=0):
            raise ValueError("invalid JSON")

        def model_info(self):
            return {"provider": "bad"}

    monkeypatch.setattr("reai.ai.analyzer.create_ai_client", lambda config: BadClient())
    analyzer = BottomUpAIAnalyzer(AIConfig(provider="mock", max_retries=0, max_functions=1), repository, workspace)

    stats = analyzer.run(sample.sample_id)

    assert stats.failed == 1
    row = repository.get_ai_analysis_rows(sample.sample_id)[0]
    assert row["status"] == "FAILED"
    assert repository.get_ai_request_rows(sample.sample_id)[0]["success"] == 0


def _add_function(repository, sample_id, name):
    from reai.extraction.models import FunctionRecord

    existing = repository.list_extracted_functions(sample_id)
    address = 0x6000 + len(existing) * 0x100
    bundle = ExtractionBundle(
        metadata=BinaryMetadata(architecture="x86-64"),
        functions=[
            FunctionRecord(
                address=int(row["address"], 16),
                end_address=int(row["end_address"], 16),
                name=row["name"],
                size=row["size"],
                is_thunk=bool(row["is_thunk"]),
                is_library=bool(row["is_library"]),
                is_external=bool(row["is_external"]),
            )
            for row in existing
        ]
        + [FunctionRecord(address=address, end_address=address + 0x10, name=name, size=0x10)],
        callgraph=CallGraph(
            nodes=[CallGraphNode(address=int(row["address"], 16), name=row["name"]) for row in existing]
            + [CallGraphNode(address=address, name=name)],
            edges=[],
        ),
    )
    repository.persist_extraction(sample_id, bundle)
