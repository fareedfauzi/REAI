import json
import sqlite3

from reai.ai.schemas import ArtifactCandidate, ConfidenceLabel, EvidenceItem, EvidenceSource, FunctionAnalysisResult, VariableProposal
from reai.analysis.engine import MalwareUnderstandingEngine
from reai.core.config import AnalysisConfig
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


def _phase5_workspace(tmp_path):
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
        FunctionRecord(address=0x2000, end_address=0x2010, name="sub_2000", size=0x10, callers=[0x1000]),
        FunctionRecord(address=0x3000, end_address=0x3010, name="sub_3000", size=0x10, callers=[0x1000], string_refs=[0xA000], import_refs=[0x9000]),
        FunctionRecord(address=0x4000, end_address=0x4010, name="sub_4000", size=0x10, string_refs=[0xB000]),
        FunctionRecord(address=0x5000, end_address=0x5010, name="sub_5000", size=0x10),
    ]
    imports = [
        ImportRecord(
            module="winhttp",
            name="WinHttpConnect",
            address=0x9000,
            xrefs=[
                ReferenceRecord(
                    source_address=0x3002,
                    destination_address=0x9000,
                    source_function=0x3000,
                    destination_entity="import",
                    xref_type="code",
                )
            ],
        )
    ]
    strings = [
        StringRecord(
            address=0xA000,
            value="Example.COM",
            xrefs=[
                ReferenceRecord(
                    source_address=0x3003,
                    destination_address=0xA000,
                    source_function=0x3000,
                    destination_entity="string",
                    xref_type="data",
                )
            ],
        ),
        StringRecord(
            address=0xB000,
            value="C:\\Windows\\System32",
            xrefs=[
                ReferenceRecord(
                    source_address=0x4003,
                    destination_address=0xB000,
                    source_function=0x4000,
                    destination_entity="string",
                    xref_type="data",
                )
            ],
        ),
    ]
    callgraph = CallGraph(
        nodes=[CallGraphNode(address=f.address, name=f.name) for f in functions],
        edges=[CallEdge(caller=0x1000, callee=0x2000), CallEdge(caller=0x1000, callee=0x3000)],
    )
    repository.persist_extraction(
        sample.sample_id,
        ExtractionBundle(metadata=BinaryMetadata(architecture="x86-64"), functions=functions, imports=imports, strings=strings, callgraph=callgraph),
    )

    _persist_finding(
        repository,
        sample.sample_id,
        "0x1000",
        "sub_1000",
        "initialize_data",
        "Initializes data from child routines.",
        0.62,
        ConfidenceLabel.MEDIUM,
        variables=[VariableProposal(original="v7", proposed="buffer", confidence=0.61, evidence="Weak local use.")],
    )
    _persist_finding(
        repository,
        sample.sample_id,
        "0x2000",
        "sub_2000",
        "decrypt_configuration",
        "Decrypts embedded config; config +0x10 domain pointer, config +0x18 port.",
        0.91,
        ConfidenceLabel.HIGH,
        capabilities=["configuration", "crypto"],
    )
    _persist_finding(
        repository,
        sample.sample_id,
        "0x3000",
        "sub_3000",
        "initialize_c2",
        "Initializes C2 HTTP connection; config +0x20 c2 domain and config +0x28 sleep interval.",
        0.9,
        ConfidenceLabel.HIGH,
        capabilities=["c2"],
        artifacts=[ArtifactCandidate(value="Example.COM", type="domain", address="0xa000", usage="Passed to WinHttpConnect", confidence=0.84)],
    )
    _persist_finding(
        repository,
        sample.sample_id,
        "0x4000",
        "sub_4000",
        "write_file_path",
        "References a generic Windows path during file logic.",
        0.8,
        ConfidenceLabel.MEDIUM,
        artifacts=[ArtifactCandidate(value="C:\\Windows\\System32", type="file_path", address="0xb000", usage="Generic system directory", confidence=0.9)],
    )
    _persist_finding(
        repository,
        sample.sample_id,
        "0x5000",
        "sub_5000",
        "process_data",
        "Generic high-confidence claim.",
        0.95,
        ConfidenceLabel.HIGH,
    )
    return sample, workspace, repository


def _persist_finding(repository, sample_id, address, original, proposed, summary, confidence, label, *, capabilities=None, artifacts=None, variables=None):
    result = FunctionAnalysisResult(
        address=address,
        proposed_name=proposed,
        summary=summary,
        behavior=[summary],
        confidence=confidence,
        confidence_label=label,
        evidence=[
            EvidenceItem(
                type="semantic_summary",
                value=proposed,
                description=summary,
                address=address,
                source=EvidenceSource.AI_DERIVED,
            )
        ],
        variables=variables or [],
        types=[],
        capabilities=capabilities or [],
        artifacts=artifacts or [],
        unknowns=[],
        reasoning_summary=summary,
        analysis_pass=1,
        needs_investigation=False,
    )
    repository.persist_ai_analysis(
        sample_id,
        original,
        result,
        status="COMPLETED",
        prompt_version="test",
        schema_version="test",
        confidence_policy_version="test",
        context_builder_version="test",
        analysis_fingerprint=f"test-{address}",
    )


def test_phase5_propagates_context_and_preserves_phase3_finding(tmp_path):
    sample, workspace, repository = _phase5_workspace(tmp_path)

    stats = MalwareUnderstandingEngine(AnalysisConfig(), repository, workspace).run(sample.sample_id)

    assert stats.functions_validated == 5
    with sqlite3.connect(workspace.database) as connection:
        validated = connection.execute(
            "SELECT proposed_name FROM validated_function_findings WHERE sample_id = ? AND function_address = '0x1000'",
            (sample.sample_id,),
        ).fetchone()[0]
        original = connection.execute(
            "SELECT proposed_name FROM ai_function_analysis WHERE sample_id = ? AND address = '0x1000'",
            (sample.sample_id,),
        ).fetchone()[0]
        changed = connection.execute("SELECT interpretations_changed FROM propagation_passes WHERE sample_id = ? ORDER BY pass_number LIMIT 1", (sample.sample_id,)).fetchone()[0]
    assert original == "initialize_data"
    assert validated == "initialize_c2_configuration"
    assert changed >= 1
    exported = json.loads((workspace.analysis / "validated_analysis.json").read_text(encoding="utf-8"))
    assert exported["stats"]["functions_validated"] == 5


def test_phase5_subsystems_artifacts_structures_and_validation(tmp_path):
    sample, workspace, repository = _phase5_workspace(tmp_path)

    stats = MalwareUnderstandingEngine(AnalysisConfig(), repository, workspace).run(sample.sample_id)

    assert stats.subsystems >= 3
    assert stats.capabilities >= 3
    assert stats.validated_iocs == 1
    assert stats.recovered_structures == 1
    artifacts = json.loads((workspace.analysis / "validated_artifacts.json").read_text(encoding="utf-8"))["artifacts"]
    assert [item["normalized_value"] for item in artifacts] == ["example.com"]
    structures = json.loads((workspace.analysis / "recovered_structures.json").read_text(encoding="utf-8"))["structures"]
    field_names = {field["name"] for field in structures[0]["fields"]}
    assert {"c2_domain", "c2_port", "sleep_interval"}.issubset(field_names)
    with sqlite3.connect(workspace.database) as connection:
        generic_eligible = connection.execute(
            """
            SELECT eligible_for_idb FROM change_candidates
            WHERE sample_id = ? AND address = '0x5000' AND change_type = 'rename'
            """,
            (sample.sample_id,),
        ).fetchone()[0]
        variable_eligible = connection.execute(
            """
            SELECT eligible_for_idb FROM change_candidates
            WHERE sample_id = ? AND entity = 'variable' AND address = '0x1000'
            """,
            (sample.sample_id,),
        ).fetchone()[0]
    assert generic_eligible == 0
    assert variable_eligible == 0

