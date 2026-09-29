from reai.core.jobs import AnalysisJob
from reai.core.sample import Sample
from reai.core.states import JobStatus, SampleState
from reai.extraction.models import (
    BinaryMetadata,
    CallEdge,
    CallGraph,
    CallGraphNode,
    ExtractionBundle,
    FunctionRecord,
    SegmentRecord,
    StringRecord,
)
from reai.storage.database import initialize_database
from reai.storage.repository import AnalysisRepository
from reai.utils.hashing import hash_file
from reai.utils.paths import WorkspacePaths


def test_sqlite_sample_job_and_state_transitions(tmp_path):
    source = tmp_path / "malware.bin"
    source.write_bytes(b"payload")
    hashes = hash_file(source)
    workspace = WorkspacePaths.for_sample(tmp_path / "out", source.name, hashes.sha256)
    workspace.create_directories()
    initialize_database(workspace.database)
    repository = AnalysisRepository(workspace.database)
    sample = Sample.from_file_hashes(source_path=source, hashes=hashes, workspace=workspace)

    repository.create_sample(sample)
    repository.record_state_transition(sample.sample_id, None, SampleState.DISCOVERED)
    repository.update_sample_state(sample.sample_id, SampleState.INITIALIZING)
    repository.update_sample_state(sample.sample_id, SampleState.INITIALIZED)
    job = AnalysisJob.create(sample.sample_id, run_config={"workers": 2, "recursive": True})
    repository.create_job(job)
    repository.update_job(job.job_id, JobStatus.COMPLETED)

    stored = repository.get_sample(sample.sample_id)
    assert stored is not None
    assert stored.status == SampleState.INITIALIZED
    assert repository.count_jobs() == 1
    with repository._connect() as connection:
        config_json = connection.execute("SELECT config_json FROM jobs").fetchone()[0]
    assert '"workers": 2' in config_json
    assert '"recursive": true' in config_json
    transitions = repository.state_transitions(sample.sample_id)
    assert [row["new_state"] for row in transitions] == ["DISCOVERED", "INITIALIZING", "INITIALIZED"]


def test_sqlite_persists_phase2_extraction(tmp_path):
    source = tmp_path / "malware.bin"
    source.write_bytes(b"payload")
    hashes = hash_file(source)
    workspace = WorkspacePaths.for_sample(tmp_path / "out", source.name, hashes.sha256)
    workspace.create_directories()
    initialize_database(workspace.database)
    repository = AnalysisRepository(workspace.database)
    sample = Sample.from_file_hashes(source_path=source, hashes=hashes, workspace=workspace)
    repository.create_sample(sample)
    bundle = ExtractionBundle(
        metadata=BinaryMetadata(architecture="x86-64", bitness=64, ida_version="9.0"),
        functions=[
            FunctionRecord(
                address=0x1000,
                end_address=0x1010,
                name="sub_1000",
                size=0x10,
                string_refs=[0x3000],
            )
        ],
        strings=[StringRecord(address=0x3000, value="hello", length=5)],
        segments=[SegmentRecord(name=".text", start=0x1000, end=0x2000, size=0x1000)],
        callgraph=CallGraph(
            nodes=[CallGraphNode(address=0x1000, name="sub_1000")],
            edges=[CallEdge(caller=0x1000, callee=0x1000, type="direct")],
        ),
    )

    repository.persist_extraction(sample.sample_id, bundle)

    assert repository.get_function_record_json(sample.sample_id, "0x1000") is not None
    with repository._connect() as connection:
        assert connection.execute("SELECT COUNT(*) FROM binary_metadata").fetchone()[0] == 1
        assert connection.execute("SELECT COUNT(*) FROM functions").fetchone()[0] == 1
        assert connection.execute("SELECT COUNT(*) FROM function_calls").fetchone()[0] == 1
        assert connection.execute("SELECT COUNT(*) FROM strings").fetchone()[0] == 1
