import json
import sqlite3

from reai.core.config import EnrichmentConfig, IDAConfig
from reai.core.sample import Sample
from reai.enrichment.idb import IDBEnricher
from reai.extraction.models import BinaryMetadata, ExtractionBundle, FunctionRecord
from reai.storage.database import initialize_database
from reai.storage.repository import AnalysisRepository
from reai.utils.hashing import hash_file
from reai.utils.paths import WorkspacePaths


def _workspace(tmp_path, *, functions=None):
    source = tmp_path / "sample.bin"
    source.write_bytes(b"payload")
    hashes = hash_file(source)
    workspace = WorkspacePaths.for_sample(tmp_path / "out", source.name, hashes.sha256)
    workspace.create_directories()
    initialize_database(workspace.database)
    repository = AnalysisRepository(workspace.database)
    sample = Sample.from_file_hashes(source_path=source, hashes=hashes, workspace=workspace)
    repository.create_sample(sample)
    function_records = functions or [
        FunctionRecord(address=0x1000, end_address=0x1010, name="sub_1000", size=0x10),
        FunctionRecord(address=0x2000, end_address=0x2010, name="sub_2000", size=0x10),
    ]
    repository.persist_extraction(
        sample.sample_id,
        ExtractionBundle(metadata=BinaryMetadata(architecture="x86-64"), functions=function_records),
    )
    (workspace.ida / "original.i64").write_bytes(b"original-idb")
    return sample, workspace, repository


def _candidate(repository, sample_id, candidate_id, entity, address, change_type, original, proposed, confidence=0.9, eligible=True):
    with sqlite3.connect(repository.database_path) as connection:
        connection.execute(
            """
            INSERT INTO change_candidates (
                candidate_id, sample_id, entity, address, change_type,
                original, proposed, confidence, eligible_for_idb,
                evidence_json, reason
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                candidate_id,
                sample_id,
                entity,
                address,
                change_type,
                original,
                proposed,
                confidence,
                int(eligible),
                json.dumps([{"source": "test"}]),
                None,
            ),
        )
        connection.commit()


def _run(sample, workspace, repository):
    return IDBEnricher(
        EnrichmentConfig(mode="manifest"),
        IDAConfig(),
        repository,
        workspace,
    ).run(sample)


def test_phase6_copies_original_and_exports_verified_changes(tmp_path):
    sample, workspace, repository = _workspace(tmp_path)
    _candidate(repository, sample.sample_id, "rename_1000", "function", "0x1000", "rename", "sub_1000", "decrypt_config")
    _candidate(repository, sample.sample_id, "comment_1000", "function", "0x1000", "comment", None, "Decrypts the embedded config.")
    _candidate(repository, sample.sample_id, "rename_2000", "function", "0x2000", "rename", "sub_2000", "generic_handler", eligible=False)
    original_before = (workspace.ida / "original.i64").read_bytes()

    stats = _run(sample, workspace, repository)

    assert (workspace.ida / "original.i64").read_bytes() == original_before
    assert (workspace.ida / "analyzed.i64").read_bytes() == original_before
    assert stats.total_candidates == 3
    assert stats.verified == 2
    assert stats.skipped == 1
    changes = json.loads((workspace.analysis / "changes.json").read_text(encoding="utf-8"))
    assert changes["stats"]["verified"] == 2
    by_candidate = {row["candidate_id"]: row for row in changes["changes"]}
    assert by_candidate["rename_1000"]["status"] == "VERIFIED"
    assert by_candidate["rename_1000"]["applied"] == "decrypt_config"
    assert by_candidate["rename_2000"]["status"] == "SKIPPED_NOT_ELIGIBLE"


def test_phase6_resolves_function_name_collisions_deterministically(tmp_path):
    sample, workspace, repository = _workspace(tmp_path)
    _candidate(repository, sample.sample_id, "rename_1000", "function", "0x1000", "rename", "sub_1000", "decode config")
    _candidate(repository, sample.sample_id, "rename_2000", "function", "0x2000", "rename", "sub_2000", "decode-config")

    _run(sample, workspace, repository)

    sidecar = json.loads((workspace.ida / "analyzed.i64.reai.json").read_text(encoding="utf-8"))
    assert sidecar["functions"]["0x1000"]["name"] == "decode_config"
    assert sidecar["functions"]["0x2000"]["name"] == "decode_config_2"
    rows = {row["candidate_id"]: row for row in repository.get_idb_change_rows(sample.sample_id)}
    assert rows["rename_1000"]["applied"] == "decode_config"
    assert rows["rename_2000"]["applied"] == "decode_config_2"


def test_phase6_preserves_analyst_comments_and_replaces_reai_block(tmp_path):
    sample, workspace, repository = _workspace(tmp_path)
    _candidate(repository, sample.sample_id, "comment_1000", "function", "0x1000", "comment", None, "Initializes C2 networking.")
    original_sidecar = {
        "schema": "reai-idb-manifest-v1",
        "functions": {
            "0x1000": {
                "address": "0x1000",
                "name": "sub_1000",
                "original_name": "sub_1000",
                "comment": "Analyst note: check mutex handling.",
            }
        },
        "structures": {},
    }
    (workspace.ida / "original.i64.reai.json").write_text(json.dumps(original_sidecar), encoding="utf-8")

    _run(sample, workspace, repository)
    _run(sample, workspace, repository)

    sidecar = json.loads((workspace.ida / "analyzed.i64.reai.json").read_text(encoding="utf-8"))
    comment = sidecar["functions"]["0x1000"]["comment"]
    assert "Analyst note: check mutex handling." in comment
    assert comment.count("[REAI ANALYSIS BEGIN]") == 1
    assert comment.count("[REAI ANALYSIS END]") == 1


def test_phase6_skips_when_extracted_state_does_not_match_candidate(tmp_path):
    sample, workspace, repository = _workspace(
        tmp_path,
        functions=[FunctionRecord(address=0x1000, end_address=0x1010, name="decrypt_config", size=0x10)],
    )
    _candidate(repository, sample.sample_id, "rename_1000", "function", "0x1000", "rename", "sub_1000", "c2_init")

    stats = _run(sample, workspace, repository)

    assert stats.skipped == 1
    rows = repository.get_idb_change_rows(sample.sample_id)
    assert rows[0]["status"] == "SKIPPED_STATE_MISMATCH"
    sidecar = json.loads((workspace.ida / "analyzed.i64.reai.json").read_text(encoding="utf-8"))
    assert sidecar["functions"]["0x1000"]["name"] == "decrypt_config"
