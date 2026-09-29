import json
import sqlite3

import pytest

from reai.core.config import ApplicationConfig
from reai.core.exceptions import InputValidationError
from reai.core.orchestrator import AnalysisOrchestrator, ResultStatus


def test_orchestrator_initializes_single_file(tmp_path):
    sample = tmp_path / "malware.exe"
    sample.write_bytes(b"malware")
    output = tmp_path / "case"

    result = AnalysisOrchestrator(ApplicationConfig(output_dir=output)).initialize(sample)

    assert len(result.samples) == 1
    item = result.samples[0]
    assert item.status == ResultStatus.INITIALIZED
    assert item.workspace.root.is_dir()
    assert item.workspace.database.is_file()
    assert item.workspace.sample_metadata.is_file()
    data = json.loads(item.workspace.sample_metadata.read_text(encoding="utf-8"))
    assert data["status"] == "INITIALIZED"
    assert data["sha256"] == item.sample.sha256


def test_orchestrator_directory_non_recursive_and_recursive(tmp_path):
    samples = tmp_path / "samples"
    nested = samples / "nested"
    nested.mkdir(parents=True)
    (samples / "one.bin").write_bytes(b"one")
    (nested / "two.bin").write_bytes(b"two")

    non_recursive = AnalysisOrchestrator(
        ApplicationConfig(output_dir=tmp_path / "out1", recursive=False)
    ).initialize(samples)
    recursive = AnalysisOrchestrator(
        ApplicationConfig(output_dir=tmp_path / "out2", recursive=True)
    ).initialize(samples)

    assert [item.sample.filename for item in non_recursive.samples] == ["one.bin"]
    assert sorted(item.sample.filename for item in recursive.samples) == ["one.bin", "two.bin"]


def test_orchestrator_rejects_empty_and_missing_inputs(tmp_path):
    empty = tmp_path / "empty.bin"
    empty.write_bytes(b"")
    orchestrator = AnalysisOrchestrator(ApplicationConfig(output_dir=tmp_path / "out"))

    with pytest.raises(InputValidationError):
        orchestrator.initialize(empty)
    with pytest.raises(InputValidationError):
        orchestrator.initialize(tmp_path / "missing.bin")


def test_orchestrator_ignores_symlinks_in_directory(tmp_path):
    samples = tmp_path / "samples"
    samples.mkdir()
    target = samples / "real.bin"
    target.write_bytes(b"real")
    link = samples / "link.bin"
    try:
        link.symlink_to(target)
    except OSError:
        pytest.skip("Symlink creation is not available on this platform.")

    result = AnalysisOrchestrator(ApplicationConfig(output_dir=tmp_path / "out")).initialize(samples)

    assert [item.sample.filename for item in result.samples] == ["real.bin"]
    assert any("symlink" in skipped for skipped in result.skipped)


def test_duplicate_detection_and_existing_workspace(tmp_path):
    samples = tmp_path / "samples"
    samples.mkdir()
    (samples / "one.bin").write_bytes(b"same")
    (samples / "copy.bin").write_bytes(b"same")
    output = tmp_path / "out"

    first = AnalysisOrchestrator(ApplicationConfig(output_dir=output)).initialize(samples)
    second = AnalysisOrchestrator(ApplicationConfig(output_dir=output)).initialize(samples / "copy.bin")

    statuses = sorted(item.status for item in first.samples)
    assert statuses == [ResultStatus.DUPLICATE, ResultStatus.INITIALIZED]
    assert second.samples[0].status == ResultStatus.EXISTING
    assert second.samples[0].workspace.root == first.samples[0].workspace.root


def test_database_contains_initialized_sample(tmp_path):
    sample = tmp_path / "malware.bin"
    sample.write_bytes(b"payload")
    result = AnalysisOrchestrator(ApplicationConfig(output_dir=tmp_path / "out")).initialize(sample)
    database = result.samples[0].workspace.database

    with sqlite3.connect(database) as connection:
        row = connection.execute("SELECT status FROM samples").fetchone()
        config_json = connection.execute("SELECT config_json FROM jobs").fetchone()[0]

    assert row[0] == "INITIALIZED"
    assert '"workers": 1' in config_json
    assert '"recursive": false' in config_json
