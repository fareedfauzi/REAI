import json
import os
import sqlite3
import time

import pytest

from reai.core.config import ApplicationConfig, ReportConfig
from reai.core.exceptions import WorkspaceError
from reai.core.orchestrator import AnalysisOrchestrator, ResultStatus
from reai.core.states import SampleState
from reai.utils.locks import WorkspaceLock
from reai.utils.redaction import redact_secrets
from reai.utils.retry import RetryClass, RetryPolicy, classify_exception, run_with_retry
from test_phase7_reporting import _reported_workspace


def test_batch_isolates_sample_failure_and_writes_summary(tmp_path, monkeypatch):
    samples = tmp_path / "samples"
    samples.mkdir()
    (samples / "good.bin").write_bytes(b"good")
    (samples / "bad.bin").write_bytes(b"bad")
    output = tmp_path / "out"

    def fake_pipeline(self, item):
        if item.sample.filename == "bad.bin":
            raise RuntimeError("provider failed with sk-secretvalue123456")
        item.status = ResultStatus.COMPLETE

    monkeypatch.setattr(AnalysisOrchestrator, "_run_sample_pipeline", fake_pipeline)

    result = AnalysisOrchestrator(ApplicationConfig(output_dir=output)).analyze(samples)

    assert result.complete_count == 1
    assert result.failed_count == 1
    summary = json.loads((output / "batch-summary.json").read_text(encoding="utf-8"))
    assert summary["unique_samples"] == 2
    assert summary["success_count"] == 1
    assert summary["failure_count"] == 1
    failed = next(item for item in summary["samples"] if item["status"] == "FAILED")
    assert "sk-secretvalue" not in failed["error"]
    assert "sk-<redacted>" in failed["error"]
    assert (output / "batch-report.md").is_file()
    with sqlite3.connect(output / "batch.db") as connection:
        assert connection.execute("SELECT failure_count FROM batches").fetchone()[0] == 1


def test_workspace_lock_blocks_active_owner_and_recovers_stale_lock(tmp_path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    with WorkspaceLock(workspace, stale_seconds=60):
        with pytest.raises(WorkspaceError):
            with WorkspaceLock(workspace, stale_seconds=60):
                pass
    assert not (workspace / ".reai.lock").exists()

    lock_path = workspace / ".reai.lock"
    lock_path.write_text('{"pid": 1}\n', encoding="utf-8")
    old = time.time() - 120
    os.utime(lock_path, (old, old))
    with WorkspaceLock(workspace, stale_seconds=1):
        assert lock_path.exists()
    assert not lock_path.exists()


def test_retry_policy_retries_transient_and_not_authentication():
    attempts = {"count": 0}

    def flaky():
        attempts["count"] += 1
        if attempts["count"] < 3:
            raise TimeoutError("temporary timeout")
        return "ok"

    assert run_with_retry(flaky, policy=RetryPolicy(attempts=3, initial_delay_seconds=0, jitter_seconds=0), sleep=lambda _: None) == "ok"
    assert attempts["count"] == 3
    assert classify_exception(RuntimeError("HTTP 429 rate limit")) == RetryClass.RATE_LIMITED
    assert classify_exception(RuntimeError("invalid API key")) == RetryClass.AUTHENTICATION
    with pytest.raises(RuntimeError):
        run_with_retry(
            lambda: (_ for _ in ()).throw(RuntimeError("invalid API key")),
            policy=RetryPolicy(attempts=3, initial_delay_seconds=0, jitter_seconds=0),
            sleep=lambda _: None,
        )


def test_artifact_aware_resume_regenerates_missing_report_only(tmp_path):
    sample, workspace, repository, _stats = _reported_workspace(
        tmp_path,
        report_config=ReportConfig(formats=["markdown", "html", "pdf"]),
    )
    repository.update_sample_state(sample.sample_id, SampleState.COMPLETE, message="test completed pipeline")
    (workspace.report / "report.pdf").unlink()

    orchestrator = AnalysisOrchestrator(
        ApplicationConfig(
            output_dir=tmp_path / "out",
            ida={"path": "./definitely-missing-ida"},
            report={"formats": ["markdown", "html", "pdf"]},
        )
    )
    adjusted = orchestrator._artifact_adjusted_state(SampleState.COMPLETE, workspace, repository, sample.sample_id)

    assert adjusted == SampleState.ENRICHED


def test_redaction_masks_common_secret_shapes():
    text = redact_secrets('api-key = "secret" Authorization: Bearer token123 sk-proj-abcdef123456')

    assert "secret" not in text
    assert "token123" not in text
    assert "abcdef123456" not in text
