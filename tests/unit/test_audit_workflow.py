import pytest

from reai.core.config import AIConfig, ApplicationConfig
from reai.core.exceptions import AIProviderError
from reai.core.orchestrator import AnalysisOrchestrator, ResultStatus, SampleResult
from reai.core.states import SampleState
from test_ai_phase3 import _workspace_with_phase2


def test_phase3_total_ai_failure_does_not_advance_pipeline(tmp_path, monkeypatch):
    sample, workspace, repository = _workspace_with_phase2(tmp_path)

    class BadClient:
        def analyze_function(self, context, *, analysis_pass, retry_count=0):
            raise RuntimeError("provider unavailable")

        def model_info(self):
            return {"provider": "bad"}

    monkeypatch.setattr("reai.ai.analyzer.create_ai_client", lambda config: BadClient())
    orchestrator = AnalysisOrchestrator(
        ApplicationConfig(output_dir=tmp_path / "out", ai=AIConfig(provider="mock", max_retries=0))
    )
    item = SampleResult(sample=sample, workspace=workspace, status=ResultStatus.READY_FOR_ANALYSIS)

    with pytest.raises(AIProviderError):
        orchestrator._run_phase3(item)

    stored = repository.get_sample(sample.sample_id)
    assert stored is not None
    assert stored.status == SampleState.FAILED_AI


def test_batch_stops_on_global_authentication_failure(tmp_path, monkeypatch):
    samples = tmp_path / "samples"
    samples.mkdir()
    (samples / "one.bin").write_bytes(b"one")
    (samples / "two.bin").write_bytes(b"two")
    output = tmp_path / "out"

    def fail_auth(self, item):
        raise RuntimeError("invalid API key")

    monkeypatch.setattr(AnalysisOrchestrator, "_run_sample_pipeline", fail_auth)

    with pytest.raises(RuntimeError, match="invalid API key"):
        AnalysisOrchestrator(ApplicationConfig(output_dir=output)).analyze(samples)

    assert (output / "batch-summary.json").is_file()
