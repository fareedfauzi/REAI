import json

from reai.analysis.engine import MalwareUnderstandingEngine
from reai.core.config import AnalysisConfig, EnrichmentConfig, IDAConfig, ReportConfig
from reai.enrichment.idb import IDBEnricher
from reai.reporting.generator import ReportGenerator
from reai.reporting.loader import build_report_model, defang_indicator
from reai.reporting.narrative import build_sections
from test_phase5_analysis import _phase5_workspace


def _reported_workspace(tmp_path, *, report_config=None):
    sample, workspace, repository = _phase5_workspace(tmp_path)
    MalwareUnderstandingEngine(AnalysisConfig(), repository, workspace).run(sample.sample_id)
    (workspace.ida / "original.i64").write_bytes(b"original-idb")
    IDBEnricher(EnrichmentConfig(mode="manifest"), IDAConfig(), repository, workspace).run(sample)
    stats = ReportGenerator(report_config or ReportConfig(), repository, workspace).run(sample)
    return sample, workspace, repository, stats


def test_phase7_generates_markdown_html_pdf_and_report_model(tmp_path):
    sample, workspace, repository, stats = _reported_workspace(tmp_path)

    assert stats.markdown_generated is True
    assert stats.html_generated is True
    assert stats.pdf_generated is True
    assert (workspace.report / "report.md").is_file()
    assert (workspace.report / "report.html").is_file()
    assert (workspace.report / "report.pdf").is_file()
    assert (workspace.report / "report.pdf").read_bytes().startswith(b"%PDF-")
    model = json.loads((workspace.analysis / "report_model.json").read_text(encoding="utf-8"))
    assert model["sample"]["sha256"] == sample.sha256
    assert model["stats"]["sections_generated"] >= 8
    assert repository.get_latest_report_run(sample.sample_id)["status"] == "COMPLETED"


def test_phase7_uses_applied_idb_names_and_defanged_iocs(tmp_path):
    sample, workspace, repository, _stats = _reported_workspace(tmp_path)

    markdown = (workspace.report / "report.md").read_text(encoding="utf-8")
    changes = {
        row["address"]: row["applied"]
        for row in repository.get_idb_change_rows(sample.sample_id)
        if row["operation"] == "rename" and row["status"] == "VERIFIED"
    }
    assert changes
    for applied in changes.values():
        assert applied in markdown
    assert "example[.]com" in markdown
    assert "Example.COM" not in markdown


def test_phase7_dynamic_sections_omit_unsupported_behavior(tmp_path):
    sample, workspace, repository, _stats = _reported_workspace(tmp_path)

    markdown = (workspace.report / "report.md").read_text(encoding="utf-8")
    assert "## Network / C2" in markdown
    assert "## Credential Access" not in markdown
    assert "## Indicators of Compromise" in markdown
    assert "```mermaid" in markdown


def test_phase7_report_fingerprint_tracks_report_settings_not_analysis(tmp_path):
    sample, workspace, repository, _stats = _reported_workspace(tmp_path)
    first = repository.get_latest_report_run(sample.sample_id)
    source_fingerprint = first["source_analysis_fingerprint"]

    ReportGenerator(ReportConfig(defang_iocs=False), repository, workspace).run(sample)
    second = repository.get_latest_report_run(sample.sample_id)

    assert second["source_analysis_fingerprint"] == source_fingerprint
    assert second["report_fingerprint"] != first["report_fingerprint"]
    markdown = (workspace.report / "report.md").read_text(encoding="utf-8")
    assert "example.com" in markdown


def test_phase7_escaping_helpers_are_conservative(tmp_path):
    sample, workspace, repository = _phase5_workspace(tmp_path)
    MalwareUnderstandingEngine(AnalysisConfig(), repository, workspace).run(sample.sample_id)
    model = build_report_model(ReportConfig(), repository, workspace, sample.sample_id)
    build_sections(model, ReportConfig())

    assert defang_indicator("https://example.com/gate", "url") == "hxxps://example[.]com/gate"
    assert not any(section.title == "Credential Access" for section in model.sections)
