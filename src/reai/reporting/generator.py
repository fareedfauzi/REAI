from __future__ import annotations

import json
import logging
import uuid
from datetime import datetime, timezone

from reai.core.config import ReportConfig
from reai.core.exceptions import ReportError
from reai.core.sample import Sample
from reai.extraction.serialization import atomic_write_text
from reai.reporting.loader import build_report_model
from reai.reporting.narrative import build_sections
from reai.reporting.render import render_html, render_markdown, render_pdf
from reai.reporting.schemas import ReportRun, ReportRunStatus, ReportStats
from reai.reporting.validation import validate_markdown, validate_report_model
from reai.storage.repository import AnalysisRepository
from reai.utils.paths import WorkspacePaths

LOGGER = logging.getLogger("reai.reporting")


class ReportGenerator:
    def __init__(self, config: ReportConfig, repository: AnalysisRepository, workspace: WorkspacePaths) -> None:
        self.config = config
        self.repository = repository
        self.workspace = workspace

    def run(self, sample: Sample) -> ReportStats | None:
        if not self.config.enabled:
            return None
        self.workspace.report.mkdir(parents=True, exist_ok=True)
        model = build_report_model(self.config, self.repository, self.workspace, sample.sample_id)
        build_sections(model, self.config)
        model_failures = validate_report_model(model)
        run = ReportRun(
            run_id=_run_id(),
            sample_id=sample.sample_id,
            source_analysis_fingerprint=model.source_analysis_fingerprint,
            enrichment_fingerprint=model.enrichment_fingerprint,
            report_fingerprint=model.fingerprint,
            schema_version=self.config.schema_version,
            prompt_version=self.config.prompt_version,
            formats=self.config.formats,
            status=ReportRunStatus.RUNNING,
            started_at=_now(),
            stats=model.stats,
        )
        run.stats.validation_failures = len(model_failures)
        self.repository.create_report_run(run)
        try:
            self.repository.persist_report_sections(sample.sample_id, run.run_id, model.sections)
            model_path = self.workspace.analysis / "report_model.json"
            atomic_write_text(model_path, json.dumps(model.model_dump(mode="json"), indent=2, sort_keys=True) + "\n")

            markdown = render_markdown(model, self.config)
            markdown_failures = validate_markdown(markdown, model)
            failures = model_failures + markdown_failures
            run.stats.validation_failures = len(failures)

            if "markdown" in self.config.formats:
                markdown_path = self.workspace.report / "report.md"
                atomic_write_text(markdown_path, markdown)
                run.markdown_path = str(markdown_path)
                run.stats.markdown_generated = True
            if "html" in self.config.formats:
                html_path = self.workspace.report / "report.html"
                atomic_write_text(html_path, render_html(markdown, model))
                run.html_path = str(html_path)
                run.stats.html_generated = True
            if "pdf" in self.config.formats:
                pdf_path = self.workspace.report / "report.pdf"
                render_pdf(markdown, pdf_path)
                run.pdf_path = str(pdf_path)
                run.stats.pdf_generated = True

            run.status = ReportRunStatus.PARTIAL if failures else ReportRunStatus.COMPLETED
            run.error = "; ".join(failures) if failures else None
            run.completed_at = _now()
            self.repository.update_report_run(run)
            LOGGER.info("report generation complete markdown=%s html=%s pdf=%s", run.markdown_path, run.html_path, run.pdf_path)
            return run.stats
        except Exception as exc:
            run.status = ReportRunStatus.FAILED
            run.error = str(exc)
            run.completed_at = _now()
            self.repository.update_report_run(run)
            if isinstance(exc, ReportError):
                raise
            raise ReportError(f"Report generation failed: {exc}") from exc


def _run_id() -> str:
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
    return f"report_{timestamp}_{uuid.uuid4().hex[:8]}"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()
