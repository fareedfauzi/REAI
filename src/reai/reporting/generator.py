from __future__ import annotations

import hashlib
import json
import logging
import uuid
from datetime import datetime, timezone
from typing import Callable

from reai.core.config import ReportConfig
from reai.core.exceptions import ReportError
from reai.core.sample import Sample
from reai.extraction.serialization import atomic_write_text
from reai.reporting.findings import write_report_findings
from reai.reporting.models_v2 import ReportModelV2
from reai.reporting.render_v2 import render_html_v2, render_markdown_v2, render_pdf_v2
from reai.reporting.schemas import ReportRun, ReportRunStatus, ReportSection, ReportSectionStatus, ReportStats
from reai.reporting.synthesis import synthesize_report_model
from reai.reporting.validation import validate_markdown, validate_report_model
from reai.storage.repository import AnalysisRepository
from reai.utils.paths import WorkspacePaths

LOGGER = logging.getLogger("reai.reporting")


class ReportGenerator:
    def __init__(
        self,
        config: ReportConfig,
        repository: AnalysisRepository,
        workspace: WorkspacePaths,
        *,
        progress_callback: Callable[[str], None] | None = None,
    ) -> None:
        self.config = config
        self.repository = repository
        self.workspace = workspace
        self.progress_callback = progress_callback

    def run(self, sample: Sample) -> ReportStats | None:
        if not self.config.enabled:
            return None
        self.workspace.report.mkdir(parents=True, exist_ok=True)
        
        try:
            from reai.analysis.ai_narrative import generate_ai_narrative
            from reai.analysis.ai_rewrite import generate_ai_readable_code
            
            self._progress("generating AI narrative")
            generate_ai_narrative(sample.sample_id, self.workspace.root)
            self._progress("generating readable code appendix")
            generate_ai_readable_code(sample.sample_id, self.workspace.root)
        except Exception as e:
            LOGGER.error(f"Failed to generate AI content: {e}")
            raise
        self._progress("synthesizing report model")
        model = synthesize_report_model(self.config, self.repository, self.workspace, sample.sample_id)
        self._progress("writing report findings")
        write_report_findings(self.workspace, model)
        self._progress("building report sections")
        sections = _build_legacy_sections(model)
        self._progress("validating report model")
        model_failures = validate_report_model(model)

        stats = ReportStats(
            sections_generated=11,
            sections_omitted=0,
            tables_generated=6,
            diagrams_generated=1,
            iocs_rendered=len(model.indicators),
            functions_referenced=len(model.key_functions),
            evidence_references=sum(len(f.artifacts) + len(f.key_apis) for f in model.key_functions),
        )

        run = ReportRun(
            run_id=_run_id(),
            sample_id=sample.sample_id,
            source_analysis_fingerprint=model.source_analysis_fingerprint,
            enrichment_fingerprint=model.enrichment_fingerprint,
            report_fingerprint=model.fingerprint,
            schema_version="report-engine-v2",
            prompt_version=self.config.prompt_version,
            formats=self.config.formats,
            status=ReportRunStatus.RUNNING,
            started_at=_now(),
            stats=stats,
        )
        run.stats.validation_failures = len(model_failures)
        self.repository.create_report_run(run)
        try:
            self.repository.persist_report_sections(sample.sample_id, run.run_id, sections)
            model_path = self.workspace.analysis / "report_model.json"
            self._progress("writing report model JSON")
            atomic_write_text(model_path, json.dumps(model.model_dump(mode="json"), indent=2, sort_keys=True) + "\n")

            self._progress("rendering Markdown report")
            markdown = render_markdown_v2(model)
            markdown_failures = validate_markdown(markdown, model)
            failures = model_failures + markdown_failures
            run.stats.validation_failures = len(failures)

            if "markdown" in self.config.formats:
                markdown_path = self.workspace.report / "report.md"
                atomic_write_text(markdown_path, markdown)
                run.markdown_path = str(markdown_path)
                run.stats.markdown_generated = True
            if "html" in self.config.formats:
                self._progress("rendering HTML report")
                html_path = self.workspace.report / "report.html"
                atomic_write_text(html_path, render_html_v2(model))
                run.html_path = str(html_path)
                run.stats.html_generated = True
            if "pdf" in self.config.formats:
                self._progress("rendering PDF report")
                pdf_path = self.workspace.report / "report.pdf"
                render_pdf_v2(markdown, model, pdf_path)
                run.pdf_path = str(pdf_path)
                run.stats.pdf_generated = True

            run.status = ReportRunStatus.PARTIAL if failures else ReportRunStatus.COMPLETED
            run.error = "; ".join(failures) if failures else None
            run.completed_at = _now()
            self.repository.update_report_run(run)
            self._progress("report generation complete")
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

    def _progress(self, message: str) -> None:
        if self.progress_callback is not None:
            self.progress_callback(message)


def _build_legacy_sections(model: ReportModelV2) -> list[ReportSection]:
    secs = [
        ("executive_summary", "Executive Assessment", model.executive_assessment),
        ("key_findings", "Key Findings", "\n".join(f.summary for f in model.key_findings)),
        ("sample_profile", "Sample Profile", model.sample.observed_role),
        ("execution_chain", "Malware Execution Chain", "\n".join(s.description for s in model.execution_chain)),
        ("technical_analysis", "Technical Analysis", "\n\n".join(f"{s.title}: {s.narrative}" for s in model.technical_analysis)),
        ("reverse_engineering", "Reverse Engineering Findings", "\n".join(f"{f.display_name}: {f.role}" for f in model.key_functions)),
        ("threat_intelligence", "Threat Analysis & Attribution", model.threat_intelligence.development_context),
        ("iocs", "Indicators of Compromise & Artifacts", "\n".join(f"{i.ioc_type}: {i.value}" for i in model.indicators)),
        ("mitre_attack", "MITRE ATT&CK Mappings", "\n".join(f"{a.technique_id}: {a.technique}" for a in model.attack_mappings)),
        ("detection_hunting", "Detection & Threat Hunting", "\n".join(h.lead_title for h in model.hunting_leads)),
        ("analytical_gaps", "Analytical Gaps & Uncertainty", "\n".join(g.title for g in model.analytical_gaps)),
        ("appendix", "Technical Appendix", model.appendix.companion_idb),
    ]
    res: list[ReportSection] = []
    for s_id, title, narr in secs:
        fp = hashlib.sha256(f"{s_id}:{title}:{narr}".encode("utf-8")).hexdigest()
        res.append(ReportSection(
            section_id=s_id,
            title=title,
            status=ReportSectionStatus.GENERATED,
            fingerprint=fp,
            source_facts={"section_id": s_id},
            narrative=narr,
        ))
    return res


def _run_id() -> str:
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
    return f"report_{timestamp}_{uuid.uuid4().hex[:8]}"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()
