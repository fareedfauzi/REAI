from __future__ import annotations

import json
import logging
from enum import StrEnum
from pathlib import Path
from typing import Callable

from pydantic import BaseModel, ConfigDict

from reai.batch.summary import new_batch_id, write_batch_outputs
from reai.analysis.enrich_only import build_enrich_only_candidates
from reai.analysis.engine import MalwareUnderstandingEngine
from reai.analysis.schemas import SemanticAnalysisStats
from reai.core.config import ApplicationConfig
from reai.core.exceptions import AIProviderError, EnrichmentError, IDAAnalysisError, IDAUnavailableError, InputValidationError, ReportError, WorkspaceError
from reai.core.jobs import AnalysisJob
from reai.core.sample import Sample, utc_now
from reai.core.states import JobStatus, SampleState
from reai.ai.analyzer import BottomUpAIAnalyzer
from reai.ai.schemas import AIAnalysisStats
from reai.enrichment.idb import IDBEnricher
from reai.enrichment.schemas import EnrichmentStats
from reai.extraction.models import ExtractionStats
from reai.extraction.pipeline import export_bundle, load_exported_stats
from reai.extraction.serialization import atomic_write_text
from reai.ida.manager import IDAManager
from reai.mcp.client import MCPError
from reai.mcp.investigator import MCPInvestigator
from reai.mcp.schemas import MCPInvestigationStats
from reai.reporting.generator import ReportGenerator
from reai.reporting.schemas import ReportStats
from reai.storage.database import initialize_database
from reai.storage.repository import AnalysisRepository
from reai.utils.hashing import hash_file
from reai.utils.locks import WorkspaceLock
from reai.utils.logging import configure_logging
from reai.utils.paths import WorkspacePaths, find_workspace_by_sha256, is_relative_to
from reai.utils.redaction import redact_secrets
from reai.utils.retry import RetryClass, classify_exception

LOGGER = logging.getLogger("reai.orchestrator")


ProgressCallback = Callable[[str], None]


STATE_PROGRESS_MESSAGES: dict[SampleState, str] = {
    SampleState.DISCOVERED: "Phase 1: sample discovered",
    SampleState.INITIALIZING: "Phase 1: creating workspace and database",
    SampleState.INITIALIZED: "Phase 1: initialization complete",
    SampleState.IDA_ANALYSIS: "Phase 2: waiting for IDA auto-analysis",
    SampleState.EXTRACTING: "Phase 2: persisting extracted artifacts",
    SampleState.GRAPH_BUILDING: "Phase 2: building call graph and recursion metadata",
    SampleState.READY_FOR_ANALYSIS: "Phase 2: deterministic extraction complete",
    SampleState.ANALYZING: "Phase 3: analyzing target functions bottom-up with AI",
    SampleState.AI_ANALYZED: "Phase 3: AI function findings saved",
    SampleState.INVESTIGATING: "Phase 4: investigating uncertain functions with read-only MCP tools",
    SampleState.MCP_INVESTIGATED: "Phase 4: MCP evidence and refinements saved",
    SampleState.PROPAGATING: "Phase 5: propagating context across functions and artifacts",
    SampleState.VALIDATING: "Phase 5: validating names, behaviors, IOCs, and IDB change candidates",
    SampleState.VALIDATED: "Phase 5: semantic validation complete",
    SampleState.ENRICHING: "Phase 6: applying validated renames and comments to analyzed IDB",
    SampleState.ENRICHED: "Phase 6: IDB enrichment verified",
    SampleState.REPORTING: "Phase 7: writing evidence-backed Markdown, HTML, and PDF reports",
    SampleState.COMPLETE: "Phase 7: analysis complete",
    SampleState.FAILED_IDA: "Phase 2: IDA analysis failed",
    SampleState.FAILED_EXTRACTION: "Phase 2: extraction failed",
    SampleState.FAILED_AI: "Phase 3: AI analysis failed",
    SampleState.FAILED_MCP: "Phase 4: MCP investigation failed",
    SampleState.FAILED_PROPAGATION: "Phase 5: propagation failed",
    SampleState.FAILED_VALIDATION: "Phase 5: validation failed",
    SampleState.FAILED_ENRICHMENT: "Phase 6: enrichment failed",
    SampleState.FAILED_REPORT: "Phase 7: report generation failed",
}


class InputKind(StrEnum):
    FILE = "FILE"
    DIRECTORY = "DIRECTORY"
    INVALID = "INVALID"


class ResultStatus(StrEnum):
    INITIALIZED = "INITIALIZED"
    EXISTING = "EXISTING"
    DUPLICATE = "DUPLICATE"
    READY_FOR_ANALYSIS = "READY_FOR_ANALYSIS"
    AI_ANALYZED = "AI_ANALYZED"
    MCP_INVESTIGATED = "MCP_INVESTIGATED"
    VALIDATED = "VALIDATED"
    ENRICHED = "ENRICHED"
    COMPLETE = "COMPLETE"
    FAILED = "FAILED"


class SampleResult(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True)

    sample: Sample
    workspace: WorkspacePaths
    status: ResultStatus
    job: AnalysisJob | None = None
    duplicate_of: str | None = None
    extraction_stats: ExtractionStats | None = None
    ida_version: str | None = None
    ai_stats: AIAnalysisStats | None = None
    mcp_stats: MCPInvestigationStats | None = None
    semantic_stats: SemanticAnalysisStats | None = None
    enrichment_stats: EnrichmentStats | None = None
    report_stats: ReportStats | None = None
    error: str | None = None
    error_type: str | None = None


class AnalysisRunResult(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True)

    input_path: Path
    input_kind: InputKind
    output_root: Path
    workers: int
    recursive: bool
    samples: list[SampleResult]
    skipped: list[str] = []
    batch_id: str | None = None
    started_at: str | None = None
    completed_at: str | None = None

    @property
    def initialized_count(self) -> int:
        return sum(1 for sample in self.samples if sample.status == ResultStatus.INITIALIZED)

    @property
    def duplicate_count(self) -> int:
        return sum(1 for sample in self.samples if sample.status == ResultStatus.DUPLICATE)

    @property
    def existing_count(self) -> int:
        return sum(1 for sample in self.samples if sample.status == ResultStatus.EXISTING)

    @property
    def failed_count(self) -> int:
        return sum(1 for sample in self.samples if sample.status == ResultStatus.FAILED)

    @property
    def complete_count(self) -> int:
        return sum(1 for sample in self.samples if sample.status == ResultStatus.COMPLETE)


class AnalysisOrchestrator:
    def __init__(
        self,
        config: ApplicationConfig,
        *,
        progress_callback: ProgressCallback | None = None,
        enrich_idb_only: bool = False,
    ) -> None:
        self.config = config
        self.output_root = config.output_dir
        self._progress_callback = progress_callback
        self.enrich_idb_only = enrich_idb_only

    def analyze(self, input_path: Path) -> AnalysisRunResult:
        action = "IDB enrichment" if self.enrich_idb_only else "analysis"
        self._progress(f"Starting REAI {action} for {input_path}")
        started_at = utc_now().isoformat()
        batch_id = new_batch_id()
        result = self.initialize(input_path)
        result.batch_id = batch_id
        result.started_at = started_at
        try:
            for item in result.samples:
                if item.status == ResultStatus.DUPLICATE:
                    continue
                try:
                    with WorkspaceLock(item.workspace.root, stale_seconds=self.config.reliability.lock_stale_seconds):
                        self._run_sample_pipeline(item)
                except IDAUnavailableError:
                    raise
                except (KeyboardInterrupt, SystemExit):
                    raise
                except Exception as exc:
                    if classify_exception(exc) == RetryClass.AUTHENTICATION:
                        self._record_sample_failure(item, exc)
                        raise
                    if result.input_kind == InputKind.FILE:
                        self._record_sample_failure(item, exc)
                        raise
                    self._record_sample_failure(item, exc)
                    LOGGER.error(
                        "sample failed sample=%s error_type=%s error=%s",
                        item.sample.filename,
                        item.error_type,
                        item.error,
                    )
        finally:
            result.completed_at = utc_now().isoformat()
            if result.input_kind == InputKind.DIRECTORY:
                write_batch_outputs(result, batch_id=batch_id, started_at=started_at, completed_at=result.completed_at)
            self._progress("REAI analysis finished")
        return result

    def _progress(self, message: str) -> None:
        if self._progress_callback is None:
            return
        self._progress_callback(message)

    def _progress_state(self, item: SampleResult, state: SampleState) -> None:
        self._progress_sample_state(item.sample.filename, state)

    def _progress_sample_state(self, filename: str, state: SampleState) -> None:
        label = STATE_PROGRESS_MESSAGES.get(state, state.value)
        self._progress(f"{filename}: {label}")

    def _sample_phase_progress(self, item: SampleResult, phase: int) -> ProgressCallback:
        def progress(detail: str) -> None:
            self._progress(f"{item.sample.filename}: Phase {phase}: {detail}")

        return progress

    def _run_sample_pipeline(self, item: SampleResult) -> None:
        if self.enrich_idb_only:
            self._run_enrich_idb_pipeline(item)
            return

        attempts = self.config.reliability.sample_retry_limit + 1
        for attempt in range(1, attempts + 1):
            try:
                suffix = f" (attempt {attempt}/{attempts})" if attempts > 1 else ""
                self._progress(f"{item.sample.filename}: starting analysis pipeline{suffix}")
                self._run_phase2(item)
                self._run_phase3(item)
                self._run_phase4(item)
                self._run_phase5(item)
                self._run_phase6(item)
                self._run_phase7(item)
                return
            except Exception as exc:
                retry_class = classify_exception(exc)
                if attempt >= attempts or retry_class in {RetryClass.AUTHENTICATION, RetryClass.PERMANENT, RetryClass.RESOURCE_UNAVAILABLE}:
                    raise
                LOGGER.warning("retrying sample=%s attempt=%s error=%s", item.sample.filename, attempt, redact_secrets(exc))

    def _run_enrich_idb_pipeline(self, item: SampleResult) -> None:
        attempts = self.config.reliability.sample_retry_limit + 1
        for attempt in range(1, attempts + 1):
            try:
                suffix = f" (attempt {attempt}/{attempts})" if attempts > 1 else ""
                self._progress(f"{item.sample.filename}: starting IDB enrichment pipeline{suffix}")
                self._run_phase2(item)
                if item.status == ResultStatus.READY_FOR_ANALYSIS:
                    self._run_phase3(item)
                self._run_enrich_idb_candidates(item)
                self._run_enrich_idb_apply(item)
                return
            except Exception as exc:
                retry_class = classify_exception(exc)
                if attempt >= attempts or retry_class in {RetryClass.AUTHENTICATION, RetryClass.PERMANENT, RetryClass.RESOURCE_UNAVAILABLE}:
                    raise
                LOGGER.warning("retrying enrichidb sample=%s attempt=%s error=%s", item.sample.filename, attempt, redact_secrets(exc))

    def _record_sample_failure(self, item: SampleResult, exc: Exception) -> None:
        item.status = ResultStatus.FAILED
        item.error_type = exc.__class__.__name__
        item.error = redact_secrets(exc)
        self._progress(f"{item.sample.filename}: analysis failed - {item.error_type}")
        try:
            repository = AnalysisRepository(item.workspace.database)
            stored = repository.get_sample(item.sample.sample_id)
            if stored is not None:
                item.sample = stored
        except Exception:
            pass

    def initialize(self, input_path: Path) -> AnalysisRunResult:
        LOGGER.info("startup")
        LOGGER.info("configuration output_dir=%s workers=%s recursive=%s", self.output_root, self.config.workers, self.config.recursive)
        self._progress("Discovering input samples")

        resolved_input = input_path.expanduser()
        input_kind = self._detect_input_kind(resolved_input)
        if input_kind == InputKind.INVALID:
            raise InputValidationError(f"Input does not exist:\n{input_path}")

        self._ensure_output_root()
        candidates, skipped = self._discover_samples(resolved_input, input_kind)
        if not candidates:
            raise InputValidationError(f"No non-empty regular files were discovered:\n{input_path}")

        results: list[SampleResult] = []
        seen_sha256: dict[str, SampleResult] = {}

        for candidate in candidates:
            LOGGER.info("hashing %s", candidate)
            self._progress(f"Hashing {candidate.name}")
            hashes = hash_file(candidate)
            existing = seen_sha256.get(hashes.sha256)
            if existing is not None:
                duplicate_sample = Sample.from_file_hashes(
                    source_path=candidate,
                    hashes=hashes,
                    workspace=existing.workspace,
                    status=SampleState.INITIALIZED,
                )
                results.append(
                    SampleResult(
                        sample=duplicate_sample,
                        workspace=existing.workspace,
                        status=ResultStatus.DUPLICATE,
                        duplicate_of=existing.sample.source_path.name,
                    )
                )
                continue

            result = self._initialize_sample(candidate, hashes)
            seen_sha256[hashes.sha256] = result
            results.append(result)

        return AnalysisRunResult(
            input_path=input_path,
            input_kind=input_kind,
            output_root=self.output_root,
            workers=self.config.workers,
            recursive=self.config.recursive,
            samples=results,
            skipped=skipped,
        )

    def _detect_input_kind(self, input_path: Path) -> InputKind:
        if not input_path.exists():
            return InputKind.INVALID
        if input_path.is_file():
            return InputKind.FILE
        if input_path.is_dir():
            return InputKind.DIRECTORY
        return InputKind.INVALID

    def _discover_samples(self, input_path: Path, input_kind: InputKind) -> tuple[list[Path], list[str]]:
        LOGGER.info("input discovery kind=%s path=%s", input_kind, input_path)
        if input_kind == InputKind.FILE:
            return [self._validate_file(input_path)], []

        iterator = input_path.rglob("*") if self.config.recursive else input_path.iterdir()
        samples: list[Path] = []
        skipped: list[str] = []

        for candidate in sorted(iterator, key=lambda path: str(path).lower()):
            if candidate.is_symlink():
                skipped.append(f"symlink: {candidate}")
                continue
            if candidate.is_dir():
                continue
            if self.output_root.exists() and is_relative_to(candidate, self.output_root):
                skipped.append(f"reai output: {candidate}")
                continue
            if candidate.name in {".DS_Store", "Thumbs.db", "desktop.ini"} or candidate.name.startswith("~$"):
                skipped.append(f"metadata/temp: {candidate}")
                continue
            try:
                samples.append(self._validate_file(candidate))
            except InputValidationError as exc:
                skipped.append(str(exc).replace("\n", " "))

        return samples, skipped

    def _validate_file(self, path: Path) -> Path:
        if path.is_symlink():
            raise InputValidationError(f"Input file is a symlink and will not be analyzed:\n{path}")
        if not path.exists():
            raise InputValidationError(f"Input does not exist:\n{path}")
        if not path.is_file():
            raise InputValidationError(f"Input is not a regular file:\n{path}")
        try:
            size = path.stat().st_size
        except OSError as exc:
            raise InputValidationError(f"Unable to inspect input file:\n{path}") from exc
        if size == 0:
            raise InputValidationError(f"Input file is empty:\n{path}")
        try:
            with path.open("rb") as handle:
                handle.read(1)
        except OSError as exc:
            raise InputValidationError(f"Input file is not readable:\n{path}") from exc
        return path

    def _ensure_output_root(self) -> None:
        try:
            self.output_root.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            raise WorkspaceError(f"Unable to create output directory:\n{self.output_root}") from exc

    def _initialize_sample(self, source_path: Path, hashes) -> SampleResult:
        self._progress(f"{source_path.name}: checking workspace")
        workspace = find_workspace_by_sha256(self.output_root, hashes.sha256)
        existing = workspace is not None
        if workspace is None:
            workspace = WorkspacePaths.for_sample(self.output_root, source_path.name, hashes.md5)

        sample = Sample.from_file_hashes(
            source_path=source_path,
            hashes=hashes,
            workspace=workspace,
            status=SampleState.DISCOVERED,
        )

        if existing:
            self._verify_existing_workspace(workspace, hashes.sha256)
            removed_legacy_dirs = workspace.cleanup_legacy_empty_directories()
            configure_logging(workspace.logs / "reai.log", verbose=self.config.verbose)
            LOGGER.info("startup")
            LOGGER.info("configuration output_dir=%s workers=%s recursive=%s", self.output_root, self.config.workers, self.config.recursive)
            LOGGER.info("input discovery source=%s", source_path)
            LOGGER.info("hashing complete sha256=%s size=%s", hashes.sha256, hashes.size)
            LOGGER.info("existing workspace detected %s", workspace.root)
            for legacy_dir in removed_legacy_dirs:
                LOGGER.info("removed empty legacy workspace directory %s", legacy_dir)
            self._progress(f"{source_path.name}: resuming existing workspace")
            configure_logging(None, verbose=self.config.verbose)
            return SampleResult(sample=sample, workspace=workspace, status=ResultStatus.EXISTING)

        LOGGER.info("workspace creation %s", workspace.root)
        self._progress(f"{source_path.name}: creating workspace")
        try:
            workspace.create_directories()
        except OSError as exc:
            raise WorkspaceError(f"Unable to create sample workspace:\n{workspace.root}") from exc

        configure_logging(workspace.logs / "reai.log", verbose=self.config.verbose)
        LOGGER.info("startup")
        LOGGER.info("configuration output_dir=%s workers=%s recursive=%s", self.output_root, self.config.workers, self.config.recursive)
        LOGGER.info("input discovery source=%s", source_path)
        LOGGER.info("hashing complete sha256=%s size=%s", hashes.sha256, hashes.size)
        LOGGER.info("workspace creation %s", workspace.root)
        LOGGER.info("database initialization %s", workspace.database)
        initialize_database(workspace.database)
        repository = AnalysisRepository(workspace.database)
        repository.create_sample(sample)
        LOGGER.info("state transition %s", SampleState.DISCOVERED)
        self._progress_sample_state(sample.filename, SampleState.DISCOVERED)
        repository.record_state_transition(
            sample.sample_id,
            None,
            SampleState.DISCOVERED,
            message="Sample discovered and identity calculated.",
        )
        LOGGER.info("state transition %s", SampleState.INITIALIZING)
        self._progress_sample_state(sample.filename, SampleState.INITIALIZING)
        repository.update_sample_state(
            sample.sample_id,
            SampleState.INITIALIZING,
            message="Creating Phase 1 workspace and persistent state.",
        )

        job = AnalysisJob.create(
            sample.sample_id,
            run_config={
                "output_dir": str(self.output_root),
                "recursive": self.config.recursive,
                "workers": self.config.workers,
            },
        )
        job.started_at = utc_now()
        job.status = JobStatus.RUNNING
        job.updated_at = utc_now()
        repository.create_job(job)
        LOGGER.info("job created %s", job.job_id)

        LOGGER.info("state transition %s", SampleState.INITIALIZED)
        self._progress_sample_state(sample.filename, SampleState.INITIALIZED)
        repository.update_sample_state(
            sample.sample_id,
            SampleState.INITIALIZED,
            message="Phase 1 initialization complete.",
        )
        job.completed_at = utc_now()
        repository.update_job(job.job_id, JobStatus.COMPLETED, completed_at=job.completed_at)

        stored = repository.get_sample(sample.sample_id)
        if stored is None:
            raise WorkspaceError("Sample state was not persisted correctly.")
        self._write_sample_metadata(workspace, stored)
        LOGGER.info("metadata stored %s", workspace.sample_metadata)
        configure_logging(None, verbose=self.config.verbose)

        return SampleResult(
            sample=stored,
            workspace=workspace,
            status=ResultStatus.INITIALIZED,
            job=job,
        )

    def _run_phase2(self, item: SampleResult) -> None:
        initialize_database(item.workspace.database)
        repository = AnalysisRepository(item.workspace.database)
        stored = repository.get_sample(item.sample.sample_id)
        if stored is None:
            raise WorkspaceError(f"Existing workspace database is missing sample record:\n{item.workspace.root}")
        item.sample = stored

        if stored.status in {
            SampleState.READY_FOR_ANALYSIS,
            SampleState.ANALYZING,
            SampleState.AI_ANALYZED,
            SampleState.INVESTIGATING,
            SampleState.MCP_INVESTIGATED,
            SampleState.PROPAGATING,
            SampleState.VALIDATING,
            SampleState.VALIDATED,
            SampleState.ENRICHING,
            SampleState.ENRICHED,
            SampleState.REPORTING,
            SampleState.COMPLETE,
        }:
            stats = load_exported_stats(item.workspace)
            item.extraction_stats = stats
            resume_state = self._artifact_adjusted_state(stored.status, item.workspace, repository, item.sample.sample_id)
            if resume_state in {SampleState.VALIDATED, SampleState.ENRICHING, SampleState.ENRICHED, SampleState.REPORTING, SampleState.COMPLETE}:
                item.semantic_stats = repository.calculate_semantic_stats(item.sample.sample_id)
                item.mcp_stats = repository.calculate_mcp_stats(item.sample.sample_id)
                item.ai_stats = repository.calculate_ai_stats(item.sample.sample_id)
                if resume_state == SampleState.COMPLETE:
                    item.status = ResultStatus.COMPLETE
                    item.enrichment_stats = repository.calculate_enrichment_stats(item.sample.sample_id)
                    item.report_stats = repository.calculate_report_stats(item.sample.sample_id)
                elif resume_state in {SampleState.ENRICHED, SampleState.REPORTING}:
                    item.status = ResultStatus.ENRICHED
                    item.enrichment_stats = repository.calculate_enrichment_stats(item.sample.sample_id)
                else:
                    item.status = ResultStatus.VALIDATED
                return
            elif resume_state in {SampleState.MCP_INVESTIGATED, SampleState.PROPAGATING, SampleState.VALIDATING}:
                item.status = ResultStatus.MCP_INVESTIGATED
                item.mcp_stats = repository.calculate_mcp_stats(item.sample.sample_id)
                item.ai_stats = repository.calculate_ai_stats(item.sample.sample_id)
                return
            elif resume_state in {SampleState.AI_ANALYZED, SampleState.INVESTIGATING}:
                item.status = ResultStatus.AI_ANALYZED
                item.ai_stats = repository.calculate_ai_stats(item.sample.sample_id)
                return
            elif resume_state == SampleState.READY_FOR_ANALYSIS:
                item.status = ResultStatus.READY_FOR_ANALYSIS
                return
            else:
                LOGGER.warning("checkpoint artifacts stale; rerunning Phase 2 for sample=%s state=%s", item.sample.filename, stored.status)
                stored = stored.model_copy(update={"status": resume_state})
                item.sample = stored
                # Fall through to Phase 2 rerun when extraction artifacts are stale.
                if resume_state not in {SampleState.INITIALIZED, SampleState.IDA_ANALYSIS, SampleState.EXTRACTING, SampleState.GRAPH_BUILDING}:
                    return

        configure_logging(item.workspace.logs / "reai.log", verbose=self.config.verbose)
        try:
            LOGGER.info("state transition %s", SampleState.IDA_ANALYSIS)
            self._progress_state(item, SampleState.IDA_ANALYSIS)
            repository.update_sample_state(
                item.sample.sample_id,
                SampleState.IDA_ANALYSIS,
                message="Starting IDA auto-analysis.",
            )
            ida_manager = IDAManager(self.config.ida, progress_callback=self._progress)
            ida_result = ida_manager.analyze(item.sample.source_path, item.workspace)

            LOGGER.info("state transition %s", SampleState.EXTRACTING)
            self._progress_state(item, SampleState.EXTRACTING)
            repository.update_sample_state(
                item.sample.sample_id,
                SampleState.EXTRACTING,
                message="Persisting deterministic bulk extraction.",
            )
            stats = export_bundle(item.workspace, ida_result.bundle)
            repository.persist_extraction(item.sample.sample_id, ida_result.bundle)
            LOGGER.info("extraction persisted")
            
            if stats.total_functions == 0:
                raise ValueError("File contains no executable code or functions. Is this a supported binary?")

            LOGGER.info("state transition %s", SampleState.GRAPH_BUILDING)
            self._progress_state(item, SampleState.GRAPH_BUILDING)
            repository.update_sample_state(
                item.sample.sample_id,
                SampleState.GRAPH_BUILDING,
                message="Call graph and SCC metadata persisted.",
            )

            LOGGER.info("state transition %s", SampleState.READY_FOR_ANALYSIS)
            self._progress_state(item, SampleState.READY_FOR_ANALYSIS)
            repository.update_sample_state(
                item.sample.sample_id,
                SampleState.READY_FOR_ANALYSIS,
                message="Phase 2 deterministic extraction complete.",
            )
            ready_sample = repository.get_sample(item.sample.sample_id)
            if ready_sample is not None:
                item.sample = ready_sample
                self._write_sample_metadata(item.workspace, ready_sample)
            item.extraction_stats = stats
            item.ida_version = ida_result.bundle.metadata.ida_version
            item.status = ResultStatus.READY_FOR_ANALYSIS
        except (IDAAnalysisError, IDAUnavailableError):
            repository.update_sample_state(
                item.sample.sample_id,
                SampleState.FAILED_IDA,
                message="IDA analysis failed or environment was unavailable.",
            )
            failed_sample = repository.get_sample(item.sample.sample_id)
            if failed_sample is not None:
                self._write_sample_metadata(item.workspace, failed_sample)
            raise
        except Exception as exc:
            msg = str(exc) if isinstance(exc, ValueError) else "Bulk extraction failed."
            repository.update_sample_state(
                item.sample.sample_id,
                SampleState.FAILED_EXTRACTION,
                message=msg,
            )
            failed_sample = repository.get_sample(item.sample.sample_id)
            if failed_sample is not None:
                self._write_sample_metadata(item.workspace, failed_sample)
            raise
        finally:
            configure_logging(None, verbose=self.config.verbose)

    def _run_phase5(self, item: SampleResult) -> None:
        if item.status not in {ResultStatus.AI_ANALYZED, ResultStatus.MCP_INVESTIGATED, ResultStatus.VALIDATED}:
            return
        if not self.config.analysis.enabled:
            # When Phase 5 is disabled, advance status so Phase 6 and 7 can still run.
            if item.status in {ResultStatus.AI_ANALYZED, ResultStatus.MCP_INVESTIGATED}:
                item.status = ResultStatus.VALIDATED
            return
        if item.status == ResultStatus.VALIDATED:
            return

        repository = AnalysisRepository(item.workspace.database)
        configure_logging(item.workspace.logs / "reai.log", verbose=self.config.verbose)
        try:
            LOGGER.info("state transition %s", SampleState.PROPAGATING)
            self._progress_state(item, SampleState.PROPAGATING)
            repository.update_sample_state(
                item.sample.sample_id,
                SampleState.PROPAGATING,
                message="Starting Phase 5 multi-pass context propagation.",
            )
            engine = MalwareUnderstandingEngine(
                self.config.analysis,
                repository,
                item.workspace,
                progress_callback=self._sample_phase_progress(item, 5),
            )
            stats = engine.run(item.sample.sample_id)
            if stats is None:
                return
            LOGGER.info("state transition %s", SampleState.VALIDATING)
            self._progress_state(item, SampleState.VALIDATING)
            repository.update_sample_state(
                item.sample.sample_id,
                SampleState.VALIDATING,
                message="Validating Phase 5 semantic model and change candidates.",
            )
            LOGGER.info("state transition %s", SampleState.VALIDATED)
            self._progress_state(item, SampleState.VALIDATED)
            repository.update_sample_state(
                item.sample.sample_id,
                SampleState.VALIDATED,
                message="Phase 5 validated malware understanding complete.",
            )
            validated_sample = repository.get_sample(item.sample.sample_id)
            if validated_sample is not None:
                item.sample = validated_sample
                self._write_sample_metadata(item.workspace, validated_sample)
            item.semantic_stats = stats
            item.status = ResultStatus.VALIDATED
        except Exception:
            stored = repository.get_sample(item.sample.sample_id)
            if stored is not None and stored.status == SampleState.VALIDATING:
                repository.update_sample_state(
                    item.sample.sample_id,
                    SampleState.FAILED_VALIDATION,
                    message="Phase 5 semantic validation failed.",
                )
            else:
                repository.update_sample_state(
                    item.sample.sample_id,
                    SampleState.FAILED_PROPAGATION,
                    message="Phase 5 context propagation failed.",
                )
            failed_sample = repository.get_sample(item.sample.sample_id)
            if failed_sample is not None:
                self._write_sample_metadata(item.workspace, failed_sample)
            raise
        finally:
            configure_logging(None, verbose=self.config.verbose)

    def _run_enrich_idb_candidates(self, item: SampleResult) -> None:
        if item.status not in {
            ResultStatus.AI_ANALYZED,
            ResultStatus.MCP_INVESTIGATED,
            ResultStatus.VALIDATED,
            ResultStatus.ENRICHED,
            ResultStatus.COMPLETE,
        }:
            return

        repository = AnalysisRepository(item.workspace.database)
        configure_logging(item.workspace.logs / "reai.log", verbose=self.config.verbose)
        try:
            self._progress(f"{item.sample.filename}: Phase 4: building IDB rename/comment candidates")
            repository.update_sample_state(
                item.sample.sample_id,
                SampleState.VALIDATING,
                message="Building IDB-only rename/comment candidates.",
            )
            stats = build_enrich_only_candidates(
                repository,
                item.sample.sample_id,
                self.config.analysis.validation,
                progress_callback=self._sample_phase_progress(item, 4),
            )
            if stats is None:
                raise AIProviderError("No completed AI function findings are available for --enrichidb.")
            self._progress(f"{item.sample.filename}: Phase 4: IDB rename/comment candidates ready")
            repository.update_sample_state(
                item.sample.sample_id,
                SampleState.VALIDATED,
                message="IDB-only rename/comment candidates are ready.",
            )
            validated_sample = repository.get_sample(item.sample.sample_id)
            if validated_sample is not None:
                item.sample = validated_sample
                self._write_sample_metadata(item.workspace, validated_sample)
            item.semantic_stats = stats
            item.status = ResultStatus.VALIDATED
        except Exception:
            repository.update_sample_state(
                item.sample.sample_id,
                SampleState.FAILED_VALIDATION,
                message="IDB-only candidate generation failed.",
            )
            failed_sample = repository.get_sample(item.sample.sample_id)
            if failed_sample is not None:
                self._write_sample_metadata(item.workspace, failed_sample)
            raise
        finally:
            configure_logging(None, verbose=self.config.verbose)

    def _run_enrich_idb_apply(self, item: SampleResult) -> None:
        if item.status != ResultStatus.VALIDATED:
            return

        repository = AnalysisRepository(item.workspace.database)
        configure_logging(item.workspace.logs / "reai.log", verbose=self.config.verbose)
        try:
            self._progress(f"{item.sample.filename}: Phase 4: applying renames, variable names, and comments")
            repository.update_sample_state(
                item.sample.sample_id,
                SampleState.ENRICHING,
                message="Applying IDB-only renames, variable names, and comments.",
            )
            enricher = IDBEnricher(
                self.config.enrichment.model_copy(update={"enabled": True}),
                self.config.ida,
                repository,
                item.workspace,
                progress_callback=self._sample_phase_progress(item, 4),
            )
            stats = enricher.run(item.sample)
            if stats is None:
                return
            self._progress(f"{item.sample.filename}: Phase 4: IDB enrichment complete")
            repository.update_sample_state(
                item.sample.sample_id,
                SampleState.ENRICHED,
                message="IDB-only enrichment complete.",
            )
            enriched_sample = repository.get_sample(item.sample.sample_id)
            if enriched_sample is not None:
                item.sample = enriched_sample
                self._write_sample_metadata(item.workspace, enriched_sample)
            item.enrichment_stats = stats
            item.status = ResultStatus.ENRICHED
        except EnrichmentError:
            repository.update_sample_state(
                item.sample.sample_id,
                SampleState.FAILED_ENRICHMENT,
                message="IDB-only enrichment failed.",
            )
            failed_sample = repository.get_sample(item.sample.sample_id)
            if failed_sample is not None:
                self._write_sample_metadata(item.workspace, failed_sample)
            raise
        finally:
            configure_logging(None, verbose=self.config.verbose)


    def _run_phase6(self, item: SampleResult) -> None:
        if item.status not in {ResultStatus.VALIDATED, ResultStatus.ENRICHED}:
            return
        if not self.config.enrichment.enabled:
            return
        if item.status == ResultStatus.ENRICHED:
            return

        repository = AnalysisRepository(item.workspace.database)
        configure_logging(item.workspace.logs / "reai.log", verbose=self.config.verbose)
        try:
            LOGGER.info("state transition %s", SampleState.ENRICHING)
            self._progress_state(item, SampleState.ENRICHING)
            repository.update_sample_state(
                item.sample.sample_id,
                SampleState.ENRICHING,
                message="Starting Phase 6 IDB enrichment.",
            )
            enricher = IDBEnricher(
                self.config.enrichment,
                self.config.ida,
                repository,
                item.workspace,
                progress_callback=self._sample_phase_progress(item, 6),
            )
            stats = enricher.run(item.sample)
            if stats is None:
                return
            LOGGER.info("state transition %s", SampleState.ENRICHED)
            self._progress_state(item, SampleState.ENRICHED)
            repository.update_sample_state(
                item.sample.sample_id,
                SampleState.ENRICHED,
                message="Phase 6 IDB enrichment complete.",
            )
            enriched_sample = repository.get_sample(item.sample.sample_id)
            if enriched_sample is not None:
                item.sample = enriched_sample
                self._write_sample_metadata(item.workspace, enriched_sample)
            item.enrichment_stats = stats
            item.status = ResultStatus.ENRICHED
        except EnrichmentError:
            repository.update_sample_state(
                item.sample.sample_id,
                SampleState.FAILED_ENRICHMENT,
                message="IDB enrichment failed.",
            )
            failed_sample = repository.get_sample(item.sample.sample_id)
            if failed_sample is not None:
                self._write_sample_metadata(item.workspace, failed_sample)
            raise
        finally:
            configure_logging(None, verbose=self.config.verbose)

    def _run_phase7(self, item: SampleResult) -> None:
        if item.status not in {ResultStatus.VALIDATED, ResultStatus.ENRICHED, ResultStatus.COMPLETE}:
            return
        if not self.config.report.enabled:
            return
        if item.status == ResultStatus.COMPLETE:
            return

        repository = AnalysisRepository(item.workspace.database)
        configure_logging(item.workspace.logs / "reai.log", verbose=self.config.verbose)
        try:
            LOGGER.info("state transition %s", SampleState.REPORTING)
            self._progress_state(item, SampleState.REPORTING)
            repository.update_sample_state(
                item.sample.sample_id,
                SampleState.REPORTING,
                message="Starting Phase 7 evidence-backed report generation.",
            )
            generator = ReportGenerator(
                self.config.report,
                repository,
                item.workspace,
                progress_callback=self._sample_phase_progress(item, 7),
            )
            stats = generator.run(item.sample)
            if stats is None:
                return
            LOGGER.info("state transition %s", SampleState.COMPLETE)
            self._progress_state(item, SampleState.COMPLETE)
            repository.update_sample_state(
                item.sample.sample_id,
                SampleState.COMPLETE,
                message="Phase 7 report generation complete.",
            )
            completed_sample = repository.get_sample(item.sample.sample_id)
            if completed_sample is not None:
                item.sample = completed_sample
                self._write_sample_metadata(item.workspace, completed_sample)
            item.report_stats = stats
            item.status = ResultStatus.COMPLETE
        except ReportError:
            repository.update_sample_state(
                item.sample.sample_id,
                SampleState.FAILED_REPORT,
                message="Report generation failed.",
            )
            failed_sample = repository.get_sample(item.sample.sample_id)
            if failed_sample is not None:
                self._write_sample_metadata(item.workspace, failed_sample)
            raise
        finally:
            configure_logging(None, verbose=self.config.verbose)

    def _run_phase3(self, item: SampleResult) -> None:
        if item.status != ResultStatus.READY_FOR_ANALYSIS:
            return
        if self.config.ai.provider.lower() == "disabled":
            return

        repository = AnalysisRepository(item.workspace.database)
        configure_logging(item.workspace.logs / "reai.log", verbose=self.config.verbose)
        try:
            LOGGER.info("state transition %s", SampleState.ANALYZING)
            self._progress_state(item, SampleState.ANALYZING)
            repository.update_sample_state(
                item.sample.sample_id,
                SampleState.ANALYZING,
                message="Starting Phase 3 bottom-up AI function analysis.",
            )
            analyzer = BottomUpAIAnalyzer(
                self.config.ai,
                repository,
                item.workspace,
                progress_callback=self._sample_phase_progress(item, 3),
            )
            stats = analyzer.run(item.sample.sample_id)
            if stats is None:
                return
            if stats.target_functions > 0 and stats.analyzed == 0:
                raise AIProviderError(
                    "Phase 3 produced no successful function analyses; refusing to advance to semantic validation."
                )
            LOGGER.info("state transition %s", SampleState.AI_ANALYZED)
            self._progress_state(item, SampleState.AI_ANALYZED)
            repository.update_sample_state(
                item.sample.sample_id,
                SampleState.AI_ANALYZED,
                message="Phase 3 bottom-up AI analysis complete.",
            )
            analyzed_sample = repository.get_sample(item.sample.sample_id)
            if analyzed_sample is not None:
                item.sample = analyzed_sample
                self._write_sample_metadata(item.workspace, analyzed_sample)
            item.ai_stats = stats
            item.status = ResultStatus.AI_ANALYZED
        except AIProviderError:
            repository.update_sample_state(
                item.sample.sample_id,
                SampleState.FAILED_AI,
                message="AI provider failed.",
            )
            failed_sample = repository.get_sample(item.sample.sample_id)
            if failed_sample is not None:
                self._write_sample_metadata(item.workspace, failed_sample)
            raise
        finally:
            configure_logging(None, verbose=self.config.verbose)

    def _run_phase4(self, item: SampleResult) -> None:
        if item.status not in {ResultStatus.AI_ANALYZED, ResultStatus.MCP_INVESTIGATED}:
            return
        if not self.config.mcp.enabled or self.config.mcp.provider.lower() == "disabled":
            return
        if item.status == ResultStatus.MCP_INVESTIGATED:
            return

        repository = AnalysisRepository(item.workspace.database)
        configure_logging(item.workspace.logs / "reai.log", verbose=self.config.verbose)
        try:
            LOGGER.info("state transition %s", SampleState.INVESTIGATING)
            self._progress_state(item, SampleState.INVESTIGATING)
            repository.update_sample_state(
                item.sample.sample_id,
                SampleState.INVESTIGATING,
                message="Starting Phase 4 autonomous MCP investigation.",
            )
            investigator = MCPInvestigator(
                self.config.mcp,
                repository,
                item.workspace,
                progress_callback=self._sample_phase_progress(item, 4),
            )
            stats = investigator.run(item.sample.sample_id)
            if stats is None:
                return
            LOGGER.info("state transition %s", SampleState.MCP_INVESTIGATED)
            self._progress_state(item, SampleState.MCP_INVESTIGATED)
            repository.update_sample_state(
                item.sample.sample_id,
                SampleState.MCP_INVESTIGATED,
                message="Phase 4 autonomous MCP investigation complete.",
            )
            investigated_sample = repository.get_sample(item.sample.sample_id)
            if investigated_sample is not None:
                item.sample = investigated_sample
                self._write_sample_metadata(item.workspace, investigated_sample)
            item.mcp_stats = stats
            item.status = ResultStatus.MCP_INVESTIGATED
        except MCPError:
            repository.update_sample_state(
                item.sample.sample_id,
                SampleState.FAILED_MCP,
                message="MCP investigation failed.",
            )
            failed_sample = repository.get_sample(item.sample.sample_id)
            if failed_sample is not None:
                self._write_sample_metadata(item.workspace, failed_sample)
            raise
        finally:
            configure_logging(None, verbose=self.config.verbose)

    def _verify_existing_workspace(self, workspace: WorkspacePaths, sha256: str) -> None:
        if not workspace.sample_metadata.exists() or not workspace.database.exists():
            raise WorkspaceError(f"Existing workspace is incomplete:\n{workspace.root}")
        data = json.loads(workspace.sample_metadata.read_text(encoding="utf-8"))
        if data.get("sha256") != sha256:
            raise WorkspaceError(f"Existing workspace SHA256 mismatch:\n{workspace.root}")

    def _artifact_adjusted_state(
        self,
        state: SampleState,
        workspace: WorkspacePaths,
        repository: AnalysisRepository,
        sample_id: str,
    ) -> SampleState:
        # FAILED_* states must be remapped to their retryable predecessor so
        # resume and the retry loop actually re-run the failed phase instead of
        # silently no-oping and reporting fake success.
        if state in {SampleState.FAILED_IDA, SampleState.FAILED_EXTRACTION}:
            return SampleState.INITIALIZED
        if state == SampleState.FAILED_AI:
            return SampleState.READY_FOR_ANALYSIS
        if state == SampleState.FAILED_MCP:
            return SampleState.AI_ANALYZED
        if state in {SampleState.FAILED_PROPAGATION, SampleState.FAILED_VALIDATION}:
            return SampleState.MCP_INVESTIGATED
        if state == SampleState.FAILED_ENRICHMENT:
            return SampleState.VALIDATED
        if state == SampleState.FAILED_REPORT:
            return SampleState.ENRICHED

        if state in {
            SampleState.READY_FOR_ANALYSIS,
            SampleState.ANALYZING,
            SampleState.AI_ANALYZED,
            SampleState.INVESTIGATING,
            SampleState.MCP_INVESTIGATED,
            SampleState.PROPAGATING,
            SampleState.VALIDATING,
            SampleState.VALIDATED,
            SampleState.ENRICHING,
            SampleState.ENRICHED,
            SampleState.REPORTING,
            SampleState.COMPLETE,
        } and not self._phase2_artifacts_valid(workspace, repository, sample_id):
            return SampleState.INITIALIZED
        if state in {SampleState.VALIDATED, SampleState.ENRICHING, SampleState.ENRICHED, SampleState.REPORTING, SampleState.COMPLETE}:
            if not repository.get_validated_function_finding_rows(sample_id):
                return SampleState.AI_ANALYZED
        if state in {SampleState.ENRICHED, SampleState.REPORTING, SampleState.COMPLETE}:
            if not self._phase6_artifacts_valid(workspace, repository, sample_id):
                return SampleState.VALIDATED
        if state == SampleState.COMPLETE and not self._phase7_artifacts_valid(workspace, repository, sample_id):
            return SampleState.ENRICHED
        if state == SampleState.REPORTING:
            return SampleState.ENRICHED
        if state == SampleState.ENRICHING:
            return SampleState.VALIDATED
        if state == SampleState.VALIDATING:
            return SampleState.MCP_INVESTIGATED
        if state == SampleState.PROPAGATING:
            return SampleState.MCP_INVESTIGATED
        if state == SampleState.INVESTIGATING:
            return SampleState.AI_ANALYZED
        if state == SampleState.ANALYZING:
            return SampleState.READY_FOR_ANALYSIS
        return state


    def _phase2_artifacts_valid(self, workspace: WorkspacePaths, repository: AnalysisRepository, sample_id: str) -> bool:
        return bool(repository.list_extracted_functions(sample_id))

    def _phase6_artifacts_valid(self, workspace: WorkspacePaths, repository: AnalysisRepository, sample_id: str) -> bool:
        latest = repository.get_latest_enrichment_run(sample_id)
        return bool(
            latest
            and latest.get("status") == "COMPLETED"
            and (workspace.ida / f"analyzed{self.config.ida.database_extension}").exists()
        )

    def _phase7_artifacts_valid(self, workspace: WorkspacePaths, repository: AnalysisRepository, sample_id: str) -> bool:
        latest = repository.get_latest_report_run(sample_id)
        if not latest or latest.get("status") not in {"COMPLETED", "PARTIAL"}:
            return False
        required = {
            "markdown": workspace.report / "report.md",
            "html": workspace.report / "report.html",
            "pdf": workspace.report / "report.pdf",
        }
        return all(required[fmt].exists() for fmt in self.config.report.formats)

    def _write_sample_metadata(self, workspace: WorkspacePaths, sample: Sample) -> None:
        data = sample.model_dump(mode="json")
        atomic_write_text(workspace.sample_metadata, json.dumps(data, indent=2, sort_keys=True) + "\n")
