from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from reai.core.jobs import AnalysisJob
from reai.core.sample import Sample, utc_now
from reai.core.states import JobStatus, SampleState
from reai.ai.schemas import AIAnalysisStats, AIRequestMetadata, FunctionAnalysisResult
from reai.analysis.schemas import SemanticAnalysisStats, ValidatedAnalysisModel
from reai.enrichment.schemas import EnrichmentChange, EnrichmentRun, EnrichmentStats, IDBVerification
from reai.reporting.schemas import ReportRun, ReportSection, ReportStats
from reai.extraction.models import ExtractionBundle
from reai.mcp.schemas import (
    AnalyticalImportance,
    MCPEvidence,
    MCPInvestigationStats,
    MCPSessionMetadata,
    MCPToolResult,
    READ_ONLY_CAPABILITIES,
    InvestigationQuestion,
    InvestigationOutcome,
    InvestigationStatus,
    InvestigationTarget,
    QuestionStatus,
)
from reai.mcp.importance import classify_importance
from reai.mcp.questions import generate_investigation_questions
from reai.storage.database import connect_database
from reai.utils.address import format_address
from reai.utils.names import is_ida_placeholder_name


def _dt(value):
    return value.isoformat() if value is not None else None


def _mcp_priority(row: sqlite3.Row, unknowns: list[str]) -> tuple[float, str]:
    score = 0.0
    reasons: list[str] = []
    confidence = float(row["confidence"])
    caller_count = int(row["caller_count"] or 0)
    callee_count = int(row["callee_count"] or 0)

    if row["confidence_label"] == "LOW":
        score += 50
        reasons.append("LOW confidence")
    elif row["confidence_label"] == "MEDIUM":
        score += 20
        reasons.append("MEDIUM confidence")
    if row["status"] == "FAILED":
        score += 30
        reasons.append("Phase 3 failed")
    if row["needs_investigation"]:
        score += 25
        reasons.append("marked needs_investigation")
    if unknowns:
        score += min(30, len(unknowns) * 8)
        reasons.append(f"{len(unknowns)} unresolved question(s)")
    if caller_count:
        score += min(40, caller_count * 4)
        reasons.append(f"{caller_count} caller(s)")
    if callee_count:
        score += min(10, callee_count)
    score += max(0.0, (1.0 - confidence) * 20)
    return round(score, 3), ", ".join(reasons) or "low-priority investigation candidate"


def _should_investigate(row: sqlite3.Row, importance: AnalyticalImportance, questions: list[InvestigationQuestion]) -> bool:
    if row["status"] == "FAILED":
        return True
    if row["needs_investigation"] or row["confidence_label"] == "LOW":
        return True
    if importance == AnalyticalImportance.HIGH and questions:
        return True
    if importance == AnalyticalImportance.MEDIUM and row["confidence_label"] != "HIGH" and questions:
        return True
    return False


class AnalysisRepository:
    def __init__(self, database_path: Path) -> None:
        self.database_path = database_path

    def _connect(self) -> sqlite3.Connection:
        return connect_database(self.database_path)

    def create_sample(self, sample: Sample) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                INSERT OR IGNORE INTO samples (
                    sample_id, filename, source_path, size, md5, sha1, sha256,
                    workspace_path, status, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    sample.sample_id,
                    sample.filename,
                    str(sample.source_path),
                    sample.size,
                    sample.md5,
                    sample.sha1,
                    sample.sha256,
                    str(sample.workspace_path),
                    sample.status.value,
                    _dt(sample.created_at),
                    _dt(sample.updated_at),
                ),
            )
            connection.commit()

    def get_sample(self, sample_id: str) -> Sample | None:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM samples WHERE sample_id = ?", (sample_id,)
            ).fetchone()
        return self._row_to_sample(row) if row is not None else None

    def update_sample_state(
        self,
        sample_id: str,
        new_state: SampleState,
        *,
        message: str | None = None,
    ) -> SampleState | None:
        now = utc_now()
        with self._connect() as connection:
            row = connection.execute(
                "SELECT status FROM samples WHERE sample_id = ?", (sample_id,)
            ).fetchone()
            previous = SampleState(row["status"]) if row is not None else None
            connection.execute(
                "UPDATE samples SET status = ?, updated_at = ? WHERE sample_id = ?",
                (new_state.value, _dt(now), sample_id),
            )
            connection.execute(
                """
                INSERT INTO state_transitions (
                    sample_id, previous_state, new_state, timestamp, message
                ) VALUES (?, ?, ?, ?, ?)
                """,
                (
                    sample_id,
                    previous.value if previous else None,
                    new_state.value,
                    _dt(now),
                    message,
                ),
            )
            connection.commit()
        return previous

    def record_state_transition(
        self,
        sample_id: str,
        previous_state: SampleState | None,
        new_state: SampleState,
        *,
        message: str | None = None,
    ) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                INSERT INTO state_transitions (
                    sample_id, previous_state, new_state, timestamp, message
                ) VALUES (?, ?, ?, ?, ?)
                """,
                (
                    sample_id,
                    previous_state.value if previous_state else None,
                    new_state.value,
                    _dt(utc_now()),
                    message,
                ),
            )
            connection.commit()

    def create_job(self, job: AnalysisJob) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                INSERT INTO jobs (
                    job_id, sample_id, status, created_at, started_at,
                    updated_at, completed_at, error, config_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    job.job_id,
                    job.sample_id,
                    job.status.value,
                    _dt(job.created_at),
                    _dt(job.started_at),
                    _dt(job.updated_at),
                    _dt(job.completed_at),
                    job.error,
                    json.dumps(job.run_config, sort_keys=True),
                ),
            )
            connection.commit()

    def update_job(
        self,
        job_id: str,
        status: JobStatus,
        *,
        started_at=None,
        completed_at=None,
        error: str | None = None,
    ) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                UPDATE jobs
                SET status = ?, started_at = COALESCE(?, started_at),
                    updated_at = ?, completed_at = COALESCE(?, completed_at),
                    error = ?
                WHERE job_id = ?
                """,
                (
                    status.value,
                    _dt(started_at),
                    _dt(utc_now()),
                    _dt(completed_at),
                    error,
                    job_id,
                ),
            )
            connection.commit()

    def count_jobs(self) -> int:
        with self._connect() as connection:
            return connection.execute("SELECT COUNT(*) FROM jobs").fetchone()[0]

    def state_transitions(self, sample_id: str) -> list[sqlite3.Row]:
        with self._connect() as connection:
            return list(
                connection.execute(
                    "SELECT * FROM state_transitions WHERE sample_id = ? ORDER BY id",
                    (sample_id,),
                )
            )

    def persist_extraction(self, sample_id: str, bundle: ExtractionBundle) -> None:
        payload = bundle.model_dump(mode="json")
        with self._connect() as connection:
            self._clear_extraction(connection, sample_id)
            metadata = bundle.metadata
            connection.execute(
                """
                INSERT INTO binary_metadata (
                    sample_id, metadata_json, ida_version, architecture, bitness,
                    processor, image_base, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    sample_id,
                    json.dumps(payload["metadata"], sort_keys=True),
                    metadata.ida_version,
                    metadata.architecture,
                    metadata.bitness,
                    metadata.processor,
                    format_address(metadata.image_base),
                    _dt(utc_now()),
                ),
            )

            for function in bundle.functions:
                connection.execute(
                    """
                    INSERT INTO functions (
                        sample_id, address, end_address, name, size, segment, flags,
                        prototype, is_thunk, is_library, is_external,
                        decompilation_status, disassembly_status, pseudocode_path,
                        disassembly_path, scc_id, recursive, record_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        sample_id,
                        format_address(function.address),
                        format_address(function.end_address),
                        function.name,
                        function.size,
                        function.segment,
                        function.flags,
                        function.prototype,
                        int(function.is_thunk),
                        int(function.is_library),
                        int(function.is_external),
                        function.decompilation_status,
                        function.disassembly_status,
                        function.pseudocode_path,
                        function.disassembly_path,
                        function.scc_id,
                        int(function.recursive),
                        json.dumps(function.model_dump(mode="json"), sort_keys=True),
                    ),
                )

            for edge in bundle.callgraph.edges:
                connection.execute(
                    """
                    INSERT OR IGNORE INTO function_calls (
                        sample_id, caller, callee, call_type, source_address
                    ) VALUES (?, ?, ?, ?, ?)
                    """,
                    (
                        sample_id,
                        format_address(edge.caller),
                        format_address(edge.callee),
                        edge.type,
                        format_address(edge.source_address),
                    ),
                )

            for record in bundle.strings:
                connection.execute(
                    """
                    INSERT INTO strings (
                        sample_id, address, value, encoding, length, record_json
                    ) VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (
                        sample_id,
                        format_address(record.address),
                        record.value,
                        record.encoding,
                        record.length,
                        json.dumps(record.model_dump(mode="json"), sort_keys=True),
                    ),
                )
                for xref in record.xrefs:
                    connection.execute(
                        """
                        INSERT INTO string_xrefs (
                            sample_id, string_address, function_address, source_address, xref_type
                        ) VALUES (?, ?, ?, ?, ?)
                        """,
                        (
                            sample_id,
                            format_address(record.address),
                            format_address(xref.source_function),
                            format_address(xref.source_address),
                            xref.xref_type,
                        ),
                    )

            for record in bundle.imports:
                address = record.address if record.address is not None else 0
                connection.execute(
                    """
                    INSERT INTO imports (
                        sample_id, address, module, name, ordinal, record_json
                    ) VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (
                        sample_id,
                        format_address(address),
                        record.module,
                        record.name,
                        record.ordinal,
                        json.dumps(record.model_dump(mode="json"), sort_keys=True),
                    ),
                )
                for xref in record.xrefs:
                    connection.execute(
                        """
                        INSERT INTO import_xrefs (
                            sample_id, import_address, function_address, source_address, xref_type
                        ) VALUES (?, ?, ?, ?, ?)
                        """,
                        (
                            sample_id,
                            format_address(address),
                            format_address(xref.source_function),
                            format_address(xref.source_address),
                            xref.xref_type,
                        ),
                    )

            for record in bundle.exports:
                connection.execute(
                    """
                    INSERT INTO exports (
                        sample_id, address, name, ordinal, record_json
                    ) VALUES (?, ?, ?, ?, ?)
                    """,
                    (
                        sample_id,
                        format_address(record.address),
                        record.name,
                        record.ordinal,
                        json.dumps(record.model_dump(mode="json"), sort_keys=True),
                    ),
                )

            for record in bundle.segments:
                connection.execute(
                    """
                    INSERT INTO segments (
                        sample_id, name, start, end, size, permissions,
                        segment_class, segment_type, record_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        sample_id,
                        record.name,
                        format_address(record.start),
                        format_address(record.end),
                        record.size,
                        record.permissions,
                        record.segment_class,
                        record.segment_type,
                        json.dumps(record.model_dump(mode="json"), sort_keys=True),
                    ),
                )

            for record in bundle.globals:
                connection.execute(
                    """
                    INSERT INTO globals (
                        sample_id, address, name, size, type, segment, record_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        sample_id,
                        format_address(record.address),
                        record.name,
                        record.size,
                        record.type,
                        record.segment,
                        json.dumps(record.model_dump(mode="json"), sort_keys=True),
                    ),
                )
                for xref in record.xrefs:
                    connection.execute(
                        """
                        INSERT INTO global_xrefs (
                            sample_id, global_address, function_address, source_address, xref_type
                        ) VALUES (?, ?, ?, ?, ?)
                        """,
                        (
                            sample_id,
                            format_address(record.address),
                            format_address(xref.source_function),
                            format_address(xref.source_address),
                            xref.xref_type,
                        ),
                    )

            for record in bundle.types:
                connection.execute(
                    """
                    INSERT INTO types (
                        sample_id, name, kind, declaration, record_json
                    ) VALUES (?, ?, ?, ?, ?)
                    """,
                    (
                        sample_id,
                        record.name,
                        record.kind,
                        record.declaration,
                        json.dumps(record.model_dump(mode="json"), sort_keys=True),
                    ),
                )

            for record in bundle.xrefs:
                connection.execute(
                    """
                    INSERT INTO xrefs (
                        sample_id, source_address, destination_address, xref_type,
                        source_function, destination_entity, record_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        sample_id,
                        format_address(record.source_address),
                        format_address(record.destination_address),
                        record.xref_type,
                        format_address(record.source_function),
                        record.destination_entity,
                        json.dumps(record.model_dump(mode="json"), sort_keys=True),
                    ),
                )

            for node in bundle.callgraph.nodes:
                connection.execute(
                    """
                    INSERT INTO callgraph_nodes (
                        sample_id, address, name, scc_id, recursive
                    ) VALUES (?, ?, ?, ?, ?)
                    """,
                    (
                        sample_id,
                        format_address(node.address),
                        node.name,
                        node.scc_id,
                        int(node.recursive),
                    ),
                )

            for component in bundle.callgraph.components:
                connection.execute(
                    """
                    INSERT INTO callgraph_components (
                        sample_id, scc_id, recursive, nodes_json
                    ) VALUES (?, ?, ?, ?)
                    """,
                    (
                        sample_id,
                        component.scc_id,
                        int(component.recursive),
                        json.dumps([format_address(node) for node in component.nodes]),
                    ),
                )

            for failure in bundle.failures:
                connection.execute(
                    """
                    INSERT INTO extraction_failures (
                        sample_id, extractor, address, name, reason, fatal
                    ) VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (
                        sample_id,
                        failure.extractor,
                        format_address(failure.address),
                        failure.name,
                        failure.reason,
                        int(failure.fatal),
                    ),
                )

            connection.commit()

    def get_function_record_json(self, sample_id: str, address: str) -> str | None:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT record_json FROM functions WHERE sample_id = ? AND address = ?",
                (sample_id, address),
            ).fetchone()
        return row["record_json"] if row else None

    def list_ai_targets(self, sample_id: str) -> list[dict]:
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT * FROM functions
                WHERE sample_id = ?
                  AND is_library = 0
                  AND is_thunk = 0
                  AND is_external = 0
                ORDER BY address
                """,
                (sample_id,),
            ).fetchall()
        entry_names = {"main", "_main", "wmain", "_wmain", "winmain", "_winmain@16", "wwinmain", "_wwinmain@16", "start", "_start"}
        return [
            dict(row) for row in rows
            if is_ida_placeholder_name(row["name"]) or (row["name"] and row["name"].lower() in entry_names)
        ]

    def list_strings(self, sample_id: str) -> list[dict]:
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT address, value, encoding, length, record_json
                FROM strings
                WHERE sample_id = ?
                ORDER BY address
                """,
                (sample_id,),
            ).fetchall()
        return [dict(row) for row in rows]

    def list_strings_with_xrefs(self, sample_id: str) -> list[dict]:
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT s.address, s.value, s.encoding, s.length, s.record_json,
                       x.function_address, x.source_address
                FROM strings s
                LEFT JOIN string_xrefs x ON s.sample_id = x.sample_id AND s.address = x.string_address
                WHERE s.sample_id = ?
                ORDER BY s.address
                """,
                (sample_id,),
            ).fetchall()
        return [dict(row) for row in rows]

    def list_extracted_functions(self, sample_id: str) -> list[dict]:
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT * FROM functions
                WHERE sample_id = ?
                ORDER BY address
                """,
                (sample_id,),
            ).fetchall()
        return [dict(row) for row in rows]

    def list_function_calls(self, sample_id: str) -> list[dict]:
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT * FROM function_calls WHERE sample_id = ? ORDER BY caller, callee",
                (sample_id,),
            ).fetchall()
        return [dict(row) for row in rows]

    def list_callgraph_components(self, sample_id: str) -> list[dict]:
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT * FROM callgraph_components WHERE sample_id = ? ORDER BY scc_id",
                (sample_id,),
            ).fetchall()
        return [dict(row) for row in rows]

    def get_completed_ai_analysis(self, sample_id: str) -> dict[str, dict]:
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT address, result_json, confidence_label, proposed_name, summary
                FROM ai_function_analysis
                WHERE sample_id = ? AND status = 'COMPLETED'
                """,
                (sample_id,),
            ).fetchall()
        return {row["address"]: dict(row) for row in rows}

    def get_function_ai_analysis(self, sample_id: str, address: str) -> dict | None:
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT * FROM ai_function_analysis
                WHERE sample_id = ? AND address = ?
                """,
                (sample_id, address),
            ).fetchone()
        return dict(row) if row else None

    def build_context_records(self, sample_id: str, address: str) -> dict:
        with self._connect() as connection:
            function = connection.execute(
                "SELECT * FROM functions WHERE sample_id = ? AND address = ?",
                (sample_id, address),
            ).fetchone()
            callers = connection.execute(
                """
                SELECT f.address, f.name, f.record_json
                FROM function_calls c
                JOIN functions f ON f.sample_id = c.sample_id AND f.address = c.caller
                WHERE c.sample_id = ? AND c.callee = ?
                ORDER BY f.address
                """,
                (sample_id, address),
            ).fetchall()
            callees = connection.execute(
                """
                SELECT f.address, f.name, f.record_json
                FROM function_calls c
                JOIN functions f ON f.sample_id = c.sample_id AND f.address = c.callee
                WHERE c.sample_id = ? AND c.caller = ?
                ORDER BY f.address
                """,
                (sample_id, address),
            ).fetchall()
            strings = connection.execute(
                """
                SELECT DISTINCT s.address, s.value, s.encoding, s.length, s.record_json
                FROM string_xrefs x
                JOIN strings s ON s.sample_id = x.sample_id AND s.address = x.string_address
                WHERE x.sample_id = ? AND x.function_address = ?
                ORDER BY s.address
                """,
                (sample_id, address),
            ).fetchall()
            imports = connection.execute(
                """
                SELECT DISTINCT i.address, i.module, i.name, i.ordinal, i.record_json
                FROM import_xrefs x
                JOIN imports i ON i.sample_id = x.sample_id AND i.address = x.import_address
                WHERE x.sample_id = ? AND x.function_address = ?
                ORDER BY i.module, i.name
                """,
                (sample_id, address),
            ).fetchall()
            globals_ = connection.execute(
                """
                SELECT DISTINCT g.address, g.name, g.size, g.type, g.segment, g.record_json
                FROM global_xrefs x
                JOIN globals g ON g.sample_id = x.sample_id AND g.address = x.global_address
                WHERE x.sample_id = ? AND x.function_address = ?
                ORDER BY g.address
                """,
                (sample_id, address),
            ).fetchall()
            types = connection.execute(
                "SELECT name, kind, declaration, record_json FROM types WHERE sample_id = ? ORDER BY name LIMIT 50",
                (sample_id,),
            ).fetchall()
            segments = connection.execute(
                "SELECT name, start, end, permissions, segment_class, record_json FROM segments WHERE sample_id = ? ORDER BY start",
                (sample_id,),
            ).fetchall()
            child_findings = connection.execute(
                """
                SELECT a.address, a.proposed_name, a.summary, a.confidence,
                       a.confidence_label, a.needs_investigation, a.result_json
                FROM function_calls c
                JOIN ai_function_analysis a
                  ON a.sample_id = c.sample_id AND a.address = c.callee
                WHERE c.sample_id = ? AND c.caller = ? AND a.status = 'COMPLETED'
                ORDER BY a.address
                """,
                (sample_id, address),
            ).fetchall()
        if function is None:
            raise KeyError(f"Function not found: {address}")
        return {
            "function": dict(function),
            "callers": [dict(row) for row in callers],
            "callees": [dict(row) for row in callees],
            "strings": [dict(row) for row in strings],
            "imports": [dict(row) for row in imports],
            "globals": [dict(row) for row in globals_],
            "types": [dict(row) for row in types],
            "segments": [dict(row) for row in segments],
            "child_findings": [dict(row) for row in child_findings],
        }

    def persist_ai_request(self, sample_id: str, request: AIRequestMetadata) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                INSERT OR REPLACE INTO ai_requests (
                    request_id, sample_id, function_address, provider, model, task,
                    analysis_pass, timestamp, input_tokens, output_tokens, latency_ms,
                    retry_count, success, error
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    request.request_id,
                    sample_id,
                    request.function_address,
                    request.provider,
                    request.model,
                    request.task,
                    request.analysis_pass,
                    request.timestamp,
                    request.input_tokens,
                    request.output_tokens,
                    request.latency_ms,
                    request.retry_count,
                    int(request.success),
                    request.error,
                ),
            )
            connection.commit()

    def persist_ai_analysis(
        self,
        sample_id: str,
        original_name: str,
        result: FunctionAnalysisResult,
        *,
        status: str,
        prompt_version: str,
        schema_version: str,
        confidence_policy_version: str,
        context_builder_version: str,
        analysis_fingerprint: str,
    ) -> None:
        now = _dt(utc_now())
        payload = result.model_dump(mode="json")
        with self._connect() as connection:
            connection.execute(
                """
                INSERT INTO ai_function_analysis (
                    sample_id, address, original_name, proposed_name, summary,
                    confidence, confidence_label, needs_investigation, status,
                    analysis_pass, result_json, prompt_version, schema_version,
                    confidence_policy_version, context_builder_version,
                    analysis_fingerprint, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(sample_id, address) DO UPDATE SET
                    proposed_name = excluded.proposed_name,
                    summary = excluded.summary,
                    confidence = excluded.confidence,
                    confidence_label = excluded.confidence_label,
                    needs_investigation = excluded.needs_investigation,
                    status = excluded.status,
                    analysis_pass = excluded.analysis_pass,
                    result_json = excluded.result_json,
                    prompt_version = excluded.prompt_version,
                    schema_version = excluded.schema_version,
                    confidence_policy_version = excluded.confidence_policy_version,
                    context_builder_version = excluded.context_builder_version,
                    analysis_fingerprint = excluded.analysis_fingerprint,
                    updated_at = excluded.updated_at
                """,
                (
                    sample_id,
                    result.address,
                    original_name,
                    result.proposed_name,
                    result.summary,
                    result.confidence,
                    result.confidence_label.value,
                    int(result.needs_investigation),
                    status,
                    result.analysis_pass,
                    json.dumps(payload, sort_keys=True),
                    prompt_version,
                    schema_version,
                    confidence_policy_version,
                    context_builder_version,
                    analysis_fingerprint,
                    now,
                    now,
                ),
            )
            connection.execute(
                "DELETE FROM ai_evidence WHERE sample_id = ? AND function_address = ?",
                (sample_id, result.address),
            )
            connection.execute(
                "DELETE FROM ai_variable_proposals WHERE sample_id = ? AND function_address = ?",
                (sample_id, result.address),
            )
            connection.execute(
                "DELETE FROM ai_type_suggestions WHERE sample_id = ? AND function_address = ?",
                (sample_id, result.address),
            )
            connection.execute(
                "DELETE FROM ai_artifact_candidates WHERE sample_id = ? AND function_address = ?",
                (sample_id, result.address),
            )
            for evidence in result.evidence:
                connection.execute(
                    """
                    INSERT INTO ai_evidence (
                        sample_id, function_address, evidence_type, source, address,
                        value, description
                    ) VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        sample_id,
                        result.address,
                        evidence.type,
                        evidence.source.value,
                        evidence.address,
                        evidence.value,
                        evidence.description,
                    ),
                )
            for variable in result.variables:
                connection.execute(
                    """
                    INSERT INTO ai_variable_proposals (
                        sample_id, function_address, original, proposed, confidence, evidence
                    ) VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (
                        sample_id,
                        result.address,
                        variable.original,
                        variable.proposed,
                        variable.confidence,
                        variable.evidence,
                    ),
                )
            for type_hint in result.types:
                connection.execute(
                    """
                    INSERT INTO ai_type_suggestions (
                        sample_id, function_address, target, proposed_type, confidence, evidence
                    ) VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (
                        sample_id,
                        result.address,
                        type_hint.target,
                        type_hint.proposed_type,
                        type_hint.confidence,
                        type_hint.evidence,
                    ),
                )
            for artifact in result.artifacts:
                connection.execute(
                    """
                    INSERT INTO ai_artifact_candidates (
                        sample_id, function_address, value, artifact_type, address,
                        usage, confidence, record_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        sample_id,
                        result.address,
                        artifact.value,
                        artifact.type,
                        artifact.address,
                        artifact.usage,
                        artifact.confidence,
                        json.dumps(artifact.model_dump(mode="json"), sort_keys=True),
                    ),
                )
            connection.commit()

    def get_ai_analysis_rows(self, sample_id: str) -> list[dict]:
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT * FROM ai_function_analysis WHERE sample_id = ? ORDER BY address",
                (sample_id,),
            ).fetchall()
        return [dict(row) for row in rows]

    def get_ai_request_rows(self, sample_id: str) -> list[dict]:
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT * FROM ai_requests WHERE sample_id = ? ORDER BY timestamp",
                (sample_id,),
            ).fetchall()
        return [dict(row) for row in rows]

    def get_ai_artifact_rows(self, sample_id: str) -> list[dict]:
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT record_json FROM ai_artifact_candidates WHERE sample_id = ? ORDER BY function_address, id",
                (sample_id,),
            ).fetchall()
        return [json.loads(row["record_json"]) for row in rows]

    def build_relationship_source_records(self, sample_id: str) -> dict[str, list[dict]]:
        with self._connect() as connection:
            imports = connection.execute(
                """
                SELECT x.function_address, x.source_address, x.xref_type,
                       x.import_address, i.module, i.name
                FROM import_xrefs x
                JOIN imports i ON i.sample_id = x.sample_id AND i.address = x.import_address
                WHERE x.sample_id = ? AND x.function_address IS NOT NULL
                ORDER BY x.function_address, i.module, i.name
                """,
                (sample_id,),
            ).fetchall()
            strings = connection.execute(
                """
                SELECT x.function_address, x.source_address, x.xref_type,
                       x.string_address, s.value
                FROM string_xrefs x
                JOIN strings s ON s.sample_id = x.sample_id AND s.address = x.string_address
                WHERE x.sample_id = ? AND x.function_address IS NOT NULL
                ORDER BY x.function_address, x.string_address
                """,
                (sample_id,),
            ).fetchall()
            globals_ = connection.execute(
                """
                SELECT x.function_address, x.source_address, x.xref_type,
                       x.global_address, g.name, g.type
                FROM global_xrefs x
                JOIN globals g ON g.sample_id = x.sample_id AND g.address = x.global_address
                WHERE x.sample_id = ? AND x.function_address IS NOT NULL
                ORDER BY x.function_address, x.global_address
                """,
                (sample_id,),
            ).fetchall()
        return {
            "imports": [dict(row) for row in imports],
            "strings": [dict(row) for row in strings],
            "globals": [dict(row) for row in globals_],
        }

    def get_import_usage_by_function(self, sample_id: str) -> dict[str, list[str]]:
        usage: dict[str, list[str]] = {}
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT x.function_address, i.module, i.name
                FROM import_xrefs x
                JOIN imports i ON i.sample_id = x.sample_id AND i.address = x.import_address
                WHERE x.sample_id = ? AND x.function_address IS NOT NULL
                ORDER BY x.function_address, i.module, i.name
                """,
                (sample_id,),
            ).fetchall()
        for row in rows:
            label = f"{row['module'] or ''}!{row['name'] or ''}".strip("!")
            usage.setdefault(row["function_address"], []).append(label)
        return usage

    def calculate_ai_stats(self, sample_id: str, target_count: int | None = None) -> AIAnalysisStats:
        rows = self.get_ai_analysis_rows(sample_id)
        requests = self.get_ai_request_rows(sample_id)
        completed = [row for row in rows if row["status"] == "COMPLETED"]
        proposed = [row for row in completed if row["proposed_name"]]
        generic_count = 0
        try:
            from reai.ai.validation import is_generic_name

            generic_count = sum(1 for row in proposed if is_generic_name(row["proposed_name"]))
        except Exception:
            generic_count = 0
        return AIAnalysisStats(
            target_functions=target_count if target_count is not None else len(rows),
            analyzed=len(completed),
            failed=sum(1 for row in rows if row["status"] == "FAILED"),
            high_confidence=sum(1 for row in completed if row["confidence_label"] == "HIGH"),
            medium_confidence=sum(1 for row in completed if row["confidence_label"] == "MEDIUM"),
            low_confidence=sum(1 for row in completed if row["confidence_label"] == "LOW"),
            proposed_function_names=len(proposed),
            variable_proposals=sum(len(json.loads(row["result_json"]).get("variables", [])) for row in completed),
            needs_investigation=sum(1 for row in completed if row["needs_investigation"]),
            ai_requests=len(requests),
            total_input_tokens=sum(row["input_tokens"] or 0 for row in requests),
            total_output_tokens=sum(row["output_tokens"] or 0 for row in requests),
            generic_name_rate=(generic_count / len(proposed)) if proposed else 0.0,
        )

    def list_mcp_targets(self, sample_id: str, max_functions: int | None = None) -> list[InvestigationTarget]:
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT a.*, f.name AS current_name, f.record_json AS function_record_json,
                       COUNT(DISTINCT callers.caller) AS caller_count,
                       COUNT(DISTINCT callees.callee) AS callee_count
                FROM ai_function_analysis a
                JOIN functions f ON f.sample_id = a.sample_id AND f.address = a.address
                LEFT JOIN function_calls callers
                  ON callers.sample_id = a.sample_id AND callers.callee = a.address
                LEFT JOIN function_calls callees
                  ON callees.sample_id = a.sample_id AND callees.caller = a.address
                WHERE a.sample_id = ?
                GROUP BY a.sample_id, a.address
                ORDER BY a.address
                """,
                (sample_id,),
            ).fetchall()

        import_usage = self.get_import_usage_by_function(sample_id)
        targets: list[InvestigationTarget] = []
        for row in rows:
            result = json.loads(row["result_json"])
            function = json.loads(row["function_record_json"])
            unknowns = list(result.get("unknowns") or [])
            evidence = list(result.get("evidence") or [])
            imports = import_usage.get(row["address"], [])
            importance, importance_score, importance_reasons = classify_importance(
                name=row["current_name"],
                proposed_name=row["proposed_name"],
                summary=row["summary"],
                confidence_label=row["confidence_label"],
                unknowns=unknowns,
                evidence=evidence,
                imports=imports,
                caller_count=int(row["caller_count"] or 0),
                callee_count=int(row["callee_count"] or 0),
            )
            questions = generate_investigation_questions(
                sample_id=sample_id,
                function_address=row["address"],
                importance=importance,
                name=row["current_name"],
                proposed_name=row["proposed_name"],
                summary=row["summary"],
                unknowns=unknowns,
                evidence=evidence,
                imports=imports,
                confidence_label=row["confidence_label"],
            )
            if not _should_investigate(row, importance, questions):
                continue
            reasons = [question.reason.value for question in questions] or unknowns or importance_reasons
            priority_score, priority_reason = _mcp_priority(row, unknowns)
            if importance == AnalyticalImportance.HIGH:
                priority_score += 60
            elif importance == AnalyticalImportance.MEDIUM:
                priority_score += 25
            priority_score += min(20, len(questions) * 4)
            priority_reason = ", ".join(dict.fromkeys([*importance_reasons, priority_reason]).keys())
            targets.append(
                InvestigationTarget(
                    sample_id=sample_id,
                    address=row["address"],
                    current_name=row["current_name"],
                    proposed_name=row["proposed_name"],
                    summary=row["summary"],
                    confidence=float(row["confidence"]),
                    confidence_label=row["confidence_label"],
                    unknowns=unknowns,
                    evidence=evidence,
                    investigation_reasons=reasons,
                    investigation_questions=[question.question for question in questions],
                    analytical_importance=importance,
                    analysis_pass=int(row["analysis_pass"]),
                    caller_count=int(row["caller_count"] or 0),
                    callee_count=int(row["callee_count"] or 0),
                    function=function,
                    priority_score=priority_score,
                    priority_reason=priority_reason,
                )
            )
        targets.sort(key=lambda item: (-item.priority_score, item.address))
        return targets[:max_functions] if max_functions else targets

    def get_mcp_investigation(self, sample_id: str, function_address: str) -> dict | None:
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT * FROM mcp_investigations
                WHERE sample_id = ? AND function_address = ?
                """,
                (sample_id, function_address),
            ).fetchone()
        return dict(row) if row else None

    def start_mcp_session(self, sample_id: str, metadata: MCPSessionMetadata, *, status: str = "RUNNING", error: str | None = None) -> None:
        now = _dt(utc_now())
        with self._connect() as connection:
            connection.execute(
                """
                INSERT OR REPLACE INTO mcp_sessions (
                    session_id, sample_id, backend, provider, transport, connection_mode,
                    database, ida_version, backend_version, read_only,
                    sample_identity_verified, available_tools_json,
                    normalized_capabilities_json, status, started_at, completed_at, error
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, ?)
                """,
                (
                    metadata.session_id,
                    sample_id,
                    metadata.backend,
                    metadata.provider,
                    metadata.transport,
                    metadata.connection_mode,
                    metadata.database,
                    metadata.ida_version,
                    metadata.backend_version,
                    int(metadata.read_only),
                    int(metadata.sample_identity_verified),
                    json.dumps(metadata.available_tools, sort_keys=True),
                    json.dumps(metadata.normalized_capabilities, sort_keys=True),
                    status,
                    now,
                    error,
                ),
            )
            connection.execute("DELETE FROM mcp_capabilities WHERE session_id = ?", (metadata.session_id,))
            for capability in metadata.normalized_capabilities:
                connection.execute(
                    """
                    INSERT INTO mcp_capabilities (
                        session_id, sample_id, capability, tool_name, available, read_only
                    ) VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (
                        metadata.session_id,
                        sample_id,
                        capability,
                        None,
                        1,
                        int(capability in READ_ONLY_CAPABILITIES),
                    ),
                )
            connection.commit()

    def complete_mcp_session(self, session_id: str, *, status: str, error: str | None = None) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                UPDATE mcp_sessions
                SET status = ?, completed_at = ?, error = ?
                WHERE session_id = ?
                """,
                (status, _dt(utc_now()), error, session_id),
            )
            connection.commit()

    def get_mcp_session_rows(self, sample_id: str) -> list[dict]:
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT * FROM mcp_sessions WHERE sample_id = ? ORDER BY started_at",
                (sample_id,),
            ).fetchall()
        return [dict(row) for row in rows]

    def upsert_mcp_questions(self, questions: list[InvestigationQuestion]) -> None:
        if not questions:
            return
        now = _dt(utc_now())
        with self._connect() as connection:
            for question in questions:
                connection.execute(
                    """
                    INSERT INTO mcp_questions (
                        question_id, sample_id, function_address, question, reason,
                        priority, status, answer, evidence_json, created_at,
                        updated_at, completed_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL)
                    ON CONFLICT(question_id) DO UPDATE SET
                        priority = excluded.priority,
                        updated_at = excluded.updated_at
                    """,
                    (
                        question.fingerprint(),
                        question.sample_id,
                        question.function_address,
                        question.question,
                        question.reason.value,
                        question.priority.value,
                        question.status.value,
                        question.answer,
                        json.dumps(question.evidence_json, sort_keys=True),
                        now,
                        now,
                    ),
                )
            connection.commit()

    def update_mcp_question_status(
        self,
        sample_id: str,
        function_address: str,
        question: str,
        *,
        status: QuestionStatus,
        answer: str | None = None,
        evidence: list[dict] | None = None,
    ) -> None:
        now = _dt(utc_now())
        completed_at = now if status in {QuestionStatus.RESOLVED, QuestionStatus.PARTIALLY_RESOLVED, QuestionStatus.UNRESOLVED, QuestionStatus.FAILED} else None
        with self._connect() as connection:
            connection.execute(
                """
                UPDATE mcp_questions
                SET status = ?, answer = COALESCE(?, answer),
                    evidence_json = CASE WHEN ? IS NULL THEN evidence_json ELSE ? END,
                    updated_at = ?, completed_at = COALESCE(?, completed_at)
                WHERE sample_id = ? AND function_address = ? AND question = ?
                """,
                (
                    status.value,
                    answer,
                    json.dumps(evidence, sort_keys=True) if evidence is not None else None,
                    json.dumps(evidence, sort_keys=True) if evidence is not None else None,
                    now,
                    completed_at,
                    sample_id,
                    function_address,
                    question,
                ),
            )
            connection.commit()

    def get_mcp_question_rows(self, sample_id: str, function_address: str | None = None) -> list[dict]:
        query = "SELECT * FROM mcp_questions WHERE sample_id = ?"
        params: tuple = (sample_id,)
        if function_address is not None:
            query += " AND function_address = ?"
            params = (sample_id, function_address)
        query += " ORDER BY priority, created_at, question_id"
        with self._connect() as connection:
            rows = connection.execute(query, params).fetchall()
        return [dict(row) for row in rows]

    def start_mcp_investigation(self, target: InvestigationTarget) -> None:
        now = _dt(utc_now())
        with self._connect() as connection:
            connection.execute(
                """
                INSERT INTO mcp_investigations (
                    sample_id, function_address, current_name, proposed_name, status,
                    outcome, priority_score, priority_reason, confidence_before,
                    confidence_after, confidence_delta, rounds, tool_calls,
                    interpretation_changed, started_at, updated_at, completed_at, error
                ) VALUES (?, ?, ?, ?, ?, NULL, ?, ?, ?, NULL, NULL, 0, 0, 0, ?, ?, NULL, NULL)
                ON CONFLICT(sample_id, function_address) DO UPDATE SET
                    status = excluded.status,
                    proposed_name = excluded.proposed_name,
                    priority_score = excluded.priority_score,
                    priority_reason = excluded.priority_reason,
                    updated_at = excluded.updated_at,
                    error = NULL
                """,
                (
                    target.sample_id,
                    target.address,
                    target.current_name,
                    target.proposed_name,
                    InvestigationStatus.RUNNING.value,
                    target.priority_score,
                    target.priority_reason,
                    target.confidence,
                    now,
                    now,
                ),
            )
            connection.commit()

    def complete_mcp_investigation(
        self,
        sample_id: str,
        function_address: str,
        *,
        outcome: InvestigationOutcome,
        confidence_after: float,
        interpretation_changed: bool,
        error: str | None = None,
    ) -> None:
        now = _dt(utc_now())
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT confidence_before FROM mcp_investigations
                WHERE sample_id = ? AND function_address = ?
                """,
                (sample_id, function_address),
            ).fetchone()
            before = row["confidence_before"] if row else None
            delta = None if before is None else round(confidence_after - before, 4)
            connection.execute(
                """
                UPDATE mcp_investigations
                SET status = ?, outcome = ?, confidence_after = ?, confidence_delta = ?,
                    interpretation_changed = ?, updated_at = ?, completed_at = ?, error = ?
                WHERE sample_id = ? AND function_address = ?
                """,
                (
                    InvestigationStatus.COMPLETED.value if outcome != InvestigationOutcome.FAILED else InvestigationStatus.FAILED.value,
                    outcome.value,
                    confidence_after,
                    delta,
                    int(interpretation_changed),
                    now,
                    now,
                    error,
                    sample_id,
                    function_address,
                ),
            )
            connection.commit()

    def create_mcp_round(
        self,
        sample_id: str,
        function_address: str,
        *,
        round_number: int,
        goal: str,
        plan_json: str,
        confidence_before: float,
        unknowns_before: list[str],
    ) -> int:
        now = _dt(utc_now())
        with self._connect() as connection:
            cursor = connection.execute(
                """
                INSERT INTO mcp_rounds (
                    sample_id, function_address, round_number, goal, plan_json,
                    confidence_before, unknowns_before_json, unknowns_after_json,
                    status, started_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    sample_id,
                    function_address,
                    round_number,
                    goal,
                    plan_json,
                    confidence_before,
                    json.dumps(unknowns_before, sort_keys=True),
                    "[]",
                    InvestigationStatus.RUNNING.value,
                    now,
                ),
            )
            connection.commit()
            return int(cursor.lastrowid)

    def complete_mcp_round(
        self,
        round_id: int,
        *,
        status: InvestigationStatus,
        confidence_after: float,
        unknowns_after: list[str],
    ) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                UPDATE mcp_rounds
                SET status = ?, confidence_after = ?, unknowns_after_json = ?, completed_at = ?
                WHERE id = ?
                """,
                (
                    status.value,
                    confidence_after,
                    json.dumps(unknowns_after, sort_keys=True),
                    _dt(utc_now()),
                    round_id,
                ),
            )
            connection.commit()

    def next_mcp_round_number(self, sample_id: str, function_address: str) -> int:
        with self._connect() as connection:
            value = connection.execute(
                """
                SELECT COALESCE(MAX(round_number), 0) + 1 FROM mcp_rounds
                WHERE sample_id = ? AND function_address = ?
                """,
                (sample_id, function_address),
            ).fetchone()[0]
        return int(value)

    def get_completed_mcp_action_fingerprints(self, sample_id: str, function_address: str) -> set[str]:
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT fingerprint FROM mcp_calls
                WHERE sample_id = ? AND function_address = ?
                  AND status IN ('SUCCESS', 'DEDUPED')
                """,
                (sample_id, function_address),
            ).fetchall()
        return {row["fingerprint"] for row in rows}

    def count_mcp_calls_for_function(self, sample_id: str, function_address: str) -> int:
        with self._connect() as connection:
            value = connection.execute(
                "SELECT COUNT(*) FROM mcp_calls WHERE sample_id = ? AND function_address = ?",
                (sample_id, function_address),
            ).fetchone()[0]
        return int(value)

    def count_mcp_calls_for_sample(self, sample_id: str) -> int:
        with self._connect() as connection:
            value = connection.execute(
                "SELECT COUNT(*) FROM mcp_calls WHERE sample_id = ?",
                (sample_id,),
            ).fetchone()[0]
        return int(value)

    def persist_mcp_call(
        self,
        sample_id: str,
        function_address: str,
        *,
        round_number: int,
        call_id: str,
        fingerprint: str,
        result: MCPToolResult,
        parameters: dict,
        status: str,
    ) -> None:
        raw = result.raw if result.raw is not None else {"observations": result.observations}
        with self._connect() as connection:
            connection.execute(
                """
                INSERT OR REPLACE INTO mcp_calls (
                    call_id, sample_id, function_address, round_number, capability,
                    target, parameters_json, fingerprint, started_at, completed_at,
                    duration_ms, status, result_size, result_json, error
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    call_id,
                    sample_id,
                    function_address,
                    round_number,
                    result.capability.value,
                    result.target,
                    json.dumps(parameters, sort_keys=True),
                    fingerprint,
                    _dt(utc_now()),
                    _dt(utc_now()),
                    result.duration_ms,
                    status,
                    result.result_size,
                    json.dumps(raw, sort_keys=True),
                    result.error,
                ),
            )
            connection.execute(
                """
                UPDATE mcp_investigations
                SET tool_calls = tool_calls + 1, updated_at = ?
                WHERE sample_id = ? AND function_address = ?
                """,
                (_dt(utc_now()), sample_id, function_address),
            )
            connection.commit()

    def persist_mcp_evidence(
        self,
        sample_id: str,
        function_address: str,
        *,
        round_number: int,
        evidence: MCPEvidence,
    ) -> bool:
        fingerprint = evidence.fingerprint()
        with self._connect() as connection:
            cursor = connection.execute(
                """
                INSERT OR IGNORE INTO mcp_evidence (
                    sample_id, function_address, round_number, capability, target,
                    evidence_type, source, address, value, description, record_json,
                    fingerprint, deduped
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0)
                """,
                (
                    sample_id,
                    function_address,
                    round_number,
                    evidence.capability.value,
                    evidence.target,
                    evidence.evidence_type,
                    evidence.source,
                    evidence.address,
                    evidence.value,
                    evidence.description,
                    json.dumps(evidence.record, sort_keys=True),
                    fingerprint,
                ),
            )
            # cursor.rowcount is 1 for a successful INSERT, 0 for IGNORE (duplicate).
            inserted = cursor.rowcount > 0
            connection.commit()
        return inserted

    def increment_mcp_rounds(self, sample_id: str, function_address: str) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                UPDATE mcp_investigations
                SET rounds = rounds + 1, updated_at = ?
                WHERE sample_id = ? AND function_address = ?
                """,
                (_dt(utc_now()), sample_id, function_address),
            )
            connection.commit()

    def persist_ai_analysis_version(
        self,
        sample_id: str,
        function_address: str,
        *,
        source: str,
        analysis_pass: int,
        investigation_round: int | None,
        result_json: str,
        confidence: float,
        confidence_label: str,
        needs_investigation: bool,
    ) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                INSERT INTO ai_analysis_versions (
                    sample_id, function_address, source, analysis_pass,
                    investigation_round, result_json, confidence, confidence_label,
                    needs_investigation, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    sample_id,
                    function_address,
                    source,
                    analysis_pass,
                    investigation_round,
                    result_json,
                    confidence,
                    confidence_label,
                    int(needs_investigation),
                    _dt(utc_now()),
                ),
            )
            connection.commit()

    def get_mcp_investigation_rows(self, sample_id: str) -> list[dict]:
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT * FROM mcp_investigations WHERE sample_id = ? ORDER BY priority_score DESC, function_address",
                (sample_id,),
            ).fetchall()
        return [dict(row) for row in rows]

    def get_mcp_evidence_rows(self, sample_id: str, function_address: str | None = None) -> list[dict]:
        query = "SELECT * FROM mcp_evidence WHERE sample_id = ?"
        params: tuple = (sample_id,)
        if function_address is not None:
            query += " AND function_address = ?"
            params = (sample_id, function_address)
        query += " ORDER BY function_address, round_number, id"
        with self._connect() as connection:
            rows = connection.execute(query, params).fetchall()
        return [dict(row) for row in rows]

    def get_mcp_call_rows(self, sample_id: str) -> list[dict]:
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT * FROM mcp_calls WHERE sample_id = ? ORDER BY started_at, call_id",
                (sample_id,),
            ).fetchall()
        return [dict(row) for row in rows]

    def calculate_mcp_stats(self, sample_id: str, candidate_count: int | None = None) -> MCPInvestigationStats:
        investigations = self.get_mcp_investigation_rows(sample_id)
        calls = self.get_mcp_call_rows(sample_id)
        completed = [row for row in investigations if row["status"] == "COMPLETED"]
        before_values = [row["confidence_before"] for row in investigations if row["confidence_before"] is not None]
        after_values = [row["confidence_after"] for row in investigations if row["confidence_after"] is not None]
        return MCPInvestigationStats(
            candidates=candidate_count if candidate_count is not None else len(investigations),
            attempted=len(investigations),
            completed=len(completed),
            resolved_high=sum(1 for row in investigations if row["outcome"] == "RESOLVED_HIGH"),
            resolved_medium=sum(1 for row in investigations if row["outcome"] == "RESOLVED_MEDIUM"),
            unresolved=sum(1 for row in investigations if row["outcome"] == "UNRESOLVED"),
            budget_exhausted=sum(1 for row in investigations if row["outcome"] == "BUDGET_EXHAUSTED"),
            mcp_unavailable=sum(1 for row in investigations if row["outcome"] == "MCP_UNAVAILABLE"),
            failed=sum(1 for row in investigations if row["status"] == "FAILED" or row["outcome"] == "FAILED"),
            rounds=sum(int(row["rounds"] or 0) for row in investigations),
            mcp_calls=len(calls),
            tool_failures=sum(1 for row in calls if row["status"] != "SUCCESS"),
            confidence_improved=sum(1 for row in investigations if (row["confidence_delta"] or 0) > 0),
            confidence_reduced=sum(1 for row in investigations if (row["confidence_delta"] or 0) < 0),
            interpretation_changed=sum(1 for row in investigations if row["interpretation_changed"]),
            average_confidence_before=(sum(before_values) / len(before_values)) if before_values else 0.0,
            average_confidence_after=(sum(after_values) / len(after_values)) if after_values else 0.0,
        )

    def persist_validated_analysis(self, sample_id: str, model: ValidatedAnalysisModel) -> None:
        with self._connect() as connection:
            self._clear_validated_analysis(connection, sample_id)
            now = _dt(utc_now())
            for relationship in model.relationships:
                connection.execute(
                    """
                    INSERT INTO semantic_relationships (
                        relationship_id, sample_id, source_entity, target_entity,
                        relationship_type, confidence, evidence_json, provenance, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        relationship.relationship_id,
                        sample_id,
                        relationship.source_entity,
                        relationship.target_entity,
                        relationship.relationship_type.value,
                        relationship.confidence,
                        json.dumps(relationship.evidence, sort_keys=True),
                        relationship.provenance.value,
                        now,
                    ),
                )
            for finding in model.functions:
                connection.execute(
                    """
                    INSERT INTO validated_function_findings (
                        sample_id, function_address, original_name, proposed_name,
                        summary, confidence, confidence_label, analysis_pass, finding_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        sample_id,
                        finding.address,
                        finding.original_name,
                        finding.proposed_name,
                        finding.summary,
                        finding.confidence,
                        finding.confidence_label,
                        finding.analysis_pass,
                        finding.model_dump_json(),
                    ),
                )
            for subsystem in model.subsystems:
                connection.execute(
                    """
                    INSERT INTO subsystems (
                        sample_id, subsystem_id, name, confidence, evidence_json
                    ) VALUES (?, ?, ?, ?, ?)
                    """,
                    (
                        sample_id,
                        subsystem.subsystem_id,
                        subsystem.name,
                        subsystem.confidence,
                        json.dumps(subsystem.evidence, sort_keys=True),
                    ),
                )
                for member in subsystem.functions:
                    connection.execute(
                        """
                        INSERT INTO subsystem_functions (
                            sample_id, subsystem_id, function_address, role, confidence, evidence_json
                        ) VALUES (?, ?, ?, ?, ?, ?)
                        """,
                        (
                            sample_id,
                            subsystem.subsystem_id,
                            member.function_address,
                            member.role,
                            member.confidence,
                            json.dumps(member.evidence, sort_keys=True),
                        ),
                    )
            for flow in model.execution_flows:
                connection.execute(
                    """
                    INSERT OR REPLACE INTO execution_flows (
                        flow_id, sample_id, source_function, target_function,
                        relationship, confidence, evidence_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        flow.flow_id,
                        sample_id,
                        flow.source_function,
                        flow.target_function,
                        flow.relationship,
                        flow.confidence,
                        json.dumps(flow.evidence, sort_keys=True),
                    ),
                )
            for flow in model.data_flows:
                connection.execute(
                    """
                    INSERT OR REPLACE INTO data_flows (
                        flow_id, sample_id, source_entity, target_entity,
                        data_name, confidence, evidence_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        flow.flow_id,
                        sample_id,
                        flow.source_entity,
                        flow.target_entity,
                        flow.data_name,
                        flow.confidence,
                        json.dumps(flow.evidence, sort_keys=True),
                    ),
                )

            for structure in model.recovered_structures:
                connection.execute(
                    """
                    INSERT INTO recovered_structures (
                        sample_id, structure_id, name, confidence, size,
                        evidence_json, eligible_for_idb
                    ) VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        sample_id,
                        structure.structure_id,
                        structure.name,
                        structure.confidence,
                        structure.size,
                        json.dumps(structure.evidence, sort_keys=True),
                        int(structure.eligible_for_idb),
                    ),
                )
                for field in structure.fields:
                    connection.execute(
                        """
                        INSERT INTO recovered_structure_fields (
                            sample_id, structure_id, offset, name, field_type,
                            confidence, evidence_json, eligible_for_idb
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            sample_id,
                            structure.structure_id,
                            field.offset,
                            field.name,
                            field.field_type,
                            field.confidence,
                            json.dumps(field.evidence, sort_keys=True),
                            int(field.eligible_for_idb),
                        ),
                    )
            for artifact in model.validated_artifacts:
                connection.execute(
                    """
                    INSERT INTO validated_artifacts (
                        artifact_id, sample_id, original_value, normalized_value,
                        artifact_type, role, function_address, address, usage,
                        confidence, is_ioc, evidence_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        artifact.artifact_id,
                        sample_id,
                        artifact.original_value,
                        artifact.normalized_value,
                        artifact.artifact_type,
                        artifact.role,
                        artifact.function_address,
                        artifact.address,
                        artifact.usage,
                        artifact.confidence,
                        int(artifact.is_ioc),
                        json.dumps(artifact.evidence, sort_keys=True),
                    ),
                )
            for capability in model.capabilities:
                connection.execute(
                    """
                    INSERT INTO capabilities (
                        sample_id, capability_id, name, confidence, evidence_json
                    ) VALUES (?, ?, ?, ?, ?)
                    """,
                    (
                        sample_id,
                        capability.capability_id,
                        capability.name,
                        capability.confidence,
                        json.dumps(capability.evidence, sort_keys=True),
                    ),
                )
                for address in capability.functions:
                    connection.execute(
                        """
                        INSERT INTO capability_functions (
                            sample_id, capability_id, function_address, confidence, evidence_json
                        ) VALUES (?, ?, ?, ?, ?)
                        """,
                        (
                            sample_id,
                            capability.capability_id,
                            address,
                            capability.confidence,
                            json.dumps(capability.evidence, sort_keys=True),
                        ),
                    )
            for handler in model.command_handlers:
                connection.execute(
                    """
                    INSERT INTO command_handlers (
                        sample_id, dispatcher, command_id, handler, handler_name,
                        confidence, evidence_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        sample_id,
                        handler.dispatcher,
                        handler.command_id,
                        handler.handler,
                        handler.handler_name,
                        handler.confidence,
                        json.dumps(handler.evidence, sort_keys=True),
                    ),
                )
            for item in model.configuration_items:
                connection.execute(
                    """
                    INSERT INTO configuration_items (
                        item_id, sample_id, key, value, value_type,
                        function_address, confidence, evidence_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        item.item_id,
                        sample_id,
                        item.key,
                        item.value,
                        item.value_type,
                        item.function_address,
                        item.confidence,
                        json.dumps(item.evidence, sort_keys=True),
                    ),
                )
            for contradiction in model.contradictions:
                connection.execute(
                    """
                    INSERT INTO contradictions (
                        contradiction_id, sample_id, severity, entities_json,
                        description, evidence_json, status, resolution
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        contradiction.contradiction_id,
                        sample_id,
                        contradiction.severity,
                        json.dumps(contradiction.entities, sort_keys=True),
                        contradiction.description,
                        json.dumps(contradiction.evidence, sort_keys=True),
                        contradiction.status,
                        contradiction.resolution,
                    ),
                )
            for result in model.validation_results:
                connection.execute(
                    """
                    INSERT INTO validation_results (
                        result_id, sample_id, entity, validation_type, status,
                        confidence, reason, evidence_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        result.result_id,
                        sample_id,
                        result.entity,
                        result.validation_type,
                        result.status,
                        result.confidence,
                        result.reason,
                        json.dumps(result.evidence, sort_keys=True),
                    ),
                )
            for candidate in model.change_candidates:
                connection.execute(
                    """
                    INSERT INTO change_candidates (
                        candidate_id, sample_id, entity, address, change_type,
                        original, proposed, confidence, eligible_for_idb,
                        evidence_json, reason
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        candidate.candidate_id,
                        sample_id,
                        candidate.entity,
                        candidate.address,
                        candidate.change_type,
                        candidate.original,
                        candidate.proposed,
                        candidate.confidence,
                        int(candidate.eligible_for_idb),
                        json.dumps(candidate.evidence, sort_keys=True),
                        candidate.reason,
                    ),
                )
            for propagation in model.propagation_passes:
                connection.execute(
                    """
                    INSERT INTO propagation_passes (
                        sample_id, pass_number, functions_reconsidered,
                        interpretations_changed, confidence_changed,
                        new_relationships, new_structures, new_validated_artifacts,
                        converged, fingerprint, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        sample_id,
                        propagation.pass_number,
                        propagation.functions_reconsidered,
                        propagation.interpretations_changed,
                        propagation.confidence_changed,
                        propagation.new_relationships,
                        propagation.new_structures,
                        propagation.new_validated_artifacts,
                        int(propagation.converged),
                        propagation.fingerprint,
                        now,
                    ),
                )
            connection.commit()

    def calculate_semantic_stats(self, sample_id: str) -> SemanticAnalysisStats:
        with self._connect() as connection:
            scalar = {
                "functions_validated": "SELECT COUNT(*) FROM validated_function_findings WHERE sample_id = ?",
                "rename_candidates": "SELECT COUNT(*) FROM change_candidates WHERE sample_id = ? AND entity = 'function' AND change_type = 'rename'",
                "comment_candidates": "SELECT COUNT(*) FROM change_candidates WHERE sample_id = ? AND change_type = 'comment'",
                "variable_candidates": "SELECT COUNT(*) FROM change_candidates WHERE sample_id = ? AND entity = 'variable'",
                "type_candidates": "SELECT COUNT(*) FROM change_candidates WHERE sample_id = ? AND entity LIKE 'structure%'",
                "subsystems": "SELECT COUNT(*) FROM subsystems WHERE sample_id = ?",
                "capabilities": "SELECT COUNT(*) FROM capabilities WHERE sample_id = ?",
                "recovered_structures": "SELECT COUNT(*) FROM recovered_structures WHERE sample_id = ?",
                "recovered_fields": "SELECT COUNT(*) FROM recovered_structure_fields WHERE sample_id = ?",
                "command_handlers": "SELECT COUNT(*) FROM command_handlers WHERE sample_id = ?",
                "configuration_items": "SELECT COUNT(*) FROM configuration_items WHERE sample_id = ?",
                "validated_artifacts": "SELECT COUNT(*) FROM validated_artifacts WHERE sample_id = ?",
                "validated_iocs": "SELECT COUNT(*) FROM validated_artifacts WHERE sample_id = ? AND is_ioc = 1",
                "contradictions": "SELECT COUNT(*) FROM contradictions WHERE sample_id = ?",
                "unresolved_contradictions": "SELECT COUNT(*) FROM contradictions WHERE sample_id = ? AND status = 'OPEN'",
                "propagation_passes": "SELECT COUNT(*) FROM propagation_passes WHERE sample_id = ?",
                "semantic_relationships": "SELECT COUNT(*) FROM semantic_relationships WHERE sample_id = ?",
            }
            values = {
                key: int(connection.execute(query, (sample_id,)).fetchone()[0])
                for key, query in scalar.items()
            }
        return SemanticAnalysisStats(**values)

    def get_validated_analysis_fingerprint(self, sample_id: str) -> str | None:
        path = self.database_path.parent / "validated_analysis.json"
        if path.exists():
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
                fingerprint = data.get("fingerprint")
                if isinstance(fingerprint, str):
                    return fingerprint
            except (OSError, ValueError):
                pass
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT function_address, proposed_name, confidence, analysis_pass
                FROM validated_function_findings
                WHERE sample_id = ?
                ORDER BY function_address
                """,
                (sample_id,),
            ).fetchall()
        if not rows:
            return None
        import hashlib

        payload = [dict(row) for row in rows]
        return hashlib.sha256(json.dumps(payload, sort_keys=True).encode("utf-8")).hexdigest()

    def get_change_candidate_rows(self, sample_id: str) -> list[dict]:
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT * FROM change_candidates
                WHERE sample_id = ?
                ORDER BY entity, change_type, address, candidate_id
                """,
                (sample_id,),
            ).fetchall()
        return [dict(row) for row in rows]

    def get_validated_function_finding_rows(self, sample_id: str) -> dict[str, dict]:
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT * FROM validated_function_findings
                WHERE sample_id = ?
                ORDER BY function_address
                """,
                (sample_id,),
            ).fetchall()
        return {row["function_address"]: dict(row) for row in rows}

    def create_enrichment_run(self, run: EnrichmentRun) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                INSERT INTO enrichment_runs (
                    run_id, sample_id, source_analysis_fingerprint,
                    enrichment_fingerprint, mode, ida_version, reai_version, status,
                    original_idb_path, analyzed_idb_path, temp_idb_path,
                    started_at, completed_at, error, total_changes, applied_changes,
                    verified_changes, skipped_changes, failed_changes
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    run.run_id,
                    run.sample_id,
                    run.source_analysis_fingerprint,
                    run.enrichment_fingerprint,
                    run.mode,
                    run.ida_version,
                    run.reai_version,
                    run.status.value if hasattr(run.status, "value") else run.status,
                    run.original_idb_path,
                    run.analyzed_idb_path,
                    run.temp_idb_path,
                    run.started_at,
                    run.completed_at,
                    run.error,
                    run.total_changes,
                    run.applied_changes,
                    run.verified_changes,
                    run.skipped_changes,
                    run.failed_changes,
                ),
            )
            connection.commit()

    def update_enrichment_run(self, run: EnrichmentRun) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                UPDATE enrichment_runs
                SET status = ?, completed_at = ?, error = ?, total_changes = ?,
                    applied_changes = ?, verified_changes = ?, skipped_changes = ?,
                    failed_changes = ?
                WHERE run_id = ?
                """,
                (
                    run.status.value if hasattr(run.status, "value") else run.status,
                    run.completed_at,
                    run.error,
                    run.total_changes,
                    run.applied_changes,
                    run.verified_changes,
                    run.skipped_changes,
                    run.failed_changes,
                    run.run_id,
                ),
            )
            connection.commit()

    def persist_idb_changes(self, sample_id: str, run_id: str, changes: list[EnrichmentChange]) -> None:
        with self._connect() as connection:
            connection.execute("DELETE FROM idb_changes WHERE run_id = ?", (run_id,))
            for change in changes:
                connection.execute(
                    """
                    INSERT INTO idb_changes (
                        change_id, run_id, sample_id, candidate_id, entity, address,
                        operation, original, proposed, applied, confidence,
                        eligible_for_idb, status, reason, evidence_json, timestamp
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        change.change_id,
                        run_id,
                        sample_id,
                        change.candidate_id,
                        change.entity,
                        change.address,
                        change.operation,
                        change.original,
                        change.proposed,
                        change.applied,
                        change.confidence,
                        int(change.eligible_for_idb),
                        change.status.value if hasattr(change.status, "value") else change.status,
                        change.reason,
                        json.dumps(change.evidence, sort_keys=True),
                        change.timestamp or _dt(utc_now()),
                    ),
                )
            connection.commit()

    def persist_idb_verification(self, sample_id: str, run_id: str, verifications: list[IDBVerification]) -> None:
        with self._connect() as connection:
            connection.execute("DELETE FROM idb_verification WHERE run_id = ?", (run_id,))
            for verification in verifications:
                connection.execute(
                    """
                    INSERT INTO idb_verification (
                        verification_id, run_id, sample_id, change_id, expected,
                        actual, status, details, timestamp
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        verification.verification_id,
                        run_id,
                        sample_id,
                        verification.change_id,
                        verification.expected,
                        verification.actual,
                        verification.status.value if hasattr(verification.status, "value") else verification.status,
                        verification.details,
                        verification.timestamp or _dt(utc_now()),
                    ),
                )
            connection.commit()

    def get_latest_enrichment_run(self, sample_id: str) -> dict | None:
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT * FROM enrichment_runs
                WHERE sample_id = ?
                ORDER BY started_at DESC
                LIMIT 1
                """,
                (sample_id,),
            ).fetchone()
        return dict(row) if row else None

    def get_idb_change_rows(self, sample_id: str, run_id: str | None = None) -> list[dict]:
        query = "SELECT * FROM idb_changes WHERE sample_id = ?"
        params: tuple = (sample_id,)
        if run_id is not None:
            query += " AND run_id = ?"
            params = (sample_id, run_id)
        query += " ORDER BY timestamp, change_id"
        with self._connect() as connection:
            rows = connection.execute(query, params).fetchall()
        return [dict(row) for row in rows]

    def get_idb_verification_rows(self, sample_id: str, run_id: str | None = None) -> list[dict]:
        query = "SELECT * FROM idb_verification WHERE sample_id = ?"
        params: tuple = (sample_id,)
        if run_id is not None:
            query += " AND run_id = ?"
            params = (sample_id, run_id)
        query += " ORDER BY timestamp, verification_id"
        with self._connect() as connection:
            rows = connection.execute(query, params).fetchall()
        return [dict(row) for row in rows]

    def calculate_enrichment_stats(self, sample_id: str, run_id: str | None = None) -> EnrichmentStats:
        changes = self.get_idb_change_rows(sample_id, run_id)
        return EnrichmentStats(
            total_candidates=len(changes),
            eligible_candidates=sum(1 for row in changes if row["eligible_for_idb"]),
            function_renames=sum(1 for row in changes if row["entity"] == "function" and row["operation"] == "rename" and row["status"] in {"APPLIED", "VERIFIED"}),
            variable_renames=sum(1 for row in changes if row["entity"] == "variable" and row["operation"] == "rename" and row["status"] in {"APPLIED", "VERIFIED"}),
            comments=sum(1 for row in changes if row["operation"] == "comment" and row["status"] in {"APPLIED", "VERIFIED"}),
            structures=sum(1 for row in changes if row["entity"] == "structure" and row["status"] in {"APPLIED", "VERIFIED"}),
            structure_fields=sum(1 for row in changes if row["entity"] == "structure_field" and row["status"] in {"APPLIED", "VERIFIED"}),
            types=sum(1 for row in changes if row["operation"] in {"type", "prototype"} and row["status"] in {"APPLIED", "VERIFIED"}),
            applied=sum(1 for row in changes if row["status"] in {"APPLIED", "VERIFIED"}),
            verified=sum(1 for row in changes if row["status"] == "VERIFIED"),
            skipped=sum(1 for row in changes if str(row["status"]).startswith("SKIPPED")),
            failed=sum(1 for row in changes if row["status"] in {"FAILED", "FAILED_VERIFICATION"}),
            verification_failures=sum(1 for row in changes if row["status"] == "FAILED_VERIFICATION"),
        )

    def create_report_run(self, run: ReportRun) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                INSERT INTO report_runs (
                    run_id, sample_id, source_analysis_fingerprint,
                    enrichment_fingerprint, report_fingerprint, schema_version,
                    prompt_version, formats_json, status, started_at, completed_at,
                    error, sections_generated, sections_omitted, tables_generated,
                    diagrams_generated, iocs_rendered, functions_referenced,
                    evidence_references, validation_failures, markdown_path,
                    html_path, pdf_path
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    run.run_id,
                    run.sample_id,
                    run.source_analysis_fingerprint,
                    run.enrichment_fingerprint,
                    run.report_fingerprint,
                    run.schema_version,
                    run.prompt_version,
                    json.dumps(run.formats),
                    run.status.value if hasattr(run.status, "value") else run.status,
                    run.started_at,
                    run.completed_at,
                    run.error,
                    run.stats.sections_generated,
                    run.stats.sections_omitted,
                    run.stats.tables_generated,
                    run.stats.diagrams_generated,
                    run.stats.iocs_rendered,
                    run.stats.functions_referenced,
                    run.stats.evidence_references,
                    run.stats.validation_failures,
                    run.markdown_path,
                    run.html_path,
                    run.pdf_path,
                ),
            )
            connection.commit()

    def update_report_run(self, run: ReportRun) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                UPDATE report_runs
                SET status = ?, completed_at = ?, error = ?,
                    sections_generated = ?, sections_omitted = ?,
                    tables_generated = ?, diagrams_generated = ?, iocs_rendered = ?,
                    functions_referenced = ?, evidence_references = ?,
                    validation_failures = ?, markdown_path = ?, html_path = ?,
                    pdf_path = ?
                WHERE run_id = ?
                """,
                (
                    run.status.value if hasattr(run.status, "value") else run.status,
                    run.completed_at,
                    run.error,
                    run.stats.sections_generated,
                    run.stats.sections_omitted,
                    run.stats.tables_generated,
                    run.stats.diagrams_generated,
                    run.stats.iocs_rendered,
                    run.stats.functions_referenced,
                    run.stats.evidence_references,
                    run.stats.validation_failures,
                    run.markdown_path,
                    run.html_path,
                    run.pdf_path,
                    run.run_id,
                ),
            )
            connection.commit()

    def persist_report_sections(self, sample_id: str, run_id: str, sections: list[ReportSection]) -> None:
        with self._connect() as connection:
            connection.execute("DELETE FROM report_sections WHERE run_id = ?", (run_id,))
            for section in sections:
                connection.execute(
                    """
                    INSERT INTO report_sections (
                        section_id, run_id, sample_id, title, status, fingerprint,
                        source_facts_json, narrative, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        section.section_id,
                        run_id,
                        sample_id,
                        section.title,
                        section.status.value if hasattr(section.status, "value") else section.status,
                        section.fingerprint,
                        json.dumps(section.source_facts, sort_keys=True),
                        section.narrative,
                        _dt(utc_now()),
                    ),
                )
            connection.commit()

    def get_latest_report_run(self, sample_id: str) -> dict | None:
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT * FROM report_runs
                WHERE sample_id = ?
                ORDER BY started_at DESC
                LIMIT 1
                """,
                (sample_id,),
            ).fetchone()
        return dict(row) if row else None

    def get_report_section_rows(self, sample_id: str, run_id: str | None = None) -> list[dict]:
        query = "SELECT * FROM report_sections WHERE sample_id = ?"
        params: tuple = (sample_id,)
        if run_id is not None:
            query += " AND run_id = ?"
            params = (sample_id, run_id)
        query += " ORDER BY created_at, section_id"
        with self._connect() as connection:
            rows = connection.execute(query, params).fetchall()
        return [dict(row) for row in rows]

    def calculate_report_stats(self, sample_id: str) -> ReportStats:
        run = self.get_latest_report_run(sample_id)
        if not run:
            return ReportStats()
        return ReportStats(
            sections_generated=int(run["sections_generated"] or 0),
            sections_omitted=int(run["sections_omitted"] or 0),
            tables_generated=int(run["tables_generated"] or 0),
            diagrams_generated=int(run["diagrams_generated"] or 0),
            iocs_rendered=int(run["iocs_rendered"] or 0),
            functions_referenced=int(run["functions_referenced"] or 0),
            evidence_references=int(run["evidence_references"] or 0),
            validation_failures=int(run["validation_failures"] or 0),
            markdown_generated=bool(run["markdown_path"]),
            html_generated=bool(run["html_path"]),
            pdf_generated=bool(run["pdf_path"]),
        )

    @staticmethod
    def _clear_validated_analysis(connection: sqlite3.Connection, sample_id: str) -> None:
        tables = (
            "semantic_relationships",
            "validated_function_findings",
            "subsystems",
            "subsystem_functions",
            "execution_flows",
            "data_flows",
            "recovered_structures",
            "recovered_structure_fields",
            "validated_artifacts",
            "capabilities",
            "capability_functions",
            "command_handlers",
            "configuration_items",
            "contradictions",
            "validation_results",
            "change_candidates",
            "propagation_passes",
        )
        for table in tables:
            connection.execute(f"DELETE FROM {table} WHERE sample_id = ?", (sample_id,))

    @staticmethod
    def _clear_extraction(connection: sqlite3.Connection, sample_id: str) -> None:
        tables = (
            "binary_metadata",
            "functions",
            "function_calls",
            "strings",
            "string_xrefs",
            "imports",
            "import_xrefs",
            "exports",
            "segments",
            "globals",
            "global_xrefs",
            "types",
            "xrefs",
            "callgraph_nodes",
            "callgraph_components",
            "extraction_failures",
        )
        for table in tables:
            connection.execute(f"DELETE FROM {table} WHERE sample_id = ?", (sample_id,))

    @staticmethod
    def _row_to_sample(row: sqlite3.Row) -> Sample:
        from datetime import datetime

        return Sample(
            sample_id=row["sample_id"],
            filename=row["filename"],
            source_path=Path(row["source_path"]),
            size=row["size"],
            md5=row["md5"],
            sha1=row["sha1"],
            sha256=row["sha256"],
            workspace_path=Path(row["workspace_path"]),
            status=SampleState(row["status"]),
            created_at=datetime.fromisoformat(row["created_at"]),
            updated_at=datetime.fromisoformat(row["updated_at"]),
        )
