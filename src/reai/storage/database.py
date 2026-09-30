from __future__ import annotations

import sqlite3
from datetime import datetime, timezone
from pathlib import Path

SCHEMA_VERSION = 10


def connect_database(path: Path) -> sqlite3.Connection:
    path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(path, timeout=30)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    # WAL mode allows concurrent readers and a single writer without locking the
    # entire database. This prevents 'database is locked' errors during batch
    # processing and while the terminal UI reads stats concurrently.
    connection.execute("PRAGMA journal_mode = WAL")
    # NORMAL synchronous mode is safe with WAL and substantially faster than FULL.
    connection.execute("PRAGMA synchronous = NORMAL")
    return connection


def initialize_database(path: Path) -> None:
    with connect_database(path) as connection:
        connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS schema_migrations (
                version INTEGER PRIMARY KEY,
                applied_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS samples (
                sample_id TEXT PRIMARY KEY,
                filename TEXT NOT NULL,
                source_path TEXT NOT NULL,
                size INTEGER NOT NULL,
                md5 TEXT NOT NULL,
                sha1 TEXT NOT NULL,
                sha256 TEXT NOT NULL UNIQUE,
                workspace_path TEXT NOT NULL,
                status TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS jobs (
                job_id TEXT PRIMARY KEY,
                sample_id TEXT NOT NULL,
                status TEXT NOT NULL,
                created_at TEXT NOT NULL,
                started_at TEXT,
                updated_at TEXT NOT NULL,
                completed_at TEXT,
                error TEXT,
                config_json TEXT NOT NULL DEFAULT '{}',
                FOREIGN KEY(sample_id) REFERENCES samples(sample_id)
            );

            CREATE TABLE IF NOT EXISTS state_transitions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                sample_id TEXT NOT NULL,
                previous_state TEXT,
                new_state TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                message TEXT,
                FOREIGN KEY(sample_id) REFERENCES samples(sample_id)
            );

            CREATE TABLE IF NOT EXISTS binary_metadata (
                sample_id TEXT PRIMARY KEY,
                metadata_json TEXT NOT NULL,
                ida_version TEXT,
                architecture TEXT,
                bitness INTEGER,
                processor TEXT,
                image_base TEXT,
                updated_at TEXT NOT NULL,
                FOREIGN KEY(sample_id) REFERENCES samples(sample_id)
            );

            CREATE TABLE IF NOT EXISTS functions (
                sample_id TEXT NOT NULL,
                address TEXT NOT NULL,
                end_address TEXT NOT NULL,
                name TEXT NOT NULL,
                size INTEGER NOT NULL,
                segment TEXT,
                flags INTEGER,
                prototype TEXT,
                is_thunk INTEGER NOT NULL,
                is_library INTEGER NOT NULL,
                is_external INTEGER NOT NULL,
                decompilation_status TEXT NOT NULL,
                disassembly_status TEXT NOT NULL,
                pseudocode_path TEXT,
                disassembly_path TEXT,
                scc_id INTEGER,
                recursive INTEGER NOT NULL,
                record_json TEXT NOT NULL,
                PRIMARY KEY(sample_id, address),
                FOREIGN KEY(sample_id) REFERENCES samples(sample_id)
            );

            CREATE TABLE IF NOT EXISTS function_calls (
                sample_id TEXT NOT NULL,
                caller TEXT NOT NULL,
                callee TEXT NOT NULL,
                call_type TEXT NOT NULL,
                source_address TEXT,
                PRIMARY KEY(sample_id, caller, callee, call_type, source_address),
                FOREIGN KEY(sample_id) REFERENCES samples(sample_id)
            );

            CREATE TABLE IF NOT EXISTS strings (
                sample_id TEXT NOT NULL,
                address TEXT NOT NULL,
                value TEXT NOT NULL,
                encoding TEXT,
                length INTEGER,
                record_json TEXT NOT NULL,
                PRIMARY KEY(sample_id, address),
                FOREIGN KEY(sample_id) REFERENCES samples(sample_id)
            );

            CREATE TABLE IF NOT EXISTS string_xrefs (
                sample_id TEXT NOT NULL,
                string_address TEXT NOT NULL,
                function_address TEXT,
                source_address TEXT NOT NULL,
                xref_type TEXT,
                FOREIGN KEY(sample_id) REFERENCES samples(sample_id)
            );

            CREATE TABLE IF NOT EXISTS imports (
                sample_id TEXT NOT NULL,
                address TEXT NOT NULL,
                module TEXT,
                name TEXT,
                ordinal INTEGER,
                record_json TEXT NOT NULL,
                PRIMARY KEY(sample_id, address),
                FOREIGN KEY(sample_id) REFERENCES samples(sample_id)
            );

            CREATE TABLE IF NOT EXISTS import_xrefs (
                sample_id TEXT NOT NULL,
                import_address TEXT NOT NULL,
                function_address TEXT,
                source_address TEXT NOT NULL,
                xref_type TEXT,
                FOREIGN KEY(sample_id) REFERENCES samples(sample_id)
            );

            CREATE TABLE IF NOT EXISTS exports (
                sample_id TEXT NOT NULL,
                address TEXT NOT NULL,
                name TEXT,
                ordinal INTEGER,
                record_json TEXT NOT NULL,
                PRIMARY KEY(sample_id, address, ordinal),
                FOREIGN KEY(sample_id) REFERENCES samples(sample_id)
            );

            CREATE TABLE IF NOT EXISTS segments (
                sample_id TEXT NOT NULL,
                name TEXT NOT NULL,
                start TEXT NOT NULL,
                end TEXT NOT NULL,
                size INTEGER NOT NULL,
                permissions TEXT,
                segment_class TEXT,
                segment_type TEXT,
                record_json TEXT NOT NULL,
                PRIMARY KEY(sample_id, start, end),
                FOREIGN KEY(sample_id) REFERENCES samples(sample_id)
            );

            CREATE TABLE IF NOT EXISTS globals (
                sample_id TEXT NOT NULL,
                address TEXT NOT NULL,
                name TEXT NOT NULL,
                size INTEGER,
                type TEXT,
                segment TEXT,
                record_json TEXT NOT NULL,
                PRIMARY KEY(sample_id, address),
                FOREIGN KEY(sample_id) REFERENCES samples(sample_id)
            );

            CREATE TABLE IF NOT EXISTS global_xrefs (
                sample_id TEXT NOT NULL,
                global_address TEXT NOT NULL,
                function_address TEXT,
                source_address TEXT NOT NULL,
                xref_type TEXT,
                FOREIGN KEY(sample_id) REFERENCES samples(sample_id)
            );

            CREATE TABLE IF NOT EXISTS types (
                sample_id TEXT NOT NULL,
                name TEXT NOT NULL,
                kind TEXT NOT NULL,
                declaration TEXT,
                record_json TEXT NOT NULL,
                PRIMARY KEY(sample_id, name, kind),
                FOREIGN KEY(sample_id) REFERENCES samples(sample_id)
            );

            CREATE TABLE IF NOT EXISTS xrefs (
                sample_id TEXT NOT NULL,
                source_address TEXT NOT NULL,
                destination_address TEXT NOT NULL,
                xref_type TEXT,
                source_function TEXT,
                destination_entity TEXT,
                record_json TEXT NOT NULL,
                FOREIGN KEY(sample_id) REFERENCES samples(sample_id)
            );

            CREATE TABLE IF NOT EXISTS callgraph_nodes (
                sample_id TEXT NOT NULL,
                address TEXT NOT NULL,
                name TEXT NOT NULL,
                scc_id INTEGER,
                recursive INTEGER NOT NULL,
                PRIMARY KEY(sample_id, address),
                FOREIGN KEY(sample_id) REFERENCES samples(sample_id)
            );

            CREATE TABLE IF NOT EXISTS callgraph_components (
                sample_id TEXT NOT NULL,
                scc_id INTEGER NOT NULL,
                recursive INTEGER NOT NULL,
                nodes_json TEXT NOT NULL,
                PRIMARY KEY(sample_id, scc_id),
                FOREIGN KEY(sample_id) REFERENCES samples(sample_id)
            );

            CREATE TABLE IF NOT EXISTS extraction_failures (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                sample_id TEXT NOT NULL,
                extractor TEXT NOT NULL,
                address TEXT,
                name TEXT,
                reason TEXT NOT NULL,
                fatal INTEGER NOT NULL,
                FOREIGN KEY(sample_id) REFERENCES samples(sample_id)
            );

            CREATE TABLE IF NOT EXISTS ai_function_analysis (
                sample_id TEXT NOT NULL,
                address TEXT NOT NULL,
                original_name TEXT NOT NULL,
                proposed_name TEXT,
                summary TEXT,
                confidence REAL NOT NULL,
                confidence_label TEXT NOT NULL,
                needs_investigation INTEGER NOT NULL,
                status TEXT NOT NULL,
                analysis_pass INTEGER NOT NULL,
                result_json TEXT NOT NULL,
                prompt_version TEXT NOT NULL,
                schema_version TEXT NOT NULL,
                confidence_policy_version TEXT NOT NULL,
                context_builder_version TEXT NOT NULL,
                analysis_fingerprint TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                PRIMARY KEY(sample_id, address),
                FOREIGN KEY(sample_id) REFERENCES samples(sample_id)
            );

            CREATE TABLE IF NOT EXISTS ai_evidence (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                sample_id TEXT NOT NULL,
                function_address TEXT NOT NULL,
                evidence_type TEXT NOT NULL,
                source TEXT NOT NULL,
                address TEXT,
                value TEXT,
                description TEXT NOT NULL,
                FOREIGN KEY(sample_id) REFERENCES samples(sample_id)
            );

            CREATE TABLE IF NOT EXISTS ai_variable_proposals (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                sample_id TEXT NOT NULL,
                function_address TEXT NOT NULL,
                original TEXT NOT NULL,
                proposed TEXT NOT NULL,
                confidence REAL NOT NULL,
                evidence TEXT NOT NULL,
                FOREIGN KEY(sample_id) REFERENCES samples(sample_id)
            );

            CREATE TABLE IF NOT EXISTS ai_type_suggestions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                sample_id TEXT NOT NULL,
                function_address TEXT NOT NULL,
                target TEXT NOT NULL,
                proposed_type TEXT NOT NULL,
                confidence REAL NOT NULL,
                evidence TEXT NOT NULL,
                FOREIGN KEY(sample_id) REFERENCES samples(sample_id)
            );

            CREATE TABLE IF NOT EXISTS ai_artifact_candidates (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                sample_id TEXT NOT NULL,
                function_address TEXT NOT NULL,
                value TEXT NOT NULL,
                artifact_type TEXT NOT NULL,
                address TEXT,
                usage TEXT,
                confidence REAL NOT NULL,
                record_json TEXT NOT NULL,
                FOREIGN KEY(sample_id) REFERENCES samples(sample_id)
            );

            CREATE TABLE IF NOT EXISTS ai_requests (
                request_id TEXT PRIMARY KEY,
                sample_id TEXT NOT NULL,
                function_address TEXT,
                provider TEXT NOT NULL,
                model TEXT,
                task TEXT NOT NULL,
                analysis_pass INTEGER NOT NULL,
                timestamp TEXT NOT NULL,
                input_tokens INTEGER,
                output_tokens INTEGER,
                latency_ms INTEGER,
                retry_count INTEGER NOT NULL,
                success INTEGER NOT NULL,
                error TEXT,
                FOREIGN KEY(sample_id) REFERENCES samples(sample_id)
            );

            CREATE TABLE IF NOT EXISTS ai_analysis_versions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                sample_id TEXT NOT NULL,
                function_address TEXT NOT NULL,
                source TEXT NOT NULL,
                analysis_pass INTEGER NOT NULL,
                investigation_round INTEGER,
                result_json TEXT NOT NULL,
                confidence REAL NOT NULL,
                confidence_label TEXT NOT NULL,
                needs_investigation INTEGER NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY(sample_id) REFERENCES samples(sample_id)
            );

            CREATE TABLE IF NOT EXISTS mcp_investigations (
                sample_id TEXT NOT NULL,
                function_address TEXT NOT NULL,
                current_name TEXT,
                proposed_name TEXT,
                status TEXT NOT NULL,
                outcome TEXT,
                priority_score REAL NOT NULL,
                priority_reason TEXT NOT NULL,
                confidence_before REAL,
                confidence_after REAL,
                confidence_delta REAL,
                rounds INTEGER NOT NULL DEFAULT 0,
                tool_calls INTEGER NOT NULL DEFAULT 0,
                interpretation_changed INTEGER NOT NULL DEFAULT 0,
                started_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                completed_at TEXT,
                error TEXT,
                PRIMARY KEY(sample_id, function_address),
                FOREIGN KEY(sample_id) REFERENCES samples(sample_id)
            );

            CREATE TABLE IF NOT EXISTS mcp_sessions (
                session_id TEXT PRIMARY KEY,
                sample_id TEXT NOT NULL,
                backend TEXT NOT NULL,
                provider TEXT NOT NULL,
                transport TEXT NOT NULL,
                connection_mode TEXT NOT NULL,
                database TEXT,
                ida_version TEXT,
                backend_version TEXT,
                read_only INTEGER NOT NULL,
                sample_identity_verified INTEGER NOT NULL,
                available_tools_json TEXT NOT NULL,
                normalized_capabilities_json TEXT NOT NULL,
                status TEXT NOT NULL,
                started_at TEXT NOT NULL,
                completed_at TEXT,
                error TEXT,
                FOREIGN KEY(sample_id) REFERENCES samples(sample_id)
            );

            CREATE TABLE IF NOT EXISTS mcp_capabilities (
                session_id TEXT NOT NULL,
                sample_id TEXT NOT NULL,
                capability TEXT NOT NULL,
                tool_name TEXT,
                available INTEGER NOT NULL,
                read_only INTEGER NOT NULL,
                PRIMARY KEY(session_id, capability),
                FOREIGN KEY(sample_id) REFERENCES samples(sample_id),
                FOREIGN KEY(session_id) REFERENCES mcp_sessions(session_id)
            );

            CREATE TABLE IF NOT EXISTS mcp_questions (
                question_id TEXT PRIMARY KEY,
                sample_id TEXT NOT NULL,
                function_address TEXT NOT NULL,
                question TEXT NOT NULL,
                reason TEXT NOT NULL,
                priority TEXT NOT NULL,
                status TEXT NOT NULL,
                answer TEXT,
                evidence_json TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                completed_at TEXT,
                FOREIGN KEY(sample_id) REFERENCES samples(sample_id)
            );

            CREATE TABLE IF NOT EXISTS mcp_rounds (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                sample_id TEXT NOT NULL,
                function_address TEXT NOT NULL,
                round_number INTEGER NOT NULL,
                goal TEXT NOT NULL,
                plan_json TEXT NOT NULL,
                confidence_before REAL,
                confidence_after REAL,
                unknowns_before_json TEXT NOT NULL,
                unknowns_after_json TEXT NOT NULL,
                status TEXT NOT NULL,
                started_at TEXT NOT NULL,
                completed_at TEXT,
                FOREIGN KEY(sample_id) REFERENCES samples(sample_id)
            );

            CREATE TABLE IF NOT EXISTS mcp_calls (
                call_id TEXT PRIMARY KEY,
                sample_id TEXT NOT NULL,
                function_address TEXT NOT NULL,
                round_number INTEGER NOT NULL,
                capability TEXT NOT NULL,
                target TEXT NOT NULL,
                parameters_json TEXT NOT NULL,
                fingerprint TEXT NOT NULL,
                started_at TEXT NOT NULL,
                completed_at TEXT,
                duration_ms INTEGER,
                status TEXT NOT NULL,
                result_size INTEGER NOT NULL DEFAULT 0,
                result_json TEXT,
                error TEXT,
                FOREIGN KEY(sample_id) REFERENCES samples(sample_id)
            );

            CREATE TABLE IF NOT EXISTS mcp_evidence (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                sample_id TEXT NOT NULL,
                function_address TEXT NOT NULL,
                round_number INTEGER NOT NULL,
                capability TEXT NOT NULL,
                target TEXT NOT NULL,
                evidence_type TEXT NOT NULL,
                source TEXT NOT NULL,
                address TEXT,
                value TEXT,
                description TEXT NOT NULL,
                record_json TEXT NOT NULL,
                fingerprint TEXT NOT NULL,
                deduped INTEGER NOT NULL DEFAULT 0,
                FOREIGN KEY(sample_id) REFERENCES samples(sample_id),
                UNIQUE(sample_id, function_address, fingerprint)
            );

            CREATE TABLE IF NOT EXISTS semantic_relationships (
                relationship_id TEXT PRIMARY KEY,
                sample_id TEXT NOT NULL,
                source_entity TEXT NOT NULL,
                target_entity TEXT NOT NULL,
                relationship_type TEXT NOT NULL,
                confidence REAL NOT NULL,
                evidence_json TEXT NOT NULL,
                provenance TEXT NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY(sample_id) REFERENCES samples(sample_id)
            );

            CREATE TABLE IF NOT EXISTS validated_function_findings (
                sample_id TEXT NOT NULL,
                function_address TEXT NOT NULL,
                original_name TEXT NOT NULL,
                proposed_name TEXT,
                summary TEXT,
                confidence REAL NOT NULL,
                confidence_label TEXT NOT NULL,
                analysis_pass INTEGER NOT NULL,
                finding_json TEXT NOT NULL,
                PRIMARY KEY(sample_id, function_address),
                FOREIGN KEY(sample_id) REFERENCES samples(sample_id)
            );

            CREATE TABLE IF NOT EXISTS subsystems (
                subsystem_id TEXT NOT NULL,
                sample_id TEXT NOT NULL,
                name TEXT NOT NULL,
                confidence REAL NOT NULL,
                evidence_json TEXT NOT NULL,
                PRIMARY KEY(sample_id, subsystem_id),
                FOREIGN KEY(sample_id) REFERENCES samples(sample_id)
            );

            CREATE TABLE IF NOT EXISTS subsystem_functions (
                sample_id TEXT NOT NULL,
                subsystem_id TEXT NOT NULL,
                function_address TEXT NOT NULL,
                role TEXT NOT NULL,
                confidence REAL NOT NULL,
                evidence_json TEXT NOT NULL,
                PRIMARY KEY(sample_id, subsystem_id, function_address),
                FOREIGN KEY(sample_id) REFERENCES samples(sample_id)
            );

            CREATE TABLE IF NOT EXISTS execution_flows (
                flow_id TEXT PRIMARY KEY,
                sample_id TEXT NOT NULL,
                source_function TEXT NOT NULL,
                target_function TEXT NOT NULL,
                relationship TEXT NOT NULL,
                confidence REAL NOT NULL,
                evidence_json TEXT NOT NULL,
                FOREIGN KEY(sample_id) REFERENCES samples(sample_id)
            );

            CREATE TABLE IF NOT EXISTS data_flows (
                flow_id TEXT PRIMARY KEY,
                sample_id TEXT NOT NULL,
                source_entity TEXT NOT NULL,
                target_entity TEXT NOT NULL,
                data_name TEXT,
                confidence REAL NOT NULL,
                evidence_json TEXT NOT NULL,
                FOREIGN KEY(sample_id) REFERENCES samples(sample_id)
            );

            CREATE TABLE IF NOT EXISTS recovered_structures (
                structure_id TEXT NOT NULL,
                sample_id TEXT NOT NULL,
                name TEXT NOT NULL,
                confidence REAL NOT NULL,
                size INTEGER,
                evidence_json TEXT NOT NULL,
                eligible_for_idb INTEGER NOT NULL,
                PRIMARY KEY(sample_id, structure_id),
                FOREIGN KEY(sample_id) REFERENCES samples(sample_id)
            );

            CREATE TABLE IF NOT EXISTS recovered_structure_fields (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                sample_id TEXT NOT NULL,
                structure_id TEXT NOT NULL,
                offset TEXT NOT NULL,
                name TEXT NOT NULL,
                field_type TEXT NOT NULL,
                confidence REAL NOT NULL,
                evidence_json TEXT NOT NULL,
                eligible_for_idb INTEGER NOT NULL,
                FOREIGN KEY(sample_id) REFERENCES samples(sample_id)
            );

            CREATE TABLE IF NOT EXISTS validated_artifacts (
                artifact_id TEXT PRIMARY KEY,
                sample_id TEXT NOT NULL,
                original_value TEXT NOT NULL,
                normalized_value TEXT NOT NULL,
                artifact_type TEXT NOT NULL,
                role TEXT NOT NULL,
                function_address TEXT,
                address TEXT,
                usage TEXT,
                confidence REAL NOT NULL,
                is_ioc INTEGER NOT NULL,
                evidence_json TEXT NOT NULL,
                FOREIGN KEY(sample_id) REFERENCES samples(sample_id)
            );

            CREATE TABLE IF NOT EXISTS capabilities (
                capability_id TEXT NOT NULL,
                sample_id TEXT NOT NULL,
                name TEXT NOT NULL,
                confidence REAL NOT NULL,
                evidence_json TEXT NOT NULL,
                PRIMARY KEY(sample_id, capability_id),
                FOREIGN KEY(sample_id) REFERENCES samples(sample_id)
            );

            CREATE TABLE IF NOT EXISTS capability_functions (
                sample_id TEXT NOT NULL,
                capability_id TEXT NOT NULL,
                function_address TEXT NOT NULL,
                confidence REAL NOT NULL,
                evidence_json TEXT NOT NULL,
                PRIMARY KEY(sample_id, capability_id, function_address),
                FOREIGN KEY(sample_id) REFERENCES samples(sample_id)
            );

            CREATE TABLE IF NOT EXISTS command_handlers (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                sample_id TEXT NOT NULL,
                dispatcher TEXT NOT NULL,
                command_id TEXT NOT NULL,
                handler TEXT NOT NULL,
                handler_name TEXT,
                confidence REAL NOT NULL,
                evidence_json TEXT NOT NULL,
                FOREIGN KEY(sample_id) REFERENCES samples(sample_id)
            );

            CREATE TABLE IF NOT EXISTS configuration_items (
                item_id TEXT PRIMARY KEY,
                sample_id TEXT NOT NULL,
                key TEXT NOT NULL,
                value TEXT,
                value_type TEXT NOT NULL,
                function_address TEXT,
                confidence REAL NOT NULL,
                evidence_json TEXT NOT NULL,
                FOREIGN KEY(sample_id) REFERENCES samples(sample_id)
            );

            CREATE TABLE IF NOT EXISTS contradictions (
                contradiction_id TEXT PRIMARY KEY,
                sample_id TEXT NOT NULL,
                severity TEXT NOT NULL,
                entities_json TEXT NOT NULL,
                description TEXT NOT NULL,
                evidence_json TEXT NOT NULL,
                status TEXT NOT NULL,
                resolution TEXT,
                FOREIGN KEY(sample_id) REFERENCES samples(sample_id)
            );

            CREATE TABLE IF NOT EXISTS validation_results (
                result_id TEXT PRIMARY KEY,
                sample_id TEXT NOT NULL,
                entity TEXT NOT NULL,
                validation_type TEXT NOT NULL,
                status TEXT NOT NULL,
                confidence REAL NOT NULL,
                reason TEXT NOT NULL,
                evidence_json TEXT NOT NULL,
                FOREIGN KEY(sample_id) REFERENCES samples(sample_id)
            );

            CREATE TABLE IF NOT EXISTS change_candidates (
                candidate_id TEXT PRIMARY KEY,
                sample_id TEXT NOT NULL,
                entity TEXT NOT NULL,
                address TEXT,
                change_type TEXT NOT NULL,
                original TEXT,
                proposed TEXT NOT NULL,
                confidence REAL NOT NULL,
                eligible_for_idb INTEGER NOT NULL,
                evidence_json TEXT NOT NULL,
                reason TEXT,
                FOREIGN KEY(sample_id) REFERENCES samples(sample_id)
            );

            CREATE TABLE IF NOT EXISTS propagation_passes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                sample_id TEXT NOT NULL,
                pass_number INTEGER NOT NULL,
                functions_reconsidered INTEGER NOT NULL,
                interpretations_changed INTEGER NOT NULL,
                confidence_changed INTEGER NOT NULL,
                new_relationships INTEGER NOT NULL,
                new_structures INTEGER NOT NULL,
                new_validated_artifacts INTEGER NOT NULL,
                converged INTEGER NOT NULL,
                fingerprint TEXT NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY(sample_id) REFERENCES samples(sample_id)
            );

            CREATE TABLE IF NOT EXISTS enrichment_runs (
                run_id TEXT PRIMARY KEY,
                sample_id TEXT NOT NULL,
                source_analysis_fingerprint TEXT,
                enrichment_fingerprint TEXT NOT NULL,
                mode TEXT NOT NULL,
                ida_version TEXT,
                reai_version TEXT NOT NULL,
                status TEXT NOT NULL,
                original_idb_path TEXT NOT NULL,
                analyzed_idb_path TEXT NOT NULL,
                temp_idb_path TEXT,
                started_at TEXT NOT NULL,
                completed_at TEXT,
                error TEXT,
                total_changes INTEGER NOT NULL DEFAULT 0,
                applied_changes INTEGER NOT NULL DEFAULT 0,
                verified_changes INTEGER NOT NULL DEFAULT 0,
                skipped_changes INTEGER NOT NULL DEFAULT 0,
                failed_changes INTEGER NOT NULL DEFAULT 0,
                FOREIGN KEY(sample_id) REFERENCES samples(sample_id)
            );

            CREATE TABLE IF NOT EXISTS idb_changes (
                change_id TEXT PRIMARY KEY,
                run_id TEXT NOT NULL,
                sample_id TEXT NOT NULL,
                candidate_id TEXT,
                entity TEXT NOT NULL,
                address TEXT,
                operation TEXT NOT NULL,
                original TEXT,
                proposed TEXT NOT NULL,
                applied TEXT,
                confidence REAL NOT NULL,
                eligible_for_idb INTEGER NOT NULL,
                status TEXT NOT NULL,
                reason TEXT,
                evidence_json TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                FOREIGN KEY(sample_id) REFERENCES samples(sample_id),
                FOREIGN KEY(run_id) REFERENCES enrichment_runs(run_id)
            );

            CREATE TABLE IF NOT EXISTS idb_verification (
                verification_id TEXT PRIMARY KEY,
                run_id TEXT NOT NULL,
                sample_id TEXT NOT NULL,
                change_id TEXT NOT NULL,
                expected TEXT,
                actual TEXT,
                status TEXT NOT NULL,
                details TEXT,
                timestamp TEXT NOT NULL,
                FOREIGN KEY(sample_id) REFERENCES samples(sample_id),
                FOREIGN KEY(run_id) REFERENCES enrichment_runs(run_id),
                FOREIGN KEY(change_id) REFERENCES idb_changes(change_id)
            );

            CREATE TABLE IF NOT EXISTS report_runs (
                run_id TEXT PRIMARY KEY,
                sample_id TEXT NOT NULL,
                source_analysis_fingerprint TEXT,
                enrichment_fingerprint TEXT,
                report_fingerprint TEXT NOT NULL,
                schema_version TEXT NOT NULL,
                prompt_version TEXT NOT NULL,
                formats_json TEXT NOT NULL,
                status TEXT NOT NULL,
                started_at TEXT NOT NULL,
                completed_at TEXT,
                error TEXT,
                sections_generated INTEGER NOT NULL DEFAULT 0,
                sections_omitted INTEGER NOT NULL DEFAULT 0,
                tables_generated INTEGER NOT NULL DEFAULT 0,
                diagrams_generated INTEGER NOT NULL DEFAULT 0,
                iocs_rendered INTEGER NOT NULL DEFAULT 0,
                functions_referenced INTEGER NOT NULL DEFAULT 0,
                evidence_references INTEGER NOT NULL DEFAULT 0,
                validation_failures INTEGER NOT NULL DEFAULT 0,
                markdown_path TEXT,
                html_path TEXT,
                pdf_path TEXT,
                FOREIGN KEY(sample_id) REFERENCES samples(sample_id)
            );

            CREATE TABLE IF NOT EXISTS report_sections (
                section_id TEXT NOT NULL,
                run_id TEXT NOT NULL,
                sample_id TEXT NOT NULL,
                title TEXT NOT NULL,
                status TEXT NOT NULL,
                fingerprint TEXT NOT NULL,
                source_facts_json TEXT NOT NULL,
                narrative TEXT NOT NULL,
                created_at TEXT NOT NULL,
                PRIMARY KEY(run_id, section_id),
                FOREIGN KEY(sample_id) REFERENCES samples(sample_id),
                FOREIGN KEY(run_id) REFERENCES report_runs(run_id)
            );
            """
        )
        _apply_migrations(connection)
        connection.commit()


def _apply_migrations(connection: sqlite3.Connection) -> None:
    now = datetime.now(timezone.utc).isoformat()

    applied_v1 = connection.execute(
        "SELECT 1 FROM schema_migrations WHERE version = 1"
    ).fetchone()
    if applied_v1 is None:
        connection.execute(
            "INSERT INTO schema_migrations(version, applied_at) VALUES (?, ?)",
            (1, now),
        )

    columns = {
        row["name"]
        for row in connection.execute("PRAGMA table_info(jobs)").fetchall()
    }
    if "config_json" not in columns:
        connection.execute("ALTER TABLE jobs ADD COLUMN config_json TEXT NOT NULL DEFAULT '{}'")

    applied_v2 = connection.execute(
        "SELECT 1 FROM schema_migrations WHERE version = 2"
    ).fetchone()
    if applied_v2 is None:
        connection.execute(
            "INSERT INTO schema_migrations(version, applied_at) VALUES (?, ?)",
            (2, now),
        )

    applied_v3 = connection.execute(
        "SELECT 1 FROM schema_migrations WHERE version = 3"
    ).fetchone()
    if applied_v3 is None:
        connection.execute(
            "INSERT INTO schema_migrations(version, applied_at) VALUES (?, ?)",
            (3, now),
        )

    applied_v4 = connection.execute(
        "SELECT 1 FROM schema_migrations WHERE version = 4"
    ).fetchone()
    if applied_v4 is None:
        connection.execute(
            "INSERT INTO schema_migrations(version, applied_at) VALUES (?, ?)",
            (4, now),
        )

    applied_v5 = connection.execute(
        "SELECT 1 FROM schema_migrations WHERE version = 5"
    ).fetchone()
    if applied_v5 is None:
        connection.execute(
            "INSERT INTO schema_migrations(version, applied_at) VALUES (?, ?)",
            (5, now),
        )

    applied_v6 = connection.execute(
        "SELECT 1 FROM schema_migrations WHERE version = 6"
    ).fetchone()
    if applied_v6 is None:
        connection.execute(
            "INSERT INTO schema_migrations(version, applied_at) VALUES (?, ?)",
            (6, now),
        )

    applied_v7 = connection.execute(
        "SELECT 1 FROM schema_migrations WHERE version = 7"
    ).fetchone()
    if applied_v7 is None:
        connection.execute(
            "INSERT INTO schema_migrations(version, applied_at) VALUES (?, ?)",
            (7, now),
        )

    applied_v8 = connection.execute(
        "SELECT 1 FROM schema_migrations WHERE version = 8"
    ).fetchone()
    if applied_v8 is None:
        connection.execute(
            "INSERT INTO schema_migrations(version, applied_at) VALUES (?, ?)",
            (8, now),
        )

    connection.executescript(
        """
        CREATE TABLE IF NOT EXISTS mcp_sessions (
            session_id TEXT PRIMARY KEY,
            sample_id TEXT NOT NULL,
            backend TEXT NOT NULL,
            provider TEXT NOT NULL,
            transport TEXT NOT NULL,
            connection_mode TEXT NOT NULL,
            database TEXT,
            ida_version TEXT,
            backend_version TEXT,
            read_only INTEGER NOT NULL,
            sample_identity_verified INTEGER NOT NULL,
            available_tools_json TEXT NOT NULL,
            normalized_capabilities_json TEXT NOT NULL,
            status TEXT NOT NULL,
            started_at TEXT NOT NULL,
            completed_at TEXT,
            error TEXT,
            FOREIGN KEY(sample_id) REFERENCES samples(sample_id)
        );

        CREATE TABLE IF NOT EXISTS mcp_capabilities (
            session_id TEXT NOT NULL,
            sample_id TEXT NOT NULL,
            capability TEXT NOT NULL,
            tool_name TEXT,
            available INTEGER NOT NULL,
            read_only INTEGER NOT NULL,
            PRIMARY KEY(session_id, capability),
            FOREIGN KEY(sample_id) REFERENCES samples(sample_id),
            FOREIGN KEY(session_id) REFERENCES mcp_sessions(session_id)
        );
        """
    )
    applied_v9 = connection.execute(
        "SELECT 1 FROM schema_migrations WHERE version = 9"
    ).fetchone()
    if applied_v9 is None:
        connection.execute(
            "INSERT INTO schema_migrations(version, applied_at) VALUES (?, ?)",
            (9, now),
        )

    connection.executescript(
        """
        CREATE TABLE IF NOT EXISTS mcp_questions (
            question_id TEXT PRIMARY KEY,
            sample_id TEXT NOT NULL,
            function_address TEXT NOT NULL,
            question TEXT NOT NULL,
            reason TEXT NOT NULL,
            priority TEXT NOT NULL,
            status TEXT NOT NULL,
            answer TEXT,
            evidence_json TEXT NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            completed_at TEXT,
            FOREIGN KEY(sample_id) REFERENCES samples(sample_id)
        );
        """
    )
    applied_v10 = connection.execute(
        "SELECT 1 FROM schema_migrations WHERE version = 10"
    ).fetchone()
    if applied_v10 is None:
        connection.execute(
            "INSERT INTO schema_migrations(version, applied_at) VALUES (?, ?)",
            (10, now),
        )
