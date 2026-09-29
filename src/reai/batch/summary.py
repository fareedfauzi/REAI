from __future__ import annotations

import json
import sqlite3
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from reai.extraction.serialization import atomic_write_text
from reai.utils.redaction import redact_secrets


def new_batch_id() -> str:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    return f"batch_{stamp}_{uuid.uuid4().hex[:8]}"


def write_batch_outputs(result: Any, *, batch_id: str, started_at: str, completed_at: str) -> None:
    payload = build_batch_summary(result, batch_id=batch_id, started_at=started_at, completed_at=completed_at)
    output_root = Path(result.output_root)
    atomic_write_text(output_root / "batch-summary.json", json.dumps(payload, indent=2, sort_keys=True) + "\n")
    atomic_write_text(output_root / "batch-report.md", render_batch_report(payload))
    persist_batch_index(output_root / "batch.db", payload)


def build_batch_summary(result: Any, *, batch_id: str, started_at: str, completed_at: str) -> dict:
    samples = []
    for item in result.samples:
        error = getattr(item, "error", None)
        samples.append(
            {
                "filename": item.sample.filename,
                "sha256": item.sample.sha256,
                "status": item.status.value if hasattr(item.status, "value") else str(item.status),
                "sample_state": item.sample.status.value if hasattr(item.sample.status, "value") else str(item.sample.status),
                "workspace": str(item.workspace.root),
                "duplicate_of": item.duplicate_of,
                "error_type": getattr(item, "error_type", None),
                "error": redact_secrets(error) if error else None,
            }
        )
    unique = [item for item in result.samples if item.status.value != "DUPLICATE"]
    failed = [item for item in unique if item.status.value == "FAILED"]
    complete = [item for item in unique if item.status.value == "COMPLETE"]
    partial = [item for item in unique if item.status.value not in {"COMPLETE", "FAILED"}]
    return {
        "batch_id": batch_id,
        "input_path": str(result.input_path),
        "input_kind": result.input_kind.value,
        "output_root": str(result.output_root),
        "started_at": started_at,
        "completed_at": completed_at,
        "workers": result.workers,
        "recursive": result.recursive,
        "discovered": len(result.samples) + len(result.skipped),
        "unique_samples": len(unique),
        "duplicates": sum(1 for item in result.samples if item.status.value == "DUPLICATE"),
        "skipped": list(result.skipped),
        "success_count": len(complete),
        "failure_count": len(failed),
        "partial_count": len(partial),
        "samples": samples,
    }


def render_batch_report(payload: dict) -> str:
    lines = [
        f"# REAI Batch Report: {payload['batch_id']}",
        "",
        "| Field | Value |",
        "| --- | --- |",
        f"| Input | `{payload['input_path']}` |",
        f"| Output | `{payload['output_root']}` |",
        f"| Workers | {payload['workers']} |",
        f"| Recursive | {payload['recursive']} |",
        f"| Unique samples | {payload['unique_samples']} |",
        f"| Complete | {payload['success_count']} |",
        f"| Failed | {payload['failure_count']} |",
        f"| Partial | {payload['partial_count']} |",
        f"| Duplicates | {payload['duplicates']} |",
        "",
        "## Samples",
        "",
        "| Sample | SHA256 | Status | Workspace | Error |",
        "| --- | --- | --- | --- | --- |",
    ]
    for sample in payload["samples"]:
        error = (sample.get("error") or "").replace("|", "\\|")
        lines.append(
            f"| {sample['filename']} | `{sample['sha256']}` | {sample['status']} | `{sample['workspace']}` | {error} |"
        )
    if payload["skipped"]:
        lines.extend(["", "## Skipped", ""])
        lines.extend(f"- {item}" for item in payload["skipped"])
    return "\n".join(lines).rstrip() + "\n"


def persist_batch_index(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(path) as connection:
        connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS batches (
                batch_id TEXT PRIMARY KEY,
                input_path TEXT NOT NULL,
                output_root TEXT NOT NULL,
                started_at TEXT NOT NULL,
                completed_at TEXT NOT NULL,
                workers INTEGER NOT NULL,
                recursive INTEGER NOT NULL,
                unique_samples INTEGER NOT NULL,
                success_count INTEGER NOT NULL,
                failure_count INTEGER NOT NULL,
                partial_count INTEGER NOT NULL,
                duplicates INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS batch_samples (
                batch_id TEXT NOT NULL,
                sha256 TEXT NOT NULL,
                filename TEXT NOT NULL,
                status TEXT NOT NULL,
                sample_state TEXT NOT NULL,
                workspace TEXT NOT NULL,
                duplicate_of TEXT,
                error_type TEXT,
                error TEXT,
                PRIMARY KEY(batch_id, sha256, filename)
            );
            """
        )
        connection.execute(
            """
            INSERT OR REPLACE INTO batches (
                batch_id, input_path, output_root, started_at, completed_at,
                workers, recursive, unique_samples, success_count, failure_count,
                partial_count, duplicates
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                payload["batch_id"],
                payload["input_path"],
                payload["output_root"],
                payload["started_at"],
                payload["completed_at"],
                int(payload["workers"]),
                int(payload["recursive"]),
                int(payload["unique_samples"]),
                int(payload["success_count"]),
                int(payload["failure_count"]),
                int(payload["partial_count"]),
                int(payload["duplicates"]),
            ),
        )
        connection.execute("DELETE FROM batch_samples WHERE batch_id = ?", (payload["batch_id"],))
        for sample in payload["samples"]:
            connection.execute(
                """
                INSERT INTO batch_samples (
                    batch_id, sha256, filename, status, sample_state, workspace,
                    duplicate_of, error_type, error
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    payload["batch_id"],
                    sample["sha256"],
                    sample["filename"],
                    sample["status"],
                    sample["sample_state"],
                    sample["workspace"],
                    sample["duplicate_of"],
                    sample["error_type"],
                    sample["error"],
                ),
            )
        connection.commit()
