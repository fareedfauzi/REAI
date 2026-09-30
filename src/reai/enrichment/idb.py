from __future__ import annotations

import hashlib
import json
import logging
import subprocess
import shutil
import tempfile
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from reai import __version__
from reai.core.config import EnrichmentConfig, IDAConfig
from reai.core.exceptions import EnrichmentError
from reai.core.sample import Sample
from reai.enrichment.export import export_changes
from reai.enrichment.policy import assign_unique_names, build_function_comment, is_placeholder_name, merge_reai_comment, sanitize_ida_name, unique_ida_name
from reai.enrichment.schemas import ChangeStatus, EnrichmentChange, EnrichmentRun, EnrichmentRunStatus, EnrichmentStats, IDBVerification
from reai.ida.environment import detect_ida_environment, get_clean_ida_environment
from reai.storage.repository import AnalysisRepository

from reai.utils.paths import WorkspacePaths

LOGGER = logging.getLogger("reai.enrichment")


class IDBEnricher:
    def __init__(
        self,
        config: EnrichmentConfig,
        ida_config: IDAConfig,
        repository: AnalysisRepository,
        workspace: WorkspacePaths,
    ) -> None:
        self.config = config
        self.ida_config = ida_config
        self.repository = repository
        self.workspace = workspace

    def run(self, sample: Sample) -> EnrichmentStats | None:
        if not self.config.enabled:
            return None

        original_idb = self.workspace.ida / f"original{self.ida_config.database_extension}"
        analyzed_idb = self.workspace.ida / f"analyzed{self.ida_config.database_extension}"
        temp_idb = self.workspace.ida / f".analyzed_tmp{self.ida_config.database_extension}"
        if not original_idb.exists():

            raise EnrichmentError(f"Original IDB does not exist:\n{original_idb}")

        source_fingerprint = self.repository.get_validated_analysis_fingerprint(sample.sample_id)
        candidates = self._load_candidates(sample.sample_id)
        assign_unique_names(candidates)

        run = EnrichmentRun(
            run_id=_run_id(),
            sample_id=sample.sample_id,
            source_analysis_fingerprint=source_fingerprint,
            enrichment_fingerprint=self._fingerprint(sample.sha256, original_idb, candidates, source_fingerprint),
            mode=self._resolve_mode(),
            ida_version=None,
            reai_version=__version__,
            status=EnrichmentRunStatus.RUNNING,
            original_idb_path=str(original_idb),
            analyzed_idb_path=str(analyzed_idb),
            temp_idb_path=str(temp_idb),
            started_at=_now(),
            total_changes=len(candidates),
        )
        for change in candidates:
            change.change_id = f"{run.run_id}_{change.change_id}"
        self.repository.create_enrichment_run(run)

        original_hash = _sha256_file(original_idb)
        verifications: list[IDBVerification] = []
        try:
            temp_idb.unlink(missing_ok=True)
            shutil.copy2(original_idb, temp_idb)
            if _sidecar_path(original_idb).exists():
                shutil.copy2(_sidecar_path(original_idb), _sidecar_path(temp_idb))
            LOGGER.info("copied original IDB to enrichment temp %s", temp_idb)

            if run.mode == "ida":
                verifications = self._apply_ida_backend(temp_idb, candidates)
            else:
                verifications = self._apply_manifest_backend(sample.sample_id, temp_idb, candidates)

            if _sha256_file(original_idb) != original_hash:
                raise EnrichmentError("Baseline IDB changed during enrichment; refusing to finalize.")

            _atomic_replace(temp_idb, analyzed_idb)
            if _sidecar_path(temp_idb).exists():
                _atomic_replace(_sidecar_path(temp_idb), _sidecar_path(analyzed_idb))


            stats = self._finish_run(sample.sample_id, run, candidates, verifications, None)
            export_changes(self.workspace, self.repository, sample.sample_id, run, stats)
            LOGGER.info("IDB enrichment complete analyzed=%s", analyzed_idb)
            return stats
        except Exception as exc:
            run.status = EnrichmentRunStatus.FAILED
            run.completed_at = _now()
            run.error = str(exc)
            self.repository.persist_idb_changes(sample.sample_id, run.run_id, candidates)
            if verifications:
                self.repository.persist_idb_verification(sample.sample_id, run.run_id, verifications)
            self.repository.update_enrichment_run(run)
            try:
                temp_idb.unlink(missing_ok=True)
                _sidecar_path(temp_idb).unlink(missing_ok=True)
            except OSError:
                pass
            if isinstance(exc, EnrichmentError):
                raise
            raise EnrichmentError(f"IDB enrichment failed: {exc}") from exc

    def _resolve_mode(self) -> str:
        mode = self.config.mode
        if mode == "manifest":
            return mode
        if mode == "ida":
            environment = detect_ida_environment(self.ida_config)
            if not environment.available:
                raise EnrichmentError("IDA enrichment requested, but no compatible IDA executable is available.")
            return mode
        environment = detect_ida_environment(self.ida_config)
        if environment.available:
            return "ida"
        if self.config.allow_manifest_fallback:
            return "manifest"
        raise EnrichmentError("No IDA executable is available and manifest fallback is disabled.")

    def _apply_ida_backend(self, temp_idb: Path, changes: list[EnrichmentChange]) -> list[IDBVerification]:
        environment = detect_ida_environment(self.ida_config)
        if not environment.available or environment.executable is None:
            raise EnrichmentError("IDA enrichment backend requested, but IDA is unavailable.")

        script_path = Path(__file__).parents[1] / "ida" / "scripts" / "enrich_ida.py"
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False, encoding="utf-8") as args_handle:
            args_path = Path(args_handle.name)
            result_path = args_path.with_suffix(".result.json")
            json.dump(
                {
                    "idb_path": str(temp_idb.resolve()),
                    "result_json": str(result_path.resolve()),
                    "comment_marker_begin": self.config.comment_marker_begin,
                    "comment_marker_end": self.config.comment_marker_end,
                    "changes": [change.model_dump(mode="json") for change in changes],
                },
                args_handle,
            )

        command = [
            str(environment.executable),
            "-A",
            f"-S{script_path} {args_path}",
            str(temp_idb.resolve()),
        ]
        try:
            completed = subprocess.run(
                command,
                check=False,
                capture_output=True,
                text=True,
                env=get_clean_ida_environment(),
                timeout=self.ida_config.timeout_seconds,
            )

            if completed.returncode != 0:
                details = (completed.stderr or completed.stdout or "").strip()
                raise EnrichmentError(f"IDA enrichment failed with exit code {completed.returncode}: {details or '<no output>'}")
            if not result_path.exists():
                raise EnrichmentError(f"IDA enrichment did not produce expected output:\n{result_path}")
            result = json.loads(result_path.read_text(encoding="utf-8"))
        finally:
            try:
                args_path.unlink(missing_ok=True)
                result_path.unlink(missing_ok=True)
            except OSError:
                pass

        by_id = {change.change_id: change for change in changes}
        for row in result.get("changes", []):
            change = by_id.get(row.get("change_id"))
            if change is None:
                continue
            change.status = ChangeStatus(row.get("status", ChangeStatus.FAILED.value))
            change.applied = row.get("applied")
            change.reason = row.get("reason")
            change.timestamp = row.get("timestamp") or _now()
        return [
            IDBVerification(
                verification_id=row["verification_id"],
                change_id=row["change_id"],
                expected=row.get("expected"),
                actual=row.get("actual"),
                status=ChangeStatus(row["status"]),
                details=row.get("details"),
                timestamp=row.get("timestamp") or _now(),
            )
            for row in result.get("verification", [])
        ]

    def _load_candidates(self, sample_id: str) -> list[EnrichmentChange]:
        changes: list[EnrichmentChange] = []
        for row in self.repository.get_change_candidate_rows(sample_id):
            evidence = _json_list(row.get("evidence_json"))
            status = ChangeStatus.PENDING if row["eligible_for_idb"] else ChangeStatus.SKIPPED_NOT_ELIGIBLE
            reason = row.get("reason")
            if status == ChangeStatus.SKIPPED_NOT_ELIGIBLE and not reason:
                reason = "Candidate was not eligible for IDB application."
            changes.append(
                EnrichmentChange(
                    change_id=f"idb_{row['candidate_id']}",
                    candidate_id=row["candidate_id"],
                    entity=row["entity"],
                    address=row["address"],
                    operation=row["change_type"],
                    original=row["original"],
                    proposed=row["proposed"],
                    applied=row["proposed"] if row["change_type"] != "rename" else None,
                    confidence=float(row["confidence"]),
                    eligible_for_idb=bool(row["eligible_for_idb"]),
                    status=status,
                    reason=reason,
                    evidence=evidence,
                    timestamp=_now(),
                )
            )
        return changes

    def _apply_manifest_backend(
        self,
        sample_id: str,
        temp_idb: Path,
        changes: list[EnrichmentChange],
    ) -> list[IDBVerification]:
        state = self._load_manifest_state(sample_id, temp_idb)
        for change in changes:
            if change.status != ChangeStatus.PENDING:
                continue
            if change.entity == "function" and change.operation == "rename":
                self._apply_function_rename(state, change)
            elif change.entity == "function" and change.operation == "comment":
                self._apply_function_comment(state, change)
            elif change.entity == "variable" and change.operation == "rename":
                self._apply_variable_rename(state, change)
            elif change.entity in {"structure", "structure_field"}:
                self._apply_structure_change(state, change)
            else:
                self._skip(change, ChangeStatus.SKIPPED_CONFLICT, f"Unsupported IDB change: {change.entity}.{change.operation}")

        verifications = self._verify_changes(state, changes)
        _sidecar_path(temp_idb).write_text(json.dumps(state, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        return verifications

    def _load_manifest_state(self, sample_id: str, temp_idb: Path) -> dict[str, Any]:
        existing = _sidecar_path(temp_idb)
        if existing.exists():
            try:
                return json.loads(existing.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                pass
        functions = {
            row["address"]: {
                "address": row["address"],
                "name": row["name"],
                "comment": "",
                "original_name": row["name"],
            }
            for row in self.repository.list_extracted_functions(sample_id)
        }
        return {
            "schema": "reai-idb-manifest-v1",
            "idb_path": str(temp_idb),
            "functions": functions,
            "structures": {},
            "updated_at": _now(),
        }

    def _apply_function_rename(self, state: dict[str, Any], change: EnrichmentChange) -> None:
        function = self._function_for_change(state, change)
        if function is None:
            return
        current = function["name"]
        if change.original and current != change.original:
            self._skip(change, ChangeStatus.SKIPPED_STATE_MISMATCH, f"Expected original name {change.original!r}, found {current!r}.")
            return
        if not is_placeholder_name(current):
            self._skip(change, ChangeStatus.SKIPPED_CONFLICT, f"Existing name {current!r} is meaningful and will not be overwritten.")
            return
        if not change.applied:
            self._skip(change, ChangeStatus.SKIPPED_CONFLICT, "Proposed name could not be normalized for IDA.")
            return
        used = {
            str(item.get("name") or "")
            for address, item in state.get("functions", {}).items()
            if address != change.address and item.get("name")
        }
        change.applied = unique_ida_name(change.applied, used)
        function["name"] = change.applied
        change.status = ChangeStatus.APPLIED
        change.reason = "Function placeholder renamed with collision-safe IDA name."
        change.timestamp = _now()

    def _apply_function_comment(self, state: dict[str, Any], change: EnrichmentChange) -> None:
        function = self._function_for_change(state, change)
        if function is None:
            return
        function["comment"] = merge_reai_comment(
            function.get("comment") or "",
            build_function_comment(change),
            begin=self.config.comment_marker_begin,
            end=self.config.comment_marker_end,
        )
        change.applied = change.proposed
        change.status = ChangeStatus.APPLIED
        change.reason = "REAI-managed function comment updated."
        change.timestamp = _now()

    def _apply_variable_rename(self, state: dict[str, Any], change: EnrichmentChange) -> None:
        function = self._function_for_change(state, change)
        if function is None:
            return
        if not change.original:
            self._skip(change, ChangeStatus.SKIPPED_STATE_MISMATCH, "Candidate has no original variable name.")
            return
        proposed = sanitize_ida_name(change.proposed)
        if not proposed:
            self._skip(change, ChangeStatus.SKIPPED_CONFLICT, "Proposed variable name could not be normalized.")
            return
        variables = function.setdefault("variables", {})
        if variables.get(change.original) == proposed or change.original == proposed:
            change.applied = proposed
            change.status = ChangeStatus.APPLIED
            change.reason = "Variable already has the proposed name."
            change.timestamp = _now()
            return
        used = {str(name) for name in variables.keys()}
        used.update(str(name) for name in variables.values())
        used.discard(str(change.original))
        proposed = unique_ida_name(proposed, used)
        variables[change.original] = proposed
        change.applied = proposed
        change.status = ChangeStatus.APPLIED
        change.reason = "Variable rename staged in manifest with collision-safe local name."
        change.timestamp = _now()

    def _apply_structure_change(self, state: dict[str, Any], change: EnrichmentChange) -> None:
        if not change.eligible_for_idb:
            self._skip(change, ChangeStatus.SKIPPED_NOT_ELIGIBLE, "Candidate was not eligible for IDB application.")
            return
        structures = state.setdefault("structures", {})
        key = change.address or change.candidate_id or change.change_id
        structures[key] = {
            "entity": change.entity,
            "operation": change.operation,
            "original": change.original,
            "proposed": change.proposed,
        }
        change.applied = change.proposed
        change.status = ChangeStatus.APPLIED
        change.reason = "Structure metadata staged in enrichment manifest."
        change.timestamp = _now()

    def _function_for_change(self, state: dict[str, Any], change: EnrichmentChange) -> dict[str, Any] | None:
        if not change.address:
            self._skip(change, ChangeStatus.SKIPPED_STATE_MISMATCH, "Candidate has no target address.")
            return None
        function = state.get("functions", {}).get(change.address)
        if function is None:
            self._skip(change, ChangeStatus.SKIPPED_STATE_MISMATCH, f"Target function does not exist: {change.address}")
            return None
        return function

    def _skip(self, change: EnrichmentChange, status: ChangeStatus, reason: str) -> None:
        change.status = status
        change.reason = reason
        change.timestamp = _now()

    def _verify_changes(self, state: dict[str, Any], changes: list[EnrichmentChange]) -> list[IDBVerification]:
        verifications: list[IDBVerification] = []
        for change in changes:
            if change.status != ChangeStatus.APPLIED:
                continue
            expected = change.applied or change.proposed
            actual: str | None = None
            details = "Verified."
            if change.entity == "function" and change.operation == "rename" and change.address:
                actual = state["functions"].get(change.address, {}).get("name")
            elif change.entity == "function" and change.operation == "comment" and change.address:
                actual = state["functions"].get(change.address, {}).get("comment")
                expected = self.config.comment_marker_begin
            elif change.entity == "variable" and change.operation == "rename" and change.address:
                actual = state["functions"].get(change.address, {}).get("variables", {}).get(change.original)
            elif change.entity in {"structure", "structure_field"}:
                actual = change.applied
            if actual is None or expected not in actual:
                change.status = ChangeStatus.FAILED_VERIFICATION
                details = "Applied value was not found during verification."
            else:
                change.status = ChangeStatus.VERIFIED
            verifications.append(
                IDBVerification(
                    verification_id=f"verify_{change.change_id}",
                    change_id=change.change_id,
                    expected=expected,
                    actual=actual,
                    status=change.status,
                    details=details,
                    timestamp=_now(),
                )
            )
        return verifications

    def _finish_run(
        self,
        sample_id: str,
        run: EnrichmentRun,
        changes: list[EnrichmentChange],
        verifications: list[IDBVerification],
        error: str | None,
    ) -> EnrichmentStats:
        run.status = EnrichmentRunStatus.FAILED if error else EnrichmentRunStatus.COMPLETED
        run.completed_at = _now()
        run.error = error
        run.total_changes = len(changes)
        run.applied_changes = sum(1 for change in changes if change.status in {ChangeStatus.APPLIED, ChangeStatus.VERIFIED})
        run.verified_changes = sum(1 for change in changes if change.status == ChangeStatus.VERIFIED)
        run.skipped_changes = sum(1 for change in changes if change.status.value.startswith("SKIPPED"))
        run.failed_changes = sum(1 for change in changes if change.status in {ChangeStatus.FAILED, ChangeStatus.FAILED_VERIFICATION})
        self.repository.persist_idb_changes(sample_id, run.run_id, changes)
        self.repository.persist_idb_verification(sample_id, run.run_id, verifications)
        self.repository.update_enrichment_run(run)
        return self.repository.calculate_enrichment_stats(sample_id, run.run_id)

    def _fingerprint(
        self,
        sample_sha256: str,
        original_idb: Path,
        changes: list[EnrichmentChange],
        source_fingerprint: str | None,
    ) -> str:
        payload = {
            "schema": self.config.schema_version,
            "sample_sha256": sample_sha256,
            "original_idb_sha256": _sha256_file(original_idb),
            "source_analysis_fingerprint": source_fingerprint,
            "changes": [
                {
                    "candidate_id": change.candidate_id,
                    "entity": change.entity,
                    "address": change.address,
                    "operation": change.operation,
                    "original": change.original,
                    "proposed": change.proposed,
                    "eligible_for_idb": change.eligible_for_idb,
                }
                for change in changes
            ],
        }
        return hashlib.sha256(json.dumps(payload, sort_keys=True).encode("utf-8")).hexdigest()


def _run_id() -> str:
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
    return f"enrich_{timestamp}_{uuid.uuid4().hex[:8]}"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _json_list(value: str | None) -> list[dict]:
    if not value:
        return []
    try:
        data = json.loads(value)
    except ValueError:
        return []
    return data if isinstance(data, list) else []


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _sidecar_path(path: Path) -> Path:
    return path.with_name(f"{path.name}.reai.json")


def _atomic_replace(source: Path, destination: Path) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    source.replace(destination)
