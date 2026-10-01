from __future__ import annotations

import json
import logging
import shutil
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Callable

from pydantic import BaseModel, ConfigDict

from reai.core.config import AIConfig, EnrichmentConfig, IDAConfig
from reai.core.exceptions import EnrichmentError, IDAUnavailableError
from reai.ida.environment import IDAEnvironment, detect_ida_environment, get_clean_ida_environment


LOGGER = logging.getLogger("reai.ida.enrichidb")


class NativeEnrichResult(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True)

    environment: IDAEnvironment
    output_idb: Path
    function_renames: int = 0
    variable_renames: int = 0
    comments: int = 0
    failed: int = 0


class IDANativeEnricher:
    def __init__(
        self,
        ida_config: IDAConfig,
        ai_config: AIConfig,
        enrichment_config: EnrichmentConfig,
        *,
        progress_callback: Callable[[str], None] | None = None,
        function_rename_only: bool = False,
    ) -> None:
        self.ida_config = ida_config
        self.ai_config = ai_config
        self.enrichment_config = enrichment_config
        self.progress_callback = progress_callback
        self.function_rename_only = function_rename_only
        self.environment = detect_ida_environment(ida_config)

    def ensure_available(self) -> IDAEnvironment:
        if not self.environment.available:
            configured = self.environment.configured_path or self.ida_config.path
            raise IDAUnavailableError(
                "IDA environment not available.\n\n"
                "--enrichidb requires a compatible IDA/Hex-Rays installation.\n\n"
                f"Configured path:\n{configured or '<not configured>'}\n\n"
                "Set [ida].path in the REAI configuration or REAI_IDA_PATH."
            )
        return self.environment

    def run(self, sample_path: Path) -> NativeEnrichResult:
        environment = self.ensure_available()
        assert environment.executable is not None

        output_idb = sample_path.parent / f"{sample_path.name}.i64"
        script_path = Path(__file__).with_name("scripts") / "enrichidb_native.py"
        status_path = Path(tempfile.gettempdir()) / f"reai-enrichidb-status-{time.time_ns()}.jsonl"
        result_path = Path(tempfile.gettempdir()) / f"reai-enrichidb-result-{time.time_ns()}.json"

        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False, encoding="utf-8") as handle:
            args_path = Path(handle.name)
            json.dump(
                {
                    "sample_path": str(sample_path.resolve()),
                    "output_idb": str(output_idb.resolve()),
                    "status_path": str(status_path),
                    "result_path": str(result_path),
                    "ai": {
                        "provider": self.ai_config.provider,
                        "model": self.ai_config.model,
                        "api_key": self.ai_config.api_key,
                        "base_url": self.ai_config.base_url,
                        "timeout_seconds": self.ai_config.timeout_seconds,
                        "max_retries": self.ai_config.max_retries,
                        "rate_limit_cooldown_seconds": max(180, int(self.ai_config.rate_limit_cooldown_seconds or 180)),
                    },
                    "batch_size": 5,
                    "max_workers": 2,
                    "function_rename_only": self.function_rename_only,
                    "comment_marker_begin": self.enrichment_config.comment_marker_begin,
                    "comment_marker_end": self.enrichment_config.comment_marker_end,
                },
                handle,
            )

        command = [
            str(environment.executable),
            "-A",
            f"-S{script_path} {args_path}",
            str(sample_path.resolve()),
        ]
        try:
            process = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                env=get_clean_ida_environment(),
            )
            try:
                stdout, stderr, returncode = self._communicate_with_status(
                    process,
                    timeout_seconds=self.ida_config.timeout_seconds,
                    status_path=status_path,
                    sample_name=sample_path.name,
                )
            except subprocess.TimeoutExpired as exc:
                process.kill()
                process.wait()
                raise EnrichmentError(f"--enrichidb timed out after {self.ida_config.timeout_seconds}s.") from exc
            except (KeyboardInterrupt, SystemExit):
                process.kill()
                process.wait()
                raise
        finally:
            args_path.unlink(missing_ok=True)
            status_path.unlink(missing_ok=True)

        if returncode != 0:
            details = (stderr or stdout or "").strip()
            failure_log = Path(tempfile.gettempdir()) / "reai_enrichidb_native_failure.txt"
            if failure_log.exists():
                try:
                    details = f"{details}\n\nIDA Script Traceback:\n{failure_log.read_text(encoding='utf-8')}".strip()
                    failure_log.unlink()
                except Exception:
                    pass
            raise EnrichmentError(
                "IDA-native --enrichidb failed.\n\n"
                f"Executable:\n{environment.executable}\n\n"
                f"Exit code:\n{returncode}\n\n"
                f"Details:\n{details or '<no output>'}"
            )

        output_idb = _coerce_ida_output_to_requested_path(output_idb)
        if not output_idb.exists():
            raise EnrichmentError(f"IDA-native --enrichidb did not create expected IDB:\n{output_idb}")

        payload = {}
        if result_path.exists():
            try:
                payload = json.loads(result_path.read_text(encoding="utf-8"))
            finally:
                result_path.unlink(missing_ok=True)

        payload_output = payload.get("output_idb")
        if payload_output and not output_idb.exists():
            payload_path = Path(payload_output)
            if payload_path.is_file():
                shutil.copy2(payload_path, output_idb)
        output_idb = _coerce_ida_output_to_requested_path(output_idb)
        _cleanup_alternate_database_files(sample_path, output_idb)

        return NativeEnrichResult(
            environment=environment,
            output_idb=output_idb,
            function_renames=int(payload.get("function_renames") or 0),
            variable_renames=int(payload.get("variable_renames") or 0),
            comments=int(payload.get("comments") or 0),
            failed=int(payload.get("failed") or 0),
        )

    def _communicate_with_status(
        self,
        process: subprocess.Popen[str],
        *,
        timeout_seconds: int,
        status_path: Path,
        sample_name: str,
    ) -> tuple[str, str, int]:
        deadline = time.monotonic() + timeout_seconds
        offset = 0
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise subprocess.TimeoutExpired(process.args, timeout_seconds)
            try:
                stdout, stderr = process.communicate(timeout=min(0.5, remaining))
                offset = self._emit_status(status_path, offset, sample_name)
                return stdout, stderr, process.returncode or 0
            except subprocess.TimeoutExpired:
                offset = self._emit_status(status_path, offset, sample_name)

    def _emit_status(self, status_path: Path, offset: int, sample_name: str) -> int:
        if self.progress_callback is None or not status_path.exists():
            return offset
        try:
            with status_path.open("r", encoding="utf-8", errors="replace") as handle:
                handle.seek(offset)
                lines = handle.readlines()
                offset = handle.tell()
        except OSError:
            return offset
        for line in lines:
            try:
                payload = json.loads(line)
            except ValueError:
                continue
            phase = int(payload.get("phase") or 3)
            message = str(payload.get("message") or "").strip()
            if message:
                self.progress_callback(f"{sample_name}: Phase {phase}: {message}")
        return offset


def _coerce_ida_output_to_requested_path(requested: Path) -> Path:
    if requested.exists():
        return requested
    alternatives = [
        requested.with_suffix(".i64"),
        requested.with_suffix(".idb"),
        requested.parent / f"{requested.name}.i64",
        requested.parent / f"{requested.stem}.i64",
    ]
    for alternative in alternatives:
        try:
            if alternative.resolve() == requested.resolve():
                continue
            if alternative.is_file():
                shutil.copy2(alternative, requested)
                try:
                    alternative.unlink()
                except OSError:
                    pass
                return requested
        except OSError:
            continue
    return requested


def _cleanup_alternate_database_files(sample_path: Path, final_output: Path) -> None:
    keep = {sample_path.resolve(), final_output.resolve()}
    candidates = {
        sample_path.with_suffix(".idb"),
        sample_path.parent / f"{sample_path.name}.idb",
        final_output.with_suffix(".idb"),
        final_output.parent / f"{final_output.stem}.idb",
        final_output.parent / f"{final_output.name}.idb",
    }
    for candidate in candidates:
        try:
            if candidate.resolve() not in keep and candidate.is_file():
                candidate.unlink()
        except OSError:
            continue
