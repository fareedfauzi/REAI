from __future__ import annotations

import json
import logging
import subprocess
import sys
import tempfile
from pathlib import Path

from pydantic import BaseModel, ConfigDict

from reai import __version__
from reai.core.config import IDAConfig
from reai.core.exceptions import IDAAnalysisError, IDAUnavailableError
from reai.extraction.models import ExtractionBundle
from reai.extraction.stats import calculate_stats
from reai.graph.callgraph import build_call_graph
from reai.ida.environment import IDAEnvironment, detect_ida_environment, get_clean_ida_environment
from reai.utils.paths import WorkspacePaths


LOGGER = logging.getLogger("reai.ida")


class IDAAnalysisResult(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True)

    environment: IDAEnvironment
    idb_path: Path
    bundle: ExtractionBundle


class IDAManager:
    def __init__(self, config: IDAConfig) -> None:
        self.config = config
        self.environment = detect_ida_environment(config)

    def ensure_available(self) -> IDAEnvironment:
        if not self.environment.available:
            configured = self.environment.configured_path or self.config.path
            raise IDAUnavailableError(
                "IDA environment not available.\n\n"
                "Phase 2 requires a compatible IDA/idalib installation.\n\n"
                f"Configured path:\n{configured or '<not configured>'}\n\n"
                "Set [ida].path in the REAI configuration or REAI_IDA_PATH."
            )
        return self.environment

    def analyze(self, sample_path: Path, workspace: WorkspacePaths) -> IDAAnalysisResult:
        environment = self.ensure_available()
        assert environment.executable is not None

        idb_path = workspace.ida / f"original{self.config.database_extension}"
        if idb_path.exists():
            LOGGER.info("preserving existing original IDB %s", idb_path)

        output_json = workspace.analysis / "ida-extraction.json"
        script_path = Path(__file__).with_name("scripts") / "extract_ida.py"
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False, encoding="utf-8") as handle:
            args_path = Path(handle.name)
            json.dump(
                {
                    "sample_path": str(sample_path.resolve()),
                    "workspace_root": str(workspace.root.resolve()),
                    "idb_path": str(idb_path.resolve()),
                    "output_json": str(output_json.resolve()),
                    "reai_version": __version__,
                },
                handle,
            )

        command = [
            str(environment.executable),
            "-A",
            f"-S{script_path} {args_path}",
            str(sample_path.resolve()),
        ]
        LOGGER.info("IDA initialization executable=%s source=%s", environment.executable, environment.discovery_source)
        LOGGER.info("auto-analysis start sample=%s", sample_path)
        try:
            completed = subprocess.run(
                command,
                check=False,
                capture_output=True,
                text=True,
                env=get_clean_ida_environment(),
                timeout=self.config.timeout_seconds,
            )
        except subprocess.TimeoutExpired as exc:

            raise IDAAnalysisError(f"IDA analysis timed out after {self.config.timeout_seconds}s.") from exc
        finally:
            try:
                args_path.unlink(missing_ok=True)
            except OSError:
                pass

        if completed.returncode != 0:
            details = (completed.stderr or completed.stdout or "").strip()
            raise IDAAnalysisError(
                "IDA analysis failed.\n\n"
                f"Executable:\n{environment.executable}\n\n"
                f"Exit code:\n{completed.returncode}\n\n"
                f"Details:\n{details or '<no output>'}"
            )

        if not output_json.exists():
            raise IDAAnalysisError(f"IDA extraction did not produce expected output:\n{output_json}")

        try:
            data = json.loads(output_json.read_text(encoding="utf-8"))
            bundle = ExtractionBundle.model_validate(data)
            edges = bundle.callgraph.edges
            bundle.callgraph = build_call_graph(bundle.functions, edges)
            bundle.stats = calculate_stats(bundle)
        except (OSError, ValueError) as exc:
            raise IDAAnalysisError(f"Unable to read IDA extraction output:\n{output_json}") from exc

        LOGGER.info("auto-analysis complete")
        LOGGER.info("IDB path %s", idb_path)
        LOGGER.info(
            "extractor counts functions=%s strings=%s imports=%s exports=%s edges=%s",
            bundle.stats.total_functions,
            bundle.stats.strings,
            bundle.stats.imports,
            bundle.stats.exports,
            bundle.stats.call_edges,
        )
        self._cleanup_sample_dir_idb(sample_path, idb_path)
        return IDAAnalysisResult(environment=environment, idb_path=idb_path, bundle=bundle)

    def _cleanup_sample_dir_idb(self, sample_path: Path, workspace_idb_path: Path) -> None:
        """Removes side-effect IDB and temporary database files IDA created in the sample's directory."""
        if sample_path.suffix.lower() in {".i64", ".idb"}:
            return

        if not workspace_idb_path.exists() or workspace_idb_path.stat().st_size == 0:
            return

        sample_resolved = sample_path.resolve()
        workspace_idb_resolved = workspace_idb_path.resolve()

        candidates: list[Path] = [
            sample_path.parent / f"{sample_path.name}.i64",
            sample_path.parent / f"{sample_path.stem}.i64",
            sample_path.with_suffix(".i64"),
            sample_path.parent / f"{sample_path.name}.idb",
            sample_path.parent / f"{sample_path.stem}.idb",
            sample_path.with_suffix(".idb"),
        ]

        for ext in (".id0", ".id1", ".id2", ".nam", ".til"):
            candidates.append(sample_path.parent / f"{sample_path.name}{ext}")
            candidates.append(sample_path.parent / f"{sample_path.stem}{ext}")

        for candidate in set(candidates):
            try:
                candidate_resolved = candidate.resolve()
            except (OSError, ValueError):
                continue

            if candidate_resolved in {sample_resolved, workspace_idb_resolved}:
                continue

            if candidate.is_file():
                try:
                    candidate.unlink()
                    LOGGER.info("Cleaned up side-effect IDA file: %s", candidate)
                except OSError as exc:
                    LOGGER.warning("Could not remove side-effect IDA file %s: %s", candidate, exc)

