from __future__ import annotations

import tomllib
import os
from pathlib import Path
from typing import Any

from pydantic import AliasChoices, BaseModel, ConfigDict, Field, field_validator

from reai.core.exceptions import ConfigError


class ApplicationConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", arbitrary_types_allowed=True)

    output_dir: Path = Path("./reai-output")
    workers: int = Field(default=1, ge=1)
    recursive: bool = False
    verbose: bool = False
    reliability: "ReliabilityConfig" = Field(default_factory=lambda: ReliabilityConfig())
    ida: "IDAConfig" = Field(default_factory=lambda: IDAConfig())
    ai: "AIConfig" = Field(default_factory=lambda: AIConfig())
    mcp: "MCPConfig" = Field(default_factory=lambda: MCPConfig())
    analysis: "AnalysisConfig" = Field(default_factory=lambda: AnalysisConfig())
    enrichment: "EnrichmentConfig" = Field(default_factory=lambda: EnrichmentConfig())
    report: "ReportConfig" = Field(default_factory=lambda: ReportConfig())

    @field_validator("output_dir", mode="before")
    @classmethod
    def _coerce_output_dir(cls, value: Any) -> Path:
        return Path(value)


class IDAConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", arbitrary_types_allowed=True)

    path: Path | None = None
    timeout_seconds: int = Field(default=3600, ge=1)
    max_concurrent_instances: int = Field(default=1, ge=1)
    database_extension: str = ".i64"

    @field_validator("path", mode="before")
    @classmethod
    def _coerce_path(cls, value: Any) -> Path | None:
        if value in (None, ""):
            return None
        return Path(value)

    @field_validator("database_extension")
    @classmethod
    def _validate_database_extension(cls, value: str) -> str:
        return value if value.startswith(".") else f".{value}"


class AIConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", arbitrary_types_allowed=True, populate_by_name=True)

    provider: str = "disabled"
    model: str | None = None
    api_key: str | None = Field(default=None, validation_alias=AliasChoices("api_key", "api-key"))
    max_functions: int | None = Field(default=None, ge=1)
    max_concurrent_requests: int = Field(default=1, ge=1)
    max_retries: int = Field(default=2, ge=0)
    timeout_seconds: int = Field(default=120, ge=1)
    prompt_version: str = "phase3-function-analysis-v1"
    schema_version: str = "phase3-function-analysis-v1"
    confidence_policy_version: str = "phase3-confidence-v1"
    context_builder_version: str = "phase3-context-v1"


class MCPConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", arbitrary_types_allowed=True)

    enabled: bool = False
    provider: str = "disabled"
    max_functions: int | None = Field(default=None, ge=1)
    max_rounds_per_function: int = Field(default=5, ge=1)
    max_tool_calls_per_function: int = Field(default=20, ge=1)
    max_total_tool_calls: int | None = Field(default=None, ge=1)
    max_related_functions: int = Field(default=20, ge=0)
    max_depth: int = Field(default=4, ge=0)
    timeout_seconds: int = Field(default=60, ge=1)
    allowlist: list[str] = Field(
        default_factory=lambda: [
            "decompile",
            "disassemble",
            "xrefs",
            "callers",
            "callees",
            "cfg",
            "memory",
            "data",
            "types",
            "function",
            "search",
        ]
    )


class PropagationConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", arbitrary_types_allowed=True)

    max_passes: int = Field(default=3, ge=1)
    minimum_context_change: int = Field(default=1, ge=0)
    minimum_confidence_delta: float = Field(default=0.05, ge=0.0, le=1.0)


class ValidationConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", arbitrary_types_allowed=True)

    rename_confidence_threshold: float = Field(default=0.65, ge=0.0, le=1.0)
    comment_confidence_threshold: float = Field(default=0.50, ge=0.0, le=1.0)
    variable_confidence_threshold: float = Field(default=0.65, ge=0.0, le=1.0)
    type_confidence_threshold: float = Field(default=0.85, ge=0.0, le=1.0)


class AnalysisConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", arbitrary_types_allowed=True)

    enabled: bool = True
    taxonomy_version: str = "phase5-subsystem-taxonomy-v1"
    schema_version: str = "phase5-validated-analysis-v1"
    propagation: PropagationConfig = Field(default_factory=lambda: PropagationConfig())
    validation: ValidationConfig = Field(default_factory=lambda: ValidationConfig())


class EnrichmentConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", arbitrary_types_allowed=True)

    enabled: bool = True
    mode: str = "auto"
    schema_version: str = "phase6-idb-enrichment-v1"
    comment_marker_begin: str = "[REAI ANALYSIS BEGIN]"
    comment_marker_end: str = "[REAI ANALYSIS END]"
    allow_manifest_fallback: bool = True

    @field_validator("mode")
    @classmethod
    def _validate_mode(cls, value: str) -> str:
        lowered = value.lower()
        if lowered not in {"auto", "ida", "manifest"}:
            raise ValueError("enrichment.mode must be one of: auto, ida, manifest")
        return lowered


class ReportConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", arbitrary_types_allowed=True)

    enabled: bool = True
    schema_version: str = "phase7-report-v1"
    prompt_version: str = "phase7-deterministic-narrative-v1"
    defang_iocs: bool = True
    formats: list[str] = Field(default_factory=lambda: ["markdown", "html", "pdf"])
    max_important_functions: int = Field(default=25, ge=1)
    max_evidence_items: int = Field(default=4, ge=1)
    attack_version: str = "reai-built-in-phase7-v1"

    @field_validator("formats")
    @classmethod
    def _validate_formats(cls, value: list[str]) -> list[str]:
        allowed = {"markdown", "html", "pdf"}
        normalized = []
        for item in value:
            lowered = item.lower()
            if lowered not in allowed:
                raise ValueError("report.formats entries must be one of: markdown, html, pdf")
            if lowered not in normalized:
                normalized.append(lowered)
        if not normalized:
            raise ValueError("report.formats must contain at least one output format")
        return normalized


class ReliabilityConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", arbitrary_types_allowed=True)

    sample_retry_limit: int = Field(default=0, ge=0)
    worker_restart_limit: int = Field(default=0, ge=0)
    lock_stale_seconds: int = Field(default=3600, ge=1)
    retry_initial_delay_seconds: float = Field(default=1.0, ge=0.0)
    retry_max_delay_seconds: float = Field(default=8.0, ge=0.0)


def default_config() -> ApplicationConfig:
    return ApplicationConfig()


def load_config_file(path: Path) -> ApplicationConfig:
    if not path.exists():
        raise ConfigError(f"Configuration file does not exist:\n{path}")
    if not path.is_file():
        raise ConfigError(f"Configuration path is not a file:\n{path}")

    try:
        with path.open("rb") as handle:
            raw = tomllib.load(handle)
    except tomllib.TOMLDecodeError as exc:
        raise ConfigError(f"Invalid TOML configuration:\n{path}\n{exc}") from exc
    except OSError as exc:
        raise ConfigError(f"Unable to read configuration file:\n{path}\n{exc}") from exc

    allowed_top_level = {"output_dir", "workers", "recursive", "verbose", "batch", "ida", "ai", "mcp", "analysis", "enrichment", "report", "reliability"}
    unknown = sorted(set(raw) - allowed_top_level)
    if unknown:
        raise ConfigError(f"Unknown configuration key(s): {', '.join(unknown)}")

    batch = raw.pop("batch", {})
    if not isinstance(batch, dict):
        raise ConfigError("Configuration section [batch] must be a table.")
    allowed_batch = {"workers", "recursive"}
    unknown_batch = sorted(set(batch) - allowed_batch)
    if unknown_batch:
        raise ConfigError(f"Unknown [batch] key(s): {', '.join(unknown_batch)}")

    ida = raw.pop("ida", {})
    if not isinstance(ida, dict):
        raise ConfigError("Configuration section [ida] must be a table.")
    allowed_ida = {"path", "timeout_seconds", "max_concurrent_instances", "database_extension"}
    unknown_ida = sorted(set(ida) - allowed_ida)
    if unknown_ida:
        raise ConfigError(f"Unknown [ida] key(s): {', '.join(unknown_ida)}")

    ai = raw.pop("ai", {})
    if not isinstance(ai, dict):
        raise ConfigError("Configuration section [ai] must be a table.")
    allowed_ai = {
        "provider",
        "model",
        "api_key",
        "api-key",
        "max_functions",
        "max_concurrent_requests",
        "max_retries",
        "timeout_seconds",
        "prompt_version",
        "schema_version",
        "confidence_policy_version",
        "context_builder_version",
    }
    unknown_ai = sorted(set(ai) - allowed_ai)
    if unknown_ai:
        raise ConfigError(f"Unknown [ai] key(s): {', '.join(unknown_ai)}")

    mcp = raw.pop("mcp", {})
    if not isinstance(mcp, dict):
        raise ConfigError("Configuration section [mcp] must be a table.")
    allowed_mcp = {
        "enabled",
        "provider",
        "max_functions",
        "max_rounds_per_function",
        "max_tool_calls_per_function",
        "max_total_tool_calls",
        "max_related_functions",
        "max_depth",
        "timeout_seconds",
        "allowlist",
    }
    unknown_mcp = sorted(set(mcp) - allowed_mcp)
    if unknown_mcp:
        raise ConfigError(f"Unknown [mcp] key(s): {', '.join(unknown_mcp)}")

    analysis = raw.pop("analysis", {})
    if not isinstance(analysis, dict):
        raise ConfigError("Configuration section [analysis] must be a table.")
    allowed_analysis = {"enabled", "taxonomy_version", "schema_version", "propagation", "validation"}
    unknown_analysis = sorted(set(analysis) - allowed_analysis)
    if unknown_analysis:
        raise ConfigError(f"Unknown [analysis] key(s): {', '.join(unknown_analysis)}")
    propagation = analysis.get("propagation", {})
    if not isinstance(propagation, dict):
        raise ConfigError("Configuration section [analysis.propagation] must be a table.")
    unknown_propagation = sorted(set(propagation) - {"max_passes", "minimum_context_change", "minimum_confidence_delta"})
    if unknown_propagation:
        raise ConfigError(f"Unknown [analysis.propagation] key(s): {', '.join(unknown_propagation)}")
    validation = analysis.get("validation", {})
    if not isinstance(validation, dict):
        raise ConfigError("Configuration section [analysis.validation] must be a table.")
    unknown_validation = sorted(
        set(validation)
        - {
            "rename_confidence_threshold",
            "comment_confidence_threshold",
            "variable_confidence_threshold",
            "type_confidence_threshold",
        }
    )
    if unknown_validation:
        raise ConfigError(f"Unknown [analysis.validation] key(s): {', '.join(unknown_validation)}")

    enrichment = raw.pop("enrichment", {})
    if not isinstance(enrichment, dict):
        raise ConfigError("Configuration section [enrichment] must be a table.")
    allowed_enrichment = {
        "enabled",
        "mode",
        "schema_version",
        "comment_marker_begin",
        "comment_marker_end",
        "allow_manifest_fallback",
    }
    unknown_enrichment = sorted(set(enrichment) - allowed_enrichment)
    if unknown_enrichment:
        raise ConfigError(f"Unknown [enrichment] key(s): {', '.join(unknown_enrichment)}")

    report = raw.pop("report", {})
    if not isinstance(report, dict):
        raise ConfigError("Configuration section [report] must be a table.")
    allowed_report = {
        "enabled",
        "schema_version",
        "prompt_version",
        "defang_iocs",
        "formats",
        "max_important_functions",
        "max_evidence_items",
        "attack_version",
    }
    unknown_report = sorted(set(report) - allowed_report)
    if unknown_report:
        raise ConfigError(f"Unknown [report] key(s): {', '.join(unknown_report)}")

    reliability = raw.pop("reliability", {})
    if not isinstance(reliability, dict):
        raise ConfigError("Configuration section [reliability] must be a table.")
    allowed_reliability = {
        "sample_retry_limit",
        "worker_restart_limit",
        "lock_stale_seconds",
        "retry_initial_delay_seconds",
        "retry_max_delay_seconds",
    }
    unknown_reliability = sorted(set(reliability) - allowed_reliability)
    if unknown_reliability:
        raise ConfigError(f"Unknown [reliability] key(s): {', '.join(unknown_reliability)}")

    merged = {
        **raw,
        **batch,
        "reliability": reliability,
        "ida": ida,
        "ai": ai,
        "mcp": mcp,
        "analysis": analysis,
        "enrichment": enrichment,
        "report": report,
    }
    try:
        return ApplicationConfig(**merged)
    except ValueError as exc:
        raise ConfigError(str(exc)) from exc


def discover_config_path() -> Path | None:
    # 1. Environment variable REAI_CONFIG
    env_config = os.environ.get("REAI_CONFIG")
    if env_config:
        path = Path(env_config).expanduser()
        if path.is_file():
            return path

    # 2. Current working directory and parent directories
    try:
        current = Path.cwd().resolve()
        for parent in [current, *current.parents]:
            candidate = parent / "reai.toml"
            if candidate.is_file():
                return candidate
    except Exception:
        pass

    # 3. User configuration directory (~/.reai/reai.toml or %APPDATA%/reai/reai.toml)
    try:
        user_candidates = [
            Path.home() / ".reai" / "reai.toml",
            Path.home() / ".config" / "reai" / "reai.toml",
        ]
        appdata = os.environ.get("APPDATA")
        if appdata:
            user_candidates.append(Path(appdata) / "reai" / "reai.toml")
        for candidate in user_candidates:
            if candidate.is_file():
                return candidate
    except Exception:
        pass

    # 4. Source / Repository root (for editable / development installations)
    try:
        repo_candidate = Path(__file__).resolve().parents[3] / "reai.toml"
        if repo_candidate.is_file():
            return repo_candidate
    except Exception:
        pass

    return None


def build_config(
    *,
    config_path: Path | None = None,
    auto_discover: bool = True,
    output_dir: Path | None = None,
    workers: int | None = None,
    recursive: bool | None = None,
    verbose: bool = False,
    max_functions: int | None = None,
) -> ApplicationConfig:
    values = default_config().model_dump()

    target_config = config_path
    if target_config is None and auto_discover:
        target_config = discover_config_path()

    if target_config is not None:
        values.update(load_config_file(target_config).model_dump())


    if output_dir is not None:
        values["output_dir"] = output_dir
    if workers is not None:
        values["workers"] = workers
    if recursive is not None:
        values["recursive"] = recursive
    if verbose:
        values["verbose"] = True
    if max_functions is not None:
        values.setdefault("ai", {})
        values["ai"]["max_functions"] = max_functions

    if values.get("ida") is None:
        values["ida"] = {}
    if values.get("reliability") is None:
        values["reliability"] = {}
    if values.get("ai") is None:
        values["ai"] = {}
    if values.get("mcp") is None:
        values["mcp"] = {}
    if values.get("analysis") is None:
        values["analysis"] = {}
    if values.get("enrichment") is None:
        values["enrichment"] = {}
    if values.get("report") is None:
        values["report"] = {}
    env_ida_path = os.environ.get("REAI_IDA_PATH") or os.environ.get("IDA_PATH")
    if env_ida_path and not values["ida"].get("path"):
        values["ida"]["path"] = env_ida_path

    try:
        return ApplicationConfig(**values)
    except ValueError as exc:
        raise ConfigError(str(exc)) from exc
