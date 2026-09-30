from __future__ import annotations

import json
import shutil
import subprocess
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Protocol
from uuid import uuid4

from reai.core.config import MCPConfig
from reai.core.exceptions import ReaiError
from reai.core.sample import Sample
from reai.mcp.schemas import MCPCapability, MCPSessionMetadata, MCPToolResult, READ_ONLY_CAPABILITIES
from reai.utils.paths import WorkspacePaths


class MCPError(ReaiError):
    """Raised when a read-only MCP operation cannot be completed."""


class IDAInvestigationClient(Protocol):
    def connect(self) -> None:
        ...

    def close(self) -> None:
        ...

    def discover_capabilities(self) -> set[MCPCapability]:
        ...

    def execute(self, capability: MCPCapability, target: str, parameters: dict) -> MCPToolResult:
        ...

    def session_metadata(self) -> MCPSessionMetadata:
        ...


def create_mcp_client(
    config: MCPConfig,
    *,
    workspace: WorkspacePaths | None = None,
    sample: Sample | None = None,
) -> IDAInvestigationClient | None:
    if not config.enabled:
        return None
    provider = config.provider.lower()
    if provider == "disabled":
        return None
    if provider in {"simulation", "simulator", "simulated", "mock"}:
        if not config.allow_simulation_provider:
            raise MCPError(
                "The simulation/mock MCP provider is disabled for production analysis. "
                "Set [mcp].allow_simulation_provider = true only for tests or local development."
            )
        return SimulationInvestigationClient()
    if provider in {"reai", "reai-mcp", "internal"}:
        if sample is None:
            raise MCPError("The REAI MCP provider requires the current sample identity.")
        if workspace is None:
            raise MCPError("The REAI MCP provider requires the current sample workspace.")
        return ReaiMCPClient(config, sample=sample, workspace=workspace)
    if provider in {"hexrays", "blacktop"}:
        raise MCPError(f"MCP provider '{provider}' is reserved but is not implemented in this REAI build.")
    raise MCPError(f"Unsupported MCP provider: {config.provider}")


class ReadOnlyMCPSession:
    def __init__(self, client: IDAInvestigationClient, *, allowlist: list[str], timeout_seconds: int) -> None:
        self.client = client
        self.allowlist = {name.lower() for name in allowlist}
        self.timeout_seconds = timeout_seconds
        self.capabilities: set[MCPCapability] = set()
        self.connected = False

    def connect(self) -> None:
        self.client.connect()
        discovered = self.client.discover_capabilities()
        self.capabilities = {
            capability
            for capability in discovered
            if capability.value in READ_ONLY_CAPABILITIES and capability.value in self.allowlist
        }
        self.connected = True

    def close(self) -> None:
        self.client.close()
        self.connected = False

    def execute(self, capability: MCPCapability, target: str, parameters: dict | None = None) -> MCPToolResult:
        if not self.connected:
            raise MCPError("MCP session is not connected.")
        if capability.value not in READ_ONLY_CAPABILITIES or capability.value not in self.allowlist:
            raise MCPError(f"MCP capability is not allowed in read-only investigation: {capability.value}")
        if capability not in self.capabilities:
            return MCPToolResult(
                capability=capability,
                target=target,
                success=False,
                error=f"Capability unavailable: {capability.value}",
            )
        return self.client.execute(capability, target, parameters or {})

    def session_metadata(self) -> MCPSessionMetadata:
        return self.client.session_metadata()


class ReaiMCPClient:
    """MCP client for REAI's owned read-only artifact-backed MCP server."""

    def __init__(self, config: MCPConfig, *, sample: Sample, workspace: WorkspacePaths | None = None) -> None:
        self.config = config
        self.sample = sample
        self.workspace = workspace
        self.process: subprocess.Popen[str] | None = None
        self.request_id = 0
        self.tools: dict[str, dict[str, Any]] = {}
        self.tool_by_capability: dict[MCPCapability, str] = {}
        self.database_id = sample.sha256[:16]
        self.connected = False
        self._metadata = MCPSessionMetadata(
            session_id=str(uuid4()),
            backend="reai-mcp",
            provider="reai",
            transport=config.transport,
            connection_mode=config.database_mode,
            database=self.database_id,
            read_only=True,
        )

    def connect(self) -> None:
        if self.config.transport != "http":
            raise MCPError("The owned REAI MCP provider currently supports HTTP transport only.")
        command = self.config.command or "reai-mcp"
        resolved_command = shutil.which(command)
        if resolved_command is None and command == "reai-mcp":
            resolved_command = shutil.which("python")
            command_args_prefix = ["-m", "reai.mcp.server"]
        else:
            command_args_prefix = []
        if resolved_command is None:
            raise MCPError(
                f"MCP command not found on PATH: {command}. Install REAI in editable mode or set [mcp].command."
            )
        args = self._startup_args()
        try:
            self.process = subprocess.Popen(
                [resolved_command, *command_args_prefix, *args],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                encoding="utf-8",
            )
        except OSError as exc:
            raise MCPError(f"Unable to start REAI MCP server: {exc}") from exc
        try:
            if self.config.transport == "http":
                self._wait_for_http_ready()
            self._initialize_protocol()
            self._discover_tools()
            self._open_database()
            self._verify_sample_identity()
            self.connected = True
        except Exception:
            self.close()
            raise

    def close(self) -> None:
        if self.process and self.process.poll() is None:
            try:
                if MCPCapability.DATABASE in self.tool_by_capability:
                    self._call_tool(self.tool_by_capability[MCPCapability.DATABASE], {"database": self.database_id, "operation": "close"})
            except Exception:
                pass
            self.process.terminate()
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.process.kill()
        self.connected = False

    def discover_capabilities(self) -> set[MCPCapability]:
        return set(self.tool_by_capability)

    def execute(self, capability: MCPCapability, target: str, parameters: dict) -> MCPToolResult:
        if capability not in self.tool_by_capability:
            return MCPToolResult(capability=capability, target=target, success=False, error=f"Capability unavailable: {capability.value}")
        tool_name = self.tool_by_capability[capability]
        payload = _tool_arguments(capability, target, parameters, self.database_id)
        start = time.perf_counter()
        try:
            result = self._call_tool(tool_name, payload)
        except MCPError as exc:
            return MCPToolResult(capability=capability, target=target, success=False, error=str(exc))
        observations = _result_to_observations(capability, result)
        raw_payload = json.dumps(result, sort_keys=True, default=str)
        return MCPToolResult(
            capability=capability,
            target=target,
            success=True,
            observations=observations,
            raw=result,
            duration_ms=int((time.perf_counter() - start) * 1000),
            result_size=len(raw_payload),
        )

    def session_metadata(self) -> MCPSessionMetadata:
        return self._metadata.model_copy(deep=True)

    def _initialize_protocol(self) -> None:
        response = self._request(
            "initialize",
            {
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": {"name": "reai", "version": "0.1.0"},
            },
        )
        result = response.get("result") or {}
        server_info = result.get("serverInfo") or {}
        self._metadata.backend_version = server_info.get("version")
        self._notification("notifications/initialized", {})

    def _discover_tools(self) -> None:
        response = self._request("tools/list", {})
        tools = (response.get("result") or {}).get("tools") or []
        self.tools = {tool["name"]: tool for tool in tools if isinstance(tool, dict) and tool.get("name")}
        self.tool_by_capability = normalize_tool_catalog(self.tools.keys())
        self._metadata.available_tools = sorted(self.tools)
        self._metadata.normalized_capabilities = sorted(capability.value for capability in self.tool_by_capability)
        blocked = [name for name in self.tools if _looks_mutating_tool(name)]
        if blocked and not self.config.read_only:
            raise MCPError(f"Refusing mutable MCP mode; mutating tools discovered: {', '.join(blocked[:5])}")

    def _open_database(self) -> None:
        tool = _pick_tool(self.tools.keys(), ("idb_open", "open_database", "database_open"))
        if tool is None:
            if str(self.sample.source_path) in self._startup_args():
                return
            if self.config.require_database_open:
                raise MCPError("MCP backend does not expose idb_open/open_database; cannot bind to the sample database.")
            return
        result = self._call_tool(
            tool,
            {
                "path": str(self.sample.source_path),
                "preferred_session_id": self.database_id,
                "mode": self.config.database_mode,
                "read_only": True,
            },
        )
        text = json.dumps(result, sort_keys=True, default=str)
        if self.database_id not in text:
            self.database_id = _extract_database_id(result) or self.database_id
        self._metadata.database = self.database_id

    def _verify_sample_identity(self) -> None:
        metadata_tool = self.tool_by_capability.get(MCPCapability.METADATA)
        if metadata_tool is None:
            if self.config.require_sample_identity:
                raise MCPError("MCP backend cannot verify sample identity because no metadata capability is available.")
            return
        try:
            result = self._call_tool(metadata_tool, {"database": self.database_id})
        except MCPError:
            if self.config.require_sample_identity:
                raise
            return
        text = json.dumps(result, sort_keys=True, default=str).lower()
        self._metadata.ida_version = _find_json_value(result, "ida_version") or _find_json_value(result, "version")
        if self.sample.sha256.lower() in text or str(self.sample.source_path).lower() in text:
            self._metadata.sample_identity_verified = True
        elif self.config.require_sample_identity:
            raise MCPError("MCP session opened a database whose identity did not match the current sample.")

    def _call_tool(self, name: str, arguments: dict[str, Any]) -> Any:
        response = self._request("tools/call", {"name": name, "arguments": arguments})
        if "error" in response:
            raise MCPError(str(response["error"]))
        return response.get("result")

    def _request(self, method: str, params: dict[str, Any]) -> dict[str, Any]:
        self.request_id += 1
        message = {"jsonrpc": "2.0", "id": self.request_id, "method": method, "params": params}
        if self.config.transport == "http":
            return self._http_request(message)
        self._write_message(message)
        deadline = time.monotonic() + self.config.timeout_seconds
        while time.monotonic() < deadline:
            response = self._read_message()
            if response.get("id") == self.request_id:
                if "error" in response:
                    raise MCPError(str(response["error"]))
                return response
        raise MCPError(f"MCP request timed out: {method}")

    def _notification(self, method: str, params: dict[str, Any]) -> None:
        if self.config.transport == "http":
            try:
                self._http_request({"jsonrpc": "2.0", "method": method, "params": params})
            except Exception:
                pass
            return
        self._write_message({"jsonrpc": "2.0", "method": method, "params": params})

    def _startup_args(self) -> list[str]:
        if self.config.args:
            args = list(self.config.args)
        elif self.config.transport == "stdio":
            args = ["--stdio"]
        else:
            args = ["--host", self.config.host, "--port", str(self.config.port)]
        if self.workspace is not None and "--workspace" not in args:
            args.extend(["--workspace", str(self.workspace.root)])
        if self.config.transport == "http" and str(self.sample.source_path) not in args:
            args.append(str(self.sample.source_path))
        return args

    def _wait_for_http_ready(self) -> None:
        deadline = time.monotonic() + self.config.timeout_seconds
        while time.monotonic() < deadline:
            if self.process and self.process.poll() is not None:
                stderr = self.process.stderr.read() if self.process.stderr else ""
                raise MCPError(f"MCP process exited unexpectedly. {stderr.strip()}")
            try:
                self._http_request({"jsonrpc": "2.0", "id": 0, "method": "ping", "params": {}}, allow_error=True)
                return
            except MCPError:
                time.sleep(0.5)
        raise MCPError(f"MCP HTTP endpoint did not become ready on {self.config.host}:{self.config.port}.")

    def _http_request(self, message: dict[str, Any], *, allow_error: bool = False) -> dict[str, Any]:
        payload = json.dumps(message, separators=(",", ":")).encode("utf-8")
        url = f"http://{self.config.host}:{self.config.port}/mcp"
        request = urllib.request.Request(
            url,
            data=payload,
            headers={"Content-Type": "application/json", "Accept": "application/json, text/event-stream"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=self.config.timeout_seconds) as response:
                raw = response.read().decode("utf-8", errors="replace")
        except (OSError, urllib.error.URLError) as exc:
            raise MCPError(f"MCP HTTP request failed: {exc}") from exc
        parsed = _parse_http_mcp_response(raw)
        if "error" in parsed and not allow_error:
            raise MCPError(str(parsed["error"]))
        return parsed

    def _write_message(self, message: dict[str, Any]) -> None:
        if self.process is None or self.process.stdin is None:
            raise MCPError("MCP process is not running.")
        payload = json.dumps(message, separators=(",", ":"))
        framed = f"Content-Length: {len(payload.encode('utf-8'))}\r\n\r\n{payload}"
        self.process.stdin.write(framed)
        self.process.stdin.flush()

    def _read_message(self) -> dict[str, Any]:
        if self.process is None or self.process.stdout is None:
            raise MCPError("MCP process is not running.")
        headers: dict[str, str] = {}
        while True:
            line = self.process.stdout.readline()
            if line == "":
                stderr = self.process.stderr.read() if self.process.stderr else ""
                raise MCPError(f"MCP process exited unexpectedly. {stderr.strip()}")
            line = line.strip()
            if not line:
                break
            if ":" in line:
                key, value = line.split(":", 1)
                headers[key.lower()] = value.strip()
        length = int(headers.get("content-length", "0"))
        if length <= 0:
            raise MCPError("MCP response missing Content-Length.")
        payload = self.process.stdout.read(length)
        return json.loads(payload)


class SimulationInvestigationClient:
    """Deterministic simulation provider for tests and local development."""

    def __init__(
        self,
        *,
        capabilities: set[MCPCapability] | None = None,
        responses: dict[tuple[str, str], MCPToolResult] | None = None,
        failures: dict[tuple[str, str], str] | None = None,
    ) -> None:
        self._capabilities = capabilities or set(MCPCapability)
        self._responses = responses or {}
        self._failures = failures or {}
        self.connected = False

    def connect(self) -> None:
        self.connected = True

    def close(self) -> None:
        self.connected = False

    def discover_capabilities(self) -> set[MCPCapability]:
        return set(self._capabilities)

    def session_metadata(self) -> MCPSessionMetadata:
        return MCPSessionMetadata(
            session_id=str(uuid4()),
            backend="simulation",
            provider="simulation",
            transport="in-process",
            connection_mode="test",
            sample_identity_verified=True,
            available_tools=sorted(capability.value for capability in self._capabilities),
            normalized_capabilities=sorted(capability.value for capability in self._capabilities),
        )

    def execute(self, capability: MCPCapability, target: str, parameters: dict) -> MCPToolResult:
        if not self.connected:
            raise MCPError("Simulation investigation client is not connected.")
        start = time.perf_counter()
        key = (capability.value, target.lower())
        if key in self._failures:
            return MCPToolResult(
                capability=capability,
                target=target,
                success=False,
                error=self._failures[key],
                duration_ms=int((time.perf_counter() - start) * 1000),
            )
        if key in self._responses:
            result = self._responses[key].model_copy(deep=True)
            result.duration_ms = int((time.perf_counter() - start) * 1000)
            return result

        observations = _default_observations(capability, target, parameters)
        raw = {"capability": capability.value, "target": target, "observations": observations}
        payload = json.dumps(raw, sort_keys=True)
        return MCPToolResult(
            capability=capability,
            target=target,
            success=True,
            observations=observations,
            raw=raw,
            duration_ms=int((time.perf_counter() - start) * 1000),
            result_size=len(payload),
        )


MockMCPClient = SimulationInvestigationClient


def normalize_tool_catalog(tool_names: Any) -> dict[MCPCapability, str]:
    mapping: dict[MCPCapability, str] = {}
    for raw_name in tool_names:
        name = str(raw_name)
        lowered = name.lower()
        if _looks_mutating_tool(lowered):
            continue
        capability = _capability_for_tool(lowered)
        if capability and capability not in mapping:
            mapping[capability] = name
    return mapping


def _capability_for_tool(name: str) -> MCPCapability | None:
    tests: list[tuple[MCPCapability, tuple[str, ...]]] = [
        (MCPCapability.DATABASE, ("idb_open", "idb_close", "idalib_open", "idalib_close", "idalib_current", "idalib_list", "database")),
        (MCPCapability.METADATA, ("metadata", "info")),
        (MCPCapability.FUNCTIONS, ("functions", "list_functions", "list_funcs", "lookup_funcs", "export_funcs")),
        (MCPCapability.FUNCTION, ("function", "get_function")),
        (MCPCapability.DECOMPILE, ("decompile", "pseudocode")),
        (MCPCapability.DISASSEMBLE, ("disassemble", "disasm")),
        (MCPCapability.XREF_TO, ("xrefs_to", "xref_to", "references_to")),
        (MCPCapability.XREF_FROM, ("xrefs_from", "xref_from", "references_from")),
        (MCPCapability.XREFS, ("xrefs", "references")),
        (MCPCapability.CALLERS, ("callers", "called_by")),
        (MCPCapability.CALLEES, ("callees", "calls")),
        (MCPCapability.CFG, ("cfg", "control_flow")),
        (MCPCapability.BASIC_BLOCKS, ("basic_blocks", "blocks")),
        (MCPCapability.STRINGS, ("strings",)),
        (MCPCapability.IMPORTS, ("imports",)),
        (MCPCapability.EXPORTS, ("exports",)),
        (MCPCapability.GLOBALS, ("globals", "global_variables")),
        (MCPCapability.MEMORY, ("memory", "read_memory")),
        (MCPCapability.DATA, ("data", "bytes")),
        (MCPCapability.TYPES, ("types", "type")),
        (MCPCapability.STRUCTURES, ("structures", "structs")),
        (MCPCapability.SEGMENTS, ("segments",)),
        (MCPCapability.SEARCH, ("search", "find")),
    ]
    for capability, markers in tests:
        if any(marker in name for marker in markers):
            return capability
    return None


def _looks_mutating_tool(name: str) -> bool:
    return any(
        marker in name.lower()
        for marker in (
            "rename",
            "comment",
            "comments",
            "patch",
            "write",
            "set_",
            "put_",
            "delete_",
            "declare_",
            "define_",
            "infer_",
            "make_",
            "undefine",
            "define_code",
            "apply_type",
            "debug",
            "run",
            "execute",
            "eval",
            "script",
        )
    )


def _pick_tool(tool_names: Any, candidates: tuple[str, ...]) -> str | None:
    lowered = {str(name).lower(): str(name) for name in tool_names}
    for candidate in candidates:
        if candidate in lowered:
            return lowered[candidate]
    for lowered_name, original in lowered.items():
        if any(candidate in lowered_name for candidate in candidates):
            return original
    return None


def _tool_arguments(capability: MCPCapability, target: str, parameters: dict[str, Any], database_id: str) -> dict[str, Any]:
    args = dict(parameters)
    if capability == MCPCapability.DECOMPILE:
        args.setdefault("addr", target)
    elif capability in {MCPCapability.DISASSEMBLE, MCPCapability.CFG, MCPCapability.FUNCTION}:
        args.setdefault("addr", target)
    elif capability in {MCPCapability.BASIC_BLOCKS, MCPCapability.XREFS, MCPCapability.XREF_TO, MCPCapability.XREF_FROM, MCPCapability.CALLERS, MCPCapability.CALLEES}:
        args.setdefault("addrs", target)
    elif capability == MCPCapability.FUNCTIONS:
        args.setdefault("queries", {"filter": parameters.get("filter", "*"), "offset": parameters.get("offset", 0), "count": parameters.get("count", 50)})
    elif capability in {MCPCapability.IMPORTS, MCPCapability.EXPORTS, MCPCapability.GLOBALS}:
        args.setdefault("offset", parameters.get("offset", 0))
        args.setdefault("count", parameters.get("count", 50))
    elif capability in {MCPCapability.MEMORY, MCPCapability.DATA}:
        args.setdefault("regions", {"addr": target, "size": parameters.get("size", 64)})
    elif capability == MCPCapability.STRUCTURES:
        args.setdefault("filter", parameters.get("filter", target))
    elif capability == MCPCapability.SEARCH:
        args.setdefault("type", parameters.get("type", "string"))
        args.setdefault("targets", parameters.get("query", target))
    if capability in {MCPCapability.DATABASE, MCPCapability.METADATA}:
        args.setdefault("database", database_id)
    return args


def _result_to_observations(capability: MCPCapability, result: Any) -> list[dict[str, Any]]:
    content = result.get("content") if isinstance(result, dict) else None
    if isinstance(content, list):
        observations = []
        for item in content:
            if isinstance(item, dict) and "text" in item:
                observations.append({"type": capability.value, "text": item["text"]})
            elif isinstance(item, dict):
                observations.append({"type": capability.value, **item})
            else:
                observations.append({"type": capability.value, "value": str(item)})
        return observations
    if isinstance(result, dict):
        return [{"type": capability.value, **result}]
    if isinstance(result, list):
        return [{"type": capability.value, "value": item} if not isinstance(item, dict) else {"type": capability.value, **item} for item in result]
    return [{"type": capability.value, "value": str(result)}]


def _extract_database_id(result: Any) -> str | None:
    if isinstance(result, dict):
        for key in ("database", "session", "session_id", "id"):
            value = result.get(key)
            if isinstance(value, str) and value:
                return value
        for value in result.values():
            found = _extract_database_id(value)
            if found:
                return found
    if isinstance(result, list):
        for value in result:
            found = _extract_database_id(value)
            if found:
                return found
    return None


def _parse_http_mcp_response(raw: str) -> dict[str, Any]:
    text = raw.strip()
    if not text:
        return {}
    if text.startswith("{"):
        return json.loads(text)
    data_lines = []
    for line in text.splitlines():
        if line.startswith("data:"):
            data_lines.append(line.split(":", 1)[1].strip())
    if data_lines:
        return json.loads("\n".join(data_lines))
    try:
        return json.loads(text)
    except ValueError:
        return {"raw": text}


def _find_json_value(result: Any, wanted_key: str) -> str | None:
    if isinstance(result, dict):
        for key, value in result.items():
            if key == wanted_key and isinstance(value, str):
                return value
            found = _find_json_value(value, wanted_key)
            if found:
                return found
    if isinstance(result, list):
        for value in result:
            found = _find_json_value(value, wanted_key)
            if found:
                return found
    return None


def _default_observations(capability: MCPCapability, target: str, parameters: dict) -> list[dict]:
    if capability == MCPCapability.CALLERS:
        return [{"type": "caller", "source_function": "0x401000", "source_address": "0x401050", "target": target}]
    if capability == MCPCapability.CALLEES:
        return [{"type": "callee", "callee": "0x402000", "source_address": target, "target": target}]
    if capability in {MCPCapability.XREFS, MCPCapability.XREF_TO, MCPCapability.XREF_FROM}:
        return [{"type": "xref", "source_address": "0x401080", "destination_address": target, "xref_type": "code"}]
    if capability == MCPCapability.DISASSEMBLE:
        return [{"type": "disassembly", "address": target, "text": f"{target}: call qword ptr [rax]"}]
    if capability == MCPCapability.DECOMPILE:
        return [{"type": "pseudocode", "address": target, "text": f"// simulated decompilation for {target}"}]
    if capability == MCPCapability.CFG:
        return [{"type": "cfg", "address": target, "blocks": 3, "edges": 2}]
    if capability in {MCPCapability.MEMORY, MCPCapability.DATA}:
        size = parameters.get("size", 16)
        return [{"type": "data", "address": target, "size": size, "preview": "00 11 22 33"}]
    if capability == MCPCapability.TYPES:
        return [{"type": "type", "address": target, "declaration": "int __fastcall func(void *)"}]
    if capability == MCPCapability.FUNCTION:
        return [{"type": "function", "address": target, "name": f"sub_{target.removeprefix('0x')}"}]
    if capability == MCPCapability.SEARCH:
        return [{"type": "search", "query": parameters.get("query", target), "matches": [target]}]
    if capability in {MCPCapability.STRINGS, MCPCapability.IMPORTS, MCPCapability.EXPORTS, MCPCapability.GLOBALS, MCPCapability.SEGMENTS, MCPCapability.METADATA}:
        return [{"type": capability.value, "target": target, "value": f"simulated {capability.value}"}]
    return []
