from __future__ import annotations

import json
import time
from typing import Protocol

from reai.core.config import MCPConfig
from reai.core.exceptions import ReaiError
from reai.mcp.schemas import MCPCapability, MCPToolResult, READ_ONLY_CAPABILITIES


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


def create_mcp_client(config: MCPConfig) -> IDAInvestigationClient | None:
    if not config.enabled:
        return None
    provider = config.provider.lower()
    if provider == "disabled":
        return None
    if provider in {"simulation", "simulator", "simulated", "mock"}:
        return SimulationInvestigationClient()
    raise MCPError(
        "Unsupported MCP provider. Configure [mcp].provider = \"simulation\" for deterministic offline investigation "
        "or add a concrete IDA MCP adapter for this environment."
    )


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
            raise MCPError(f"MCP capability is not allowed in read-only Phase 4: {capability.value}")
        if capability not in self.capabilities:
            return MCPToolResult(
                capability=capability,
                target=target,
                success=False,
                error=f"Capability unavailable: {capability.value}",
            )
        return self.client.execute(capability, target, parameters or {})


class SimulationInvestigationClient:
    """Deterministic simulation provider for autonomous Phase 4 investigation."""

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


# Backward-compatibility alias
MockMCPClient = SimulationInvestigationClient



def _default_observations(capability: MCPCapability, target: str, parameters: dict) -> list[dict]:
    if capability == MCPCapability.CALLERS:
        return [{"type": "caller", "source_function": "0x401000", "source_address": "0x401050", "target": target}]
    if capability == MCPCapability.CALLEES:
        return [{"type": "callee", "callee": "0x402000", "source_address": target, "target": target}]
    if capability == MCPCapability.XREFS:
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
    return []

