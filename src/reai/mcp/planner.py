from __future__ import annotations

from reai.mcp.schemas import MCPCapability, InvestigationAction, InvestigationPlan, InvestigationTarget


class InvestigationPlanner:
    def plan(
        self,
        target: InvestigationTarget,
        *,
        available_capabilities: set[MCPCapability],
        completed_fingerprints: set[str],
        remaining_tool_calls: int,
    ) -> InvestigationPlan:
        if remaining_tool_calls <= 0:
            return InvestigationPlan(function_address=target.address, goal="Investigation budget exhausted.")

        candidates = self._candidate_actions(target, available_capabilities)
        actions: list[InvestigationAction] = []
        seen: set[str] = set()
        for action in candidates:
            fingerprint = action.fingerprint()
            if fingerprint in completed_fingerprints or fingerprint in seen:
                continue
            seen.add(fingerprint)
            actions.append(action)
            if len(actions) >= remaining_tool_calls:
                break
            if len(actions) >= 3:
                break

        goal = target.investigation_reasons[0] if target.investigation_reasons else "Resolve low-confidence function interpretation."
        return InvestigationPlan(
            function_address=target.address,
            goal=goal,
            actions=actions,
            expected_information_gain=_expected_gain(actions),
            stop_if=[
                "No new normalized evidence is produced.",
                "Confidence reaches HIGH.",
                "Remaining unknowns are not answerable by available MCP capabilities.",
            ],
        )

    def _candidate_actions(
        self,
        target: InvestigationTarget,
        available_capabilities: set[MCPCapability],
    ) -> list[InvestigationAction]:
        unknown_text = " ".join(target.unknowns + target.investigation_reasons).lower()
        function = target.function
        actions: list[InvestigationAction] = []

        def add(capability: MCPCapability, reason: str, *, address: str | None = None, **parameters) -> None:
            if capability in available_capabilities:
                actions.append(
                    InvestigationAction(
                        capability=capability,
                        target=address or target.address,
                        reason=reason,
                        parameters=parameters,
                    )
                )

        if function.get("decompilation_status") == "failed":
            add(MCPCapability.DISASSEMBLE, "Decompiler failed; inspect low-level instructions.")
        if any(word in unknown_text for word in ("body", "pseudocode", "decompile")):
            add(MCPCapability.DECOMPILE, "Retrieve targeted pseudocode for missing function body.")
        if "caller" in unknown_text or "return value" in unknown_text or target.caller_count > 5:
            add(MCPCapability.CALLERS, "Inspect caller contexts and return-value consumers.")
        if "callee" in unknown_text or "child" in unknown_text:
            add(MCPCapability.CALLEES, "Inspect unresolved child-function relationships.")
        if any(word in unknown_text for word in ("xref", "reference", "global", "string", "consumer", "usage")):
            add(MCPCapability.XREFS, "Find references that clarify data or function usage.")
        if "indirect" in unknown_text or "call target" in unknown_text:
            add(MCPCapability.DISASSEMBLE, "Inspect register setup around unresolved indirect call.")
            add(MCPCapability.XREFS, "Look for references that identify indirect-call targets.")
        if any(word in unknown_text for word in ("control", "branch", "loop", "cfg", "error path")):
            add(MCPCapability.CFG, "Inspect control-flow structure for ambiguous paths.")
        if any(word in unknown_text for word in ("type", "prototype", "struct", "field")):
            add(MCPCapability.TYPES, "Inspect prototype or type information.")
        if any(word in unknown_text for word in ("memory", "bytes", "table", "data")):
            add(MCPCapability.DATA, "Read static data bytes or table metadata.")

        if not actions:
            add(MCPCapability.CALLERS, "Low confidence; caller context is the cheapest useful next query.")
            add(MCPCapability.XREFS, "Low confidence; xrefs may reveal data or function usage.")
            add(MCPCapability.DISASSEMBLE, "Low confidence; inspect code when higher-level evidence is absent.")
        return actions


def _expected_gain(actions: list[InvestigationAction]) -> str:
    if not actions:
        return "No available non-duplicate MCP action can materially improve this finding."
    names = ", ".join(action.capability.value for action in actions)
    return f"Targeted {names} evidence may resolve unknowns without broad re-extraction."

