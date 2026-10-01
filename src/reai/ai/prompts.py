from __future__ import annotations

import json

from reai.ai.schemas import FunctionContext, SCHEMA_VERSION

PROMPT_VERSION = "phase3-function-analysis-v1"


SYSTEM_PROMPT = """You are REAI's Phase 3 malware reverse-engineering analyzer.
Use only the provided deterministic static-analysis context and completed child findings.
Prefer uncertainty over generic guessing. Do not invent behavior that is not supported by evidence.
Return only the required structured schema. Do not include hidden chain-of-thought; use reasoning_summary for concise analyst-facing rationale."""


def build_function_prompt(context: FunctionContext) -> str:
    payload = context.model_dump(mode="json")
    instructions = {
        "task": "Analyze one IDA function and propose the most specific defensible semantic interpretation.",
        "schema_version": SCHEMA_VERSION,
        "naming_policy": [
            "Propose a concise, specific snake_case name reflecting the function's observed purpose, API calls, or control flow (e.g., wrapper_output_wstring, init_slist_head, timed_sleep_loop, set_exception_filter, compute_bit_shifts).",
            "Avoid overly generic names such as process_data, handle_buffer, do_work, helper_function.",
            "Do NOT preserve or repeat IDA's sub_ prefix in proposed_name. Always propose a descriptive semantic name.",
            "Only leave proposed_name null if the function is completely empty or has no discernable purpose.",
        ],
        "variable_policy": [
            "Propose renames for local variables or function arguments (e.g. this, a1, a2, v1, v2) that appear in the decompiled code.",
            "original MUST be the exact variable identifier as it appears in IDA decompilation (e.g. 'this', 'a1', 'a2', 'v3', 'Buffer'). Do NOT include types, pointers, or explanations in 'original' (e.g. use 'this', NOT '*this (pointer)').",
            "proposed MUST be a concise valid snake_case identifier (e.g. 'output_buffer', 'buffer_size', 'sleep_duration_ms', 'input_val'). Do NOT include spaces or parenthetical descriptions in 'proposed'.",
        ],

        "evidence_policy": [
            "Cite deterministic IDA facts for semantic conclusions.",
            "Mark deterministic evidence as IDA_OBSERVED.",
            "Mark semantic conclusions as AI_DERIVED only when needed.",
            "Do not classify strings as final IOCs in Phase 3.",
        ],
        "uncertainty_policy": [
            "Record unknowns when evidence is incomplete.",
            "Set needs_investigation true for low confidence or unresolved important behavior.",
        ],
        "context": payload,
    }
    return json.dumps(instructions, indent=2, sort_keys=True)


def build_function_batch_prompt(contexts: list[FunctionContext]) -> str:
    payload = [context.model_dump(mode="json") for context in contexts]
    instructions = {
        "task": "Analyze a small batch of independent IDA functions and return one result per input function.",
        "schema_version": SCHEMA_VERSION,
        "output_schema": "FunctionAnalysisBatchResult",
        "batch_policy": [
            "Return exactly one result object for each input function address.",
            "Each result must follow the same FunctionAnalysisResult schema used for single-function analysis.",
            "Do not merge functions together. Analyze each function independently, while using completed child_findings inside that function's context.",
            "Preserve each input function address in the matching result.address field.",
        ],
        "naming_policy": [
            "Propose a concise, specific snake_case name reflecting each function's observed purpose, API calls, or control flow.",
            "Avoid overly generic names such as process_data, handle_buffer, do_work, helper_function.",
            "Do NOT preserve or repeat IDA's sub_ prefix in proposed_name. Always propose a descriptive semantic name.",
            "Only leave proposed_name null if the function is completely empty or has no discernable purpose.",
        ],
        "variable_policy": [
            "Propose renames for local variables or function arguments that appear in the decompiled code.",
            "original MUST be the exact variable identifier as it appears in IDA decompilation.",
            "proposed MUST be a concise valid snake_case identifier.",
        ],
        "evidence_policy": [
            "Cite deterministic IDA facts for semantic conclusions.",
            "Mark deterministic evidence as IDA_OBSERVED.",
            "Mark semantic conclusions as AI_DERIVED only when needed.",
            "Do not classify strings as final IOCs in Phase 3.",
        ],
        "uncertainty_policy": [
            "Record unknowns when evidence is incomplete.",
            "Set needs_investigation true for low confidence or unresolved important behavior.",
        ],
        "contexts": payload,
    }
    return json.dumps(instructions, indent=2, sort_keys=True)
