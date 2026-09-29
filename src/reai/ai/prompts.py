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
            "Use concise snake_case names.",
            "Avoid generic names such as process_data, handle_buffer, do_work, helper_function.",
            "Leave proposed_name null if a specific behavior is not defensible.",
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
