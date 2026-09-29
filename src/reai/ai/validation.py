from __future__ import annotations

import re

GENERIC_NAME_DENYLIST = {
    "process_data",
    "handle_data",
    "do_work",
    "perform_operation",
    "process_buffer",
    "handle_buffer",
    "helper_function",
    "unknown_function",
    "process_input",
    "handle_request",
    "process_response",
}


def is_generic_name(name: str | None) -> bool:
    return bool(name) and name.strip().lower() in GENERIC_NAME_DENYLIST


def validate_proposed_name(name: str | None) -> tuple[bool, str | None]:
    if not name:
        return False, "No proposed name."
    name_clean = name.strip()
    if name_clean.lower().startswith("sub_"):
        return False, "Proposed name preserves IDA sub_ placeholder."
    if is_generic_name(name_clean):
        return False, "Proposed name is too generic."
    if len(name_clean) > 80:
        return False, "Proposed name is too long."
    if not re.fullmatch(r"[a-zA-Z_][a-zA-Z0-9_]*", name_clean):
        return False, "Proposed name must be a valid identifier."
    return True, None
