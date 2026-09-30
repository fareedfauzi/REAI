from __future__ import annotations

import re
from pathlib import PurePath


def is_consolidated_pseudocode_path(relative_path: str | None) -> bool:
    if not relative_path:
        return False
    name = PurePath(relative_path).name.lower()
    return name == "decompiled.c" or (name.startswith("decompiled_") and name.endswith(".c"))


def extract_consolidated_c_function(text: str | None, function_name: str | None) -> str | None:
    if not text or not function_name:
        return None

    pattern = re.compile(rf"(?m)^[^\n;{{}}]*\b{re.escape(function_name)}\s*\(")
    for match in pattern.finditer(text):
        signature_start = text.rfind("\n", 0, match.start()) + 1
        include_start = _include_previous_header_comment(text, signature_start)
        body_start = text.find("{", match.end())
        if body_start == -1:
            continue
        declaration_end = text.find(";", match.end(), body_start)
        if declaration_end != -1:
            continue

        body_end = _find_balanced_body_end(text, body_start)
        if body_end is not None:
            return text[include_start : body_end + 1].strip() + "\n"

    return None


def _include_previous_header_comment(text: str, signature_start: int) -> int:
    previous_end = signature_start - 1
    if previous_end <= 0:
        return signature_start
    previous_start = text.rfind("\n", 0, previous_end) + 1
    previous_line = text[previous_start:previous_end].strip()
    if previous_line.startswith("//-----"):
        return previous_start
    return signature_start


def _find_balanced_body_end(text: str, body_start: int) -> int | None:
    depth = 0
    in_string: str | None = None
    escaped = False
    in_line_comment = False
    in_block_comment = False

    index = body_start
    while index < len(text):
        char = text[index]
        next_char = text[index + 1] if index + 1 < len(text) else ""

        if in_line_comment:
            if char == "\n":
                in_line_comment = False
            index += 1
            continue

        if in_block_comment:
            if char == "*" and next_char == "/":
                in_block_comment = False
                index += 2
            else:
                index += 1
            continue

        if in_string:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == in_string:
                in_string = None
            index += 1
            continue

        if char == "/" and next_char == "/":
            in_line_comment = True
            index += 2
            continue
        if char == "/" and next_char == "*":
            in_block_comment = True
            index += 2
            continue
        if char in {"\"", "'"}:
            in_string = char
            index += 1
            continue
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return index
        index += 1

    return None
