from __future__ import annotations

import re

from reai.enrichment.schemas import ChangeStatus, EnrichmentChange
from reai.utils.names import is_ida_placeholder_name


MANAGED_COMMENT_BEGIN = "[REAI ANALYSIS BEGIN]"
MANAGED_COMMENT_END = "[REAI ANALYSIS END]"


def is_placeholder_name(name: str | None) -> bool:
    return is_ida_placeholder_name(name)


def sanitize_ida_name(value: str) -> str | None:
    name = re.sub(r"[^A-Za-z0-9_]", "_", value or "")
    name = re.sub(r"_+", "_", name).strip("_")
    if not name:
        return None
    if not re.match(r"^[A-Za-z_]", name):
        name = f"fn_{name}"
    return name[:96]


def assign_unique_names(changes: list[EnrichmentChange]) -> None:
    # Sort by address to make suffix assignment (name_2, name_3, etc.) fully
    # deterministic regardless of DB query order. Without this, which function
    # gets the undecorated name vs. name_2 is arbitrary across runs.
    sorted_changes = sorted(
        changes,
        key=lambda c: (c.address or "", c.entity),
    )
    used: dict[str, int] = {}
    for change in sorted_changes:
        if change.entity != "function" or change.operation != "rename" or change.status != ChangeStatus.PENDING:
            continue
        sanitized = sanitize_ida_name(change.proposed)
        if sanitized is None:
            change.status = ChangeStatus.SKIPPED_CONFLICT
            change.reason = "Proposed name cannot be converted to a valid IDA identifier."
            continue
        count = used.get(sanitized, 0) + 1
        used[sanitized] = count
        change.applied = sanitized if count == 1 else f"{sanitized}_{count}"



def merge_reai_comment(existing: str | None, managed_block: str, *, begin: str = MANAGED_COMMENT_BEGIN, end: str = MANAGED_COMMENT_END) -> str:
    existing_text = existing or ""
    pattern = re.compile(re.escape(begin) + r".*?" + re.escape(end), re.DOTALL)
    block = f"{begin}\n{managed_block.strip()}\n{end}"
    if pattern.search(existing_text):
        return pattern.sub(block, existing_text).strip()
    if existing_text.strip():
        return f"{existing_text.rstrip()}\n\n{block}"
    return block


def build_function_comment(change: EnrichmentChange, *, confidence_label: str | None = None) -> str:
    confidence = f"{change.confidence:.2f}"
    label = confidence_label or ("HIGH" if change.confidence >= 0.85 else "MEDIUM")
    lines = [
        f"[REAI ANALYSIS - {label}]",
        "",
        "Purpose:",
        re.sub(r"\s*MCP investigation added \d+ read-only evidence item\(s\) from [^.]*\.?", "", str(change.proposed)).strip(),
    ]
    if change.original:
        lines.extend(["", "Original:", change.original])
    if change.applied:
        lines.extend(["", "REAI Name:", change.applied])
    lines.extend(["", "Confidence:", f"{label} ({confidence})"])
    if change.evidence:
        lines.extend(["", "Evidence:"])
        for item in change.evidence[:5]:
            description = item.get("description") if isinstance(item, dict) else str(item)
            if description:
                lines.append(f"- {description}")
    return "\n".join(lines)
