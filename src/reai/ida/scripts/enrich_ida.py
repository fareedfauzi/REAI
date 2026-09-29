from __future__ import annotations

import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

import ida_funcs
import ida_loader
import ida_name
import idc


def main() -> None:
    args = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
    changes = args["changes"]
    begin = args.get("comment_marker_begin", "[REAI ANALYSIS BEGIN]")
    end = args.get("comment_marker_end", "[REAI ANALYSIS END]")
    verifications = []

    for change in changes:
        if change["status"] != "PENDING":
            continue
        if change["entity"] == "function" and change["operation"] == "rename":
            _apply_function_rename(change)
        elif change["entity"] == "function" and change["operation"] == "comment":
            _apply_function_comment(change, begin, end)
        else:
            _skip(change, "SKIPPED_CONFLICT", "IDA backend does not support this change type yet.")

    for change in changes:
        if change["status"] != "APPLIED":
            continue
        verification = _verify_change(change, begin)
        verifications.append(verification)

    ida_loader.save_database(args["idb_path"], 0)
    Path(args["result_json"]).write_text(
        json.dumps({"changes": changes, "verification": verifications}, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    idc.qexit(0)


def _apply_function_rename(change: dict) -> None:
    ea = _ea(change.get("address"))
    func = ida_funcs.get_func(ea)
    if func is None:
        _skip(change, "SKIPPED_STATE_MISMATCH", "Target function does not exist.")
        return
    current = ida_funcs.get_func_name(ea)
    if change.get("original") and current != change["original"]:
        _skip(change, "SKIPPED_STATE_MISMATCH", f"Expected {change['original']!r}, found {current!r}.")
        return
    if not _is_placeholder_name(current):
        _skip(change, "SKIPPED_CONFLICT", f"Existing name {current!r} is meaningful and will not be overwritten.")
        return
    proposed = change.get("applied") or _sanitize_name(change["proposed"])
    if not proposed:
        _skip(change, "SKIPPED_CONFLICT", "Proposed name could not be normalized for IDA.")
        return
    if not ida_name.set_name(ea, proposed, ida_name.SN_CHECK):
        _skip(change, "FAILED", "IDA rejected the proposed function name.")
        return
    change["applied"] = proposed
    change["status"] = "APPLIED"
    change["reason"] = "Function placeholder renamed."
    change["timestamp"] = _now()


def _apply_function_comment(change: dict, begin: str, end: str) -> None:
    ea = _ea(change.get("address"))
    func = ida_funcs.get_func(ea)
    if func is None:
        _skip(change, "SKIPPED_STATE_MISMATCH", "Target function does not exist.")
        return
    existing = ida_funcs.get_func_cmt(func, False) or ""
    managed = f"{begin}\nPurpose: {change['proposed']}\nConfidence: {change['confidence']:.2f}\n{end}"
    ida_funcs.set_func_cmt(func, _merge_comment(existing, managed, begin, end), False)
    change["applied"] = change["proposed"]
    change["status"] = "APPLIED"
    change["reason"] = "REAI-managed function comment updated."
    change["timestamp"] = _now()


def _verify_change(change: dict, begin: str) -> dict:
    expected = change.get("applied") or change["proposed"]
    actual = None
    if change["entity"] == "function" and change["operation"] == "rename":
        actual = ida_funcs.get_func_name(_ea(change.get("address")))
    elif change["entity"] == "function" and change["operation"] == "comment":
        func = ida_funcs.get_func(_ea(change.get("address")))
        actual = ida_funcs.get_func_cmt(func, False) if func else None
        expected = begin
    ok = actual is not None and expected in actual
    change["status"] = "VERIFIED" if ok else "FAILED_VERIFICATION"
    return {
        "verification_id": f"verify_{change['change_id']}",
        "change_id": change["change_id"],
        "expected": expected,
        "actual": actual,
        "status": change["status"],
        "details": "Verified." if ok else "Applied value was not found during verification.",
        "timestamp": _now(),
    }


def _skip(change: dict, status: str, reason: str) -> None:
    change["status"] = status
    change["reason"] = reason
    change["timestamp"] = _now()


def _ea(value: str | None) -> int:
    if not value:
        return idc.BADADDR
    return int(value, 16)


def _is_placeholder_name(name: str | None) -> bool:
    return bool(name) and name.lower().startswith("sub_")


def _sanitize_name(value: str) -> str | None:
    name = re.sub(r"[^A-Za-z0-9_]", "_", value or "")
    name = re.sub(r"_+", "_", name).strip("_")
    if not name:
        return None
    if not re.match(r"^[A-Za-z_]", name):
        name = f"fn_{name}"
    return name[:96]


def _merge_comment(existing: str, managed: str, begin: str, end: str) -> str:
    pattern = re.compile(rf"\n?{re.escape(begin)}.*?{re.escape(end)}\n?", re.DOTALL)
    cleaned = pattern.sub("\n", existing).strip()
    return f"{cleaned}\n\n{managed}".strip() if cleaned else managed


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


if __name__ == "__main__":
    main()
