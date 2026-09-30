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
    import ida_auto
    ida_auto.auto_wait()

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
        elif change["entity"] == "variable" and change["operation"] == "rename":
            _apply_variable_rename(change)
        else:
            _skip(change, "SKIPPED_CONFLICT", f"IDA backend does not support {change['entity']}.{change['operation']} yet.")

    for change in changes:
        if change["status"] != "APPLIED":
            continue
        verification = _verify_change(change, begin)
        verifications.append(verification)

    try:
        ida_loader.save_database(args["idb_path"], ida_loader.DBFL_COMP)
    except Exception:
        ida_loader.save_database(args["idb_path"], 0)

    Path(args["result_json"]).write_text(
        json.dumps({"changes": changes, "verification": verifications}, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    idc.qexit(0)


def _invalidate_hexrays_cache(ea: int) -> None:
    try:
        import ida_hexrays
        if ida_hexrays.init_hexrays_plugin():
            ida_hexrays.mark_cfunc_dirty(ea)
    except Exception:
        pass


def _apply_function_rename(change: dict) -> None:
    ea = _ea(change.get("address"))
    func = ida_funcs.get_func(ea)
    if func is None:
        _skip(change, "SKIPPED_STATE_MISMATCH", "Target function does not exist.")
        return
    current = ida_funcs.get_func_name(ea)
    proposed = change.get("applied") or _sanitize_name(change["proposed"])
    if not proposed:
        _skip(change, "SKIPPED_CONFLICT", "Proposed name could not be normalized for IDA.")
        return
    if current == proposed:
        change["applied"] = proposed
        change["status"] = "APPLIED"
        change["reason"] = "Function already has the proposed name."
        change["timestamp"] = _now()
        _invalidate_hexrays_cache(ea)
        return
    if change.get("original") and current != change["original"] and not _is_placeholder_name(current):
        _skip(change, "SKIPPED_STATE_MISMATCH", f"Expected {change['original']!r}, found {current!r}.")
        return
    if not _is_placeholder_name(current):
        _skip(change, "SKIPPED_CONFLICT", f"Existing name {current!r} is meaningful and will not be overwritten.")
        return
    proposed = _unique_ida_name(proposed, ea)
    if not ida_name.set_name(ea, proposed, ida_name.SN_CHECK):
        _skip(change, "FAILED", "IDA rejected the proposed function name.")
        return
    _invalidate_hexrays_cache(ea)
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
    existing = ida_funcs.get_func_cmt(func, False) or ida_funcs.get_func_cmt(func, True) or ""
    purpose = re.sub(r"\s*MCP investigation added \d+ read-only evidence item\(s\) from [^.]*\.?", "", str(change.get("proposed") or "")).strip()
    managed = f"{begin}\nPurpose: {purpose}\nConfidence: {change['confidence']:.2f}\n{end}"
    merged = _merge_comment(existing, managed, begin, end)
    ida_funcs.set_func_cmt(func, merged, False)
    ida_funcs.set_func_cmt(func, merged, True)
    _invalidate_hexrays_cache(ea)
    change["applied"] = purpose
    change["status"] = "APPLIED"
    change["reason"] = "REAI-managed function comment updated."
    change["timestamp"] = _now()


def _clean_var_identifier(name: str | None) -> str | None:
    if not name:
        return None
    cleaned = name
    if "(" in cleaned:
        cleaned = cleaned.split("(")[0]
    if ":" in cleaned:
        cleaned = cleaned.split(":")[0]
    cleaned = re.sub(r"^[&*]+", "", cleaned).strip()
    match = re.search(r"[a-zA-Z_][a-zA-Z0-9_]*", cleaned)
    return match.group(0) if match else None


def _apply_variable_rename(change: dict) -> None:
    ea = _ea(change.get("address"))
    func = ida_funcs.get_func(ea)
    if func is None:
        _skip(change, "SKIPPED_STATE_MISMATCH", "Target function does not exist.")
        return
    raw_orig = change.get("original")
    orig_id = _clean_var_identifier(raw_orig) or raw_orig
    raw_proposed = change.get("applied") or change["proposed"]
    prop_id = _clean_var_identifier(raw_proposed) or raw_proposed
    proposed = _sanitize_name(prop_id)
    if not orig_id or not proposed:
        _skip(change, "SKIPPED_CONFLICT", "Variable name invalid or missing.")
        return

    if orig_id == proposed:
        change["applied"] = proposed
        change["status"] = "APPLIED"
        change["reason"] = "Variable already has the proposed name."
        change["timestamp"] = _now()
        return

    lvar_names = set()
    try:
        import ida_hexrays
        if ida_hexrays.init_hexrays_plugin():
            cfunc = ida_hexrays.decompile(ea)
            if cfunc:
                for lvar in cfunc.get_lvars():
                    if lvar.name:
                        lvar_names.add(str(lvar.name))
    except Exception:
        pass
    is_global_name = bool(re.match(r"^(?:dword|unk|qword|byte|word)_([0-9a-fA-F]+)$", orig_id or ""))
    if lvar_names and orig_id not in lvar_names and not is_global_name:
        if proposed in lvar_names:
            change["applied"] = proposed
            change["status"] = "APPLIED"
            change["reason"] = "Variable already has the proposed name."
            change["timestamp"] = _now()
            return
        _skip(change, "SKIPPED_STATE_MISMATCH", f"Hex-Rays local variable {orig_id!r} was not found.")
        return
    if lvar_names and not is_global_name:
        proposed = _unique_local_name(proposed, lvar_names - {orig_id})

    renamed = False
    # Attempt 1: Hex-Rays local variable rename
    try:
        import ida_hexrays
        if ida_hexrays.init_hexrays_plugin():
            if ida_hexrays.rename_lvar(ea, orig_id, proposed):
                renamed = True
                ida_hexrays.mark_cfunc_dirty(ea)
    except Exception:
        pass

    # Attempt 2: IDA stack frame variable rename
    if not renamed:
        try:
            import ida_frame, ida_struct
            frame = ida_frame.get_frame(func)
            if frame:
                member = ida_struct.get_member_by_name(frame, orig_id)
                if member and ida_struct.set_member_name(frame, member.soff, proposed):
                    renamed = True
                    _invalidate_hexrays_cache(ea)
        except Exception:
            pass

    # Attempt 3: Global data variable rename (e.g. dword_404378)
    if not renamed and orig_id:
        match = re.match(r"^(?:dword|unk|qword|byte|word)_([0-9a-fA-F]+)$", orig_id)
        if match:
            try:
                global_ea = int(match.group(1), 16)
                if ida_name.set_name(global_ea, proposed, ida_name.SN_CHECK):
                    renamed = True
                    _invalidate_hexrays_cache(ea)
            except Exception:
                pass

    if not renamed:
        _skip(change, "FAILED", f"Could not rename variable {orig_id!r} to {proposed!r}.")
        return

    change["applied"] = proposed
    change["status"] = "APPLIED"
    change["reason"] = "Variable renamed in Hex-Rays/IDA."
    change["timestamp"] = _now()


def _verify_change(change: dict, begin: str) -> dict:
    expected = change.get("applied") or change["proposed"]
    actual = None
    ok = False
    if change["entity"] == "function" and change["operation"] == "rename":
        actual = ida_funcs.get_func_name(_ea(change.get("address")))
        ok = actual == expected
    elif change["entity"] == "function" and change["operation"] == "comment":
        func = ida_funcs.get_func(_ea(change.get("address")))
        actual = (ida_funcs.get_func_cmt(func, False) or ida_funcs.get_func_cmt(func, True)) if func else None
        expected = begin
        ok = actual is not None and expected in actual
    elif change["entity"] == "variable" and change["operation"] == "rename":
        ea = _ea(change.get("address"))
        try:
            import ida_hexrays
            if ida_hexrays.init_hexrays_plugin():
                cfunc = ida_hexrays.decompile(ea)
                if cfunc:
                    for lvar in cfunc.get_lvars():
                        if lvar.name == expected:
                            actual = expected
                            break
        except Exception:
            pass
        if actual is None:
            try:
                import ida_frame, ida_struct
                func = ida_funcs.get_func(ea)
                frame = ida_frame.get_frame(func) if func else None
                if frame and ida_struct.get_member_by_name(frame, expected):
                    actual = expected
            except Exception:
                pass
        if actual is None:
            try:
                orig_id = _clean_var_identifier(change.get("original")) or change.get("original")
                match = re.match(r"^(?:dword|unk|qword|byte|word)_([0-9a-fA-F]+)$", orig_id or "")
                if match:
                    global_ea = int(match.group(1), 16)
                    current_name = ida_name.get_name(global_ea)
                    if current_name == expected:
                        actual = expected
            except Exception:
                pass
        ok = actual == expected
    else:
        ok = True

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


def _unique_ida_name(base: str, ea: int) -> str:
    if idc.get_name_ea_simple(base) in (idc.BADADDR, ea):
        return base
    suffix = 2
    while True:
        tail = f"_{suffix}"
        candidate = f"{base[: 96 - len(tail)]}{tail}"
        if idc.get_name_ea_simple(candidate) in (idc.BADADDR, ea):
            return candidate
        suffix += 1


def _unique_local_name(base: str, used: set[str]) -> str:
    if base not in used:
        return base
    suffix = 2
    while True:
        tail = f"_{suffix}"
        candidate = f"{base[: 96 - len(tail)]}{tail}"
        if candidate not in used:
            return candidate
        suffix += 1


def _merge_comment(existing: str, managed: str, begin: str, end: str) -> str:
    pattern = re.compile(rf"\n?{re.escape(begin)}.*?{re.escape(end)}\n?", re.DOTALL)
    cleaned = pattern.sub("\n", existing).strip()
    return f"{cleaned}\n\n{managed}".strip() if cleaned else managed


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        try:
            import tempfile, traceback
            fail_path = Path(tempfile.gettempdir()) / "reai_enrich_failure.txt"
            fail_path.write_text(traceback.format_exc(), encoding="utf-8")
        except Exception:
            pass
        try:
            idc.qexit(1)
        except Exception:
            sys.exit(1)
