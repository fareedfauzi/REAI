from __future__ import annotations

import json
import platform
import re
import sys
from datetime import datetime, timezone
from pathlib import Path


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def sanitize_name(value: str) -> str:
    name = re.sub(r'[<>:"/\\|?*\x00-\x1f$@~]', "_", value or "function")
    name = re.sub(r"\s+", "_", name)
    name = re.sub(r"_+", "_", name).strip(" ._")
    return (name or "function")[:48]


def artifact_filename(address: int, name: str, extension: str) -> str:
    return f"{address:016x}_{sanitize_name(name)}.{extension.lstrip('.')}"


def addr(value):
    try:
        return int(value)
    except Exception:
        return None


def safe_call(default, func, *args):
    try:
        return func(*args)
    except Exception:
        return default


def report_status(args, message):
    path = args.get("status_path")
    if not path:
        return
    try:
        with Path(path).open("a", encoding="utf-8") as handle:
            handle.write(json.dumps({"timestamp": utc_now(), "message": message}) + "\n")
    except Exception:
        pass


def is_ida_placeholder_name(name):
    lowered = (name or "").lower()
    return lowered.startswith("sub_") or lowered.startswith("nullsub_") or lowered.startswith("j_sub_")


def is_callback_name(name):
    lowered = (name or "").lower()
    callback_terms = (
        "callback",
        "cb_",
        "_cb",
        "wndproc",
        "dlgproc",
        "enumproc",
        "hookproc",
        "timerproc",
        "threadproc",
        "fiberproc",
        "windowproc",
    )
    return any(term in lowered for term in callback_terms)


def analysis_target_reason(record, entry_functions, callback_functions):
    if record["is_thunk"] or record["is_library"] or record["is_external"]:
        return None
    address = record["address"]
    if address in entry_functions:
        return "entry"
    if address in callback_functions or is_callback_name(record["name"]):
        return "callback"
    if is_ida_placeholder_name(record["name"]):
        return "sub"
    return None


def decompile_target_reason(record, decompile_mode, entry_functions, callback_functions):
    if decompile_mode == "none":
        return None
    if decompile_mode == "all":
        if record["is_thunk"] or record["is_library"] or record["is_external"]:
            return None
        return "all"
    return analysis_target_reason(record, entry_functions, callback_functions)


def segment_name(ea):
    import ida_segment

    seg = ida_segment.getseg(ea)
    if not seg:
        return None
    return ida_segment.get_segm_name(seg)


def source_function(ea):
    import ida_funcs

    func = ida_funcs.get_func(ea)
    return int(func.start_ea) if func else None


def collect_entry_function_addresses():
    import ida_entry
    import ida_funcs
    import ida_idaapi

    addresses = set()
    for index in range(safe_call(0, ida_entry.get_entry_qty)):
        ordinal = ida_entry.get_entry_ordinal(index)
        ea = ida_entry.get_entry(ordinal)
        if ea == ida_idaapi.BADADDR:
            continue
        func = ida_funcs.get_func(ea)
        addresses.add(int(func.start_ea if func else ea))
    return addresses


def collect_callback_function_addresses(function_starts):
    import idautils

    callbacks = set()
    for start in function_starts:
        refs = list(safe_call([], lambda ea: list(idautils.DataRefsTo(ea)), start) or [])
        if refs:
            callbacks.add(int(start))
    return callbacks


def batch_decompile_targets(ida_hexrays, ida_pro, pseudocode_dir, target_addresses, args):
    if not target_addresses:
        return {}, {}
    if not hasattr(ida_hexrays, "decompile_many"):
        reason = "ida_hexrays.decompile_many is unavailable"
        return {}, {int(address): reason for address in target_addresses}

    batch_size = max(1, int(args.get("decompile_batch_size") or 25))
    results = {}
    failures = {}
    total = len(target_addresses)

    flags = 0
    for name in ("VDRUN_NEWFILE", "VDRUN_SILENT", "VDRUN_CMDLINE"):
        flags |= int(getattr(ida_hexrays, name, 0))

    for chunk_index, offset in enumerate(range(0, total, batch_size), start=1):
        chunk = [int(address) for address in target_addresses[offset : offset + batch_size]]
        start_number = offset + 1
        end_number = offset + len(chunk)
        output_path = pseudocode_dir / f"decompiled_{chunk_index:04d}.c"
        try:
            output_path.unlink(missing_ok=True)
        except OSError:
            pass

        report_status(args, f"batch decompiling functions {start_number}-{end_number}/{total}")
        addresses = ida_pro.uint64vec_t()
        for address in chunk:
            addresses.push_back(address)

        ok = safe_call(False, ida_hexrays.decompile_many, str(output_path), addresses, flags)
        if not ok:
            reason = "ida_hexrays.decompile_many returned false"
            failures.update({address: reason for address in chunk})
            report_status(args, f"decompile chunk {chunk_index} failed")
            continue
        if not output_path.exists() or output_path.stat().st_size == 0:
            reason = "ida_hexrays.decompile_many produced no output"
            failures.update({address: reason for address in chunk})
            report_status(args, f"decompile chunk {chunk_index} produced no output")
            continue

        rel_path = str(Path("Extracted Codes") / "pseudocode" / output_path.name)
        for address in chunk:
            results[address] = rel_path
        report_status(args, f"finished decompile chunk {chunk_index}/{(total + batch_size - 1) // batch_size}")

    return results, failures


def write_disassembly_artifact(record, disassembly_dir, max_disassembly_lines):
    import ida_lines
    import idautils

    dis_lines = []
    for head in idautils.Heads(record["address"], record["end_address"]):
        if max_disassembly_lines and len(dis_lines) >= max_disassembly_lines:
            break
        text = safe_call("", ida_lines.generate_disasm_line, head, 0) or ""
        text = ida_lines.tag_remove(text)
        if text:
            dis_lines.append(f"{int(head):016x}: {text}")
    if max_disassembly_lines and len(dis_lines) >= max_disassembly_lines:
        dis_lines.append(f"; [TRUNCATED after {max_disassembly_lines} disassembly lines]")
    dis_name = artifact_filename(int(record["address"]), record["name"], "asm")
    (disassembly_dir / dis_name).write_text("\n".join(dis_lines) + "\n", encoding="utf-8", errors="replace")
    record["disassembly_status"] = "success"
    record["disassembly_path"] = str(Path("Extracted Codes") / "disassembly" / dis_name)


def collect_metadata(args):
    import ida_entry
    import ida_ida
    import ida_idaapi
    import ida_loader
    import ida_nalt

    info = ida_ida.inf_get_procname()
    bitness = 64 if ida_ida.inf_is_64bit() else 32 if ida_ida.inf_is_32bit_exactly() else None
    entry_points = []
    for index in range(safe_call(0, ida_entry.get_entry_qty)):
        ordinal = ida_entry.get_entry_ordinal(index)
        ea = ida_entry.get_entry(ordinal)
        if ea != ida_idaapi.BADADDR:
            entry_points.append(int(ea))
    min_ea = safe_call(None, ida_ida.inf_get_min_ea)
    max_ea = safe_call(None, ida_ida.inf_get_max_ea)
    return {
        "architecture": info,
        "bitness": bitness,
        "endianness": "big" if ida_ida.inf_is_be() else "little",
        "image_base": addr(safe_call(None, ida_nalt.get_imagebase)),
        "entry_points": entry_points,
        "file_type": safe_call(None, ida_loader.get_file_type_name),
        "loader": safe_call(None, ida_loader.get_path, ida_loader.PATH_TYPE_IDB),
        "min_address": addr(min_ea),
        "max_address": addr(max_ea),
        "ida_version": safe_call(
            None,
            lambda: getattr(
                __import__("ida_kernwin"),
                "get_kernel_version",
                getattr(ida_idaapi, "get_kernel_version", lambda: None),
            )(),
        ),
        "python_version": platform.python_version(),
        "reai_version": args.get("reai_version"),

        "analysis_started_at": args.get("analysis_started_at"),
        "analysis_completed_at": utc_now(),
    }


def collect_segments():
    import ida_segment
    import idautils

    records = []
    for start in idautils.Segments():
        seg = ida_segment.getseg(start)
        if not seg:
            continue
        permissions = []
        if seg.perm & ida_segment.SEGPERM_EXEC:
            permissions.append("x")
        if seg.perm & ida_segment.SEGPERM_READ:
            permissions.append("r")
        if seg.perm & ida_segment.SEGPERM_WRITE:
            permissions.append("w")
        records.append(
            {
                "name": ida_segment.get_segm_name(seg) or f"seg_{int(seg.start_ea):x}",
                "start": int(seg.start_ea),
                "end": int(seg.end_ea),
                "size": int(seg.end_ea - seg.start_ea),
                "permissions": "".join(permissions) or None,
                "segment_class": safe_call(None, ida_segment.get_segm_class, seg),
                "segment_type": str(seg.type),
            }
        )
    return records


def collect_imports():
    import ida_nalt

    imports = {}

    def callback(ea, name, ordinal):
        imports[int(ea)] = {
            "module": current_module,
            "name": name,
            "ordinal": int(ordinal) if ordinal else None,
            "address": int(ea),
            "xrefs": [],
            "referencing_functions": [],
        }
        return True

    for index in range(ida_nalt.get_import_module_qty()):
        current_module = ida_nalt.get_import_module_name(index)
        ida_nalt.enum_import_names(index, callback)
    return imports


def collect_exports():
    import idautils

    records = []
    for index, ordinal, ea, name in idautils.Entries():
        records.append({"name": name, "address": int(ea), "ordinal": int(ordinal) if ordinal else None})
    return records


def collect_strings():
    import ida_xref
    import idautils

    records = {}
    for item in idautils.Strings():
        ea = int(item.ea)
        xrefs = []
        funcs = set()
        for ref in idautils.DataRefsTo(ea):
            func = source_function(ref)
            if func:
                funcs.add(func)
            xrefs.append(
                {
                    "source_address": int(ref),
                    "destination_address": ea,
                    "xref_type": "data",
                    "source_function": func,
                    "destination_entity": "string",

                }
            )
        records[ea] = {
            "address": ea,
            "value": str(item),
            "encoding": str(getattr(item, "strtype", "")) or None,
            "length": int(getattr(item, "length", 0)) or None,
            "xrefs": xrefs,
            "referencing_functions": sorted(funcs),
        }
    return records


def collect_functions(imports_by_address, strings_by_address, workspace_root, args):
    import ida_funcs
    import ida_hexrays
    import ida_name
    import ida_pro
    import ida_typeinf
    import idautils

    functions = {}
    edges = []
    failures = []
    all_xrefs = []
    pseudocode_dir = Path(workspace_root) / "Extracted Codes" / "pseudocode"
    disassembly_dir = Path(workspace_root) / "Extracted Codes" / "disassembly"
    pseudocode_dir.mkdir(parents=True, exist_ok=True)
    disassembly_dir.mkdir(parents=True, exist_ok=True)
    hexrays_available = bool(safe_call(False, ida_hexrays.init_hexrays_plugin))
    decompile_mode = str(args.get("decompile_mode") or "targeted").lower().replace("-", "_")
    if decompile_mode in {"target", "targets", "ai"}:
        decompile_mode = "targeted"
    elif decompile_mode in {"off", "disabled", "false"}:
        decompile_mode = "none"
    elif decompile_mode == "true":
        decompile_mode = "all"
    if decompile_mode not in {"all", "targeted", "none"}:
        decompile_mode = "targeted"
    max_decompiled = int(args.get("decompile_max_functions") or 0)
    max_disassembly_lines = int(args.get("disassembly_max_lines_per_function") or 0)
    function_starts = [int(start) for start in idautils.Functions()]
    report_status(args, f"enumerating {len(function_starts)} functions and references")
    entry_functions = collect_entry_function_addresses()
    callback_functions = collect_callback_function_addresses(function_starts)
    decompile_attempts = 0
    decompile_targets = []
    decompile_target_set = set()
    analysis_target_set = set()

    for start in function_starts:
        func = ida_funcs.get_func(start)
        if not func:
            continue
        name = ida_funcs.get_func_name(start) or ida_name.get_name(start) or f"sub_{int(start):x}"
        flags = int(func.flags)
        record = {
            "address": int(func.start_ea),
            "end_address": int(func.end_ea),
            "name": name,
            "size": int(func.end_ea - func.start_ea),
            "segment": segment_name(func.start_ea),
            "flags": flags,
            "prototype": safe_call(None, ida_typeinf.print_type, func.start_ea, 0),
            "is_thunk": bool(flags & ida_funcs.FUNC_THUNK),
            "is_library": bool(flags & ida_funcs.FUNC_LIB),
            "is_external": (segment_name(func.start_ea) or "").upper() == "XTRN",
            "callers": [],
            "callees": [],
            "string_refs": [],
            "import_refs": [],
            "global_refs": [],
            "decompilation_status": "unavailable" if not hexrays_available else "not_attempted",
            "decompilation_error": None,
            "pseudocode_path": None,
            "disassembly_status": "not_attempted",
            "disassembly_path": None,
            "scc_id": None,
            "recursive": False,
        }

        analysis_reason = analysis_target_reason(record, entry_functions, callback_functions)
        if analysis_reason:
            analysis_target_set.add(int(func.start_ea))
        decompile_reason = decompile_target_reason(record, decompile_mode, entry_functions, callback_functions)
        total_cap_reached = bool(max_decompiled and decompile_attempts >= max_decompiled)
        if hexrays_available and decompile_reason and not total_cap_reached:
            decompile_attempts += 1
            decompile_targets.append(int(func.start_ea))
            decompile_target_set.add(int(func.start_ea))

        for head in idautils.Heads(func.start_ea, func.end_ea):
            for callee in idautils.CodeRefsFrom(head, 0):
                callee_func = ida_funcs.get_func(callee)
                if callee_func:
                    edges.append(
                        {
                            "caller": int(func.start_ea),
                            "callee": int(callee_func.start_ea),
                            "type": "direct",
                            "source_address": int(head),
                        }
                    )
                    record["callees"].append(int(callee_func.start_ea))
                elif int(callee) in imports_by_address:
                    record["import_refs"].append(int(callee))
                    xref = {
                        "source_address": int(head),
                        "destination_address": int(callee),
                        "xref_type": "code",
                        "source_function": int(func.start_ea),
                        "destination_entity": "import",
                    }
                    imports_by_address[int(callee)]["xrefs"].append(xref)
                    imports_by_address[int(callee)]["referencing_functions"].append(int(func.start_ea))
                    all_xrefs.append(xref)

            for data_ref in idautils.DataRefsFrom(head):
                data_ref = int(data_ref)
                if data_ref in strings_by_address:
                    record["string_refs"].append(data_ref)
                    all_xrefs.append(
                        {
                            "source_address": int(head),
                            "destination_address": data_ref,
                            "xref_type": "data",
                            "source_function": int(func.start_ea),
                            "destination_entity": "string",
                        }
                    )

        record["callees"] = sorted(set(record["callees"]))
        record["string_refs"] = sorted(set(record["string_refs"]))
        record["import_refs"] = sorted(set(record["import_refs"]))
        functions[int(func.start_ea)] = record

    decompile_targets.sort(key=lambda address: functions.get(address, {}).get("size", 0))

    if decompile_targets:
        batch_size = max(1, int(args.get("decompile_batch_size") or 25))
        report_status(args, f"batch decompiling {len(decompile_targets)} targeted functions in chunks of {batch_size}")
    else:
        if decompile_mode == "none":
            report_status(args, "skipping Hex-Rays decompilation by config")
        else:
            report_status(args, "skipping Hex-Rays batch decompilation; no targeted functions")
    pseudocode_paths, decompile_failures = batch_decompile_targets(ida_hexrays, ida_pro, pseudocode_dir, decompile_targets, args)
    if decompile_targets:
        if pseudocode_paths:
            for address in decompile_targets:
                record = functions.get(address)
                if not record:
                    continue
                pseudocode_path = pseudocode_paths.get(address)
                if pseudocode_path:
                    record["decompilation_status"] = "success"
                    record["pseudocode_path"] = pseudocode_path
                    record["disassembly_status"] = "skipped"
        if decompile_failures:
            report_status(args, f"writing fallback disassembly for {len(decompile_failures)} decompile failures")
            for address, reason in decompile_failures.items():
                record = functions.get(address)
                if not record:
                    continue
                record["decompilation_status"] = "failed"
                record["decompilation_error"] = reason
                failures.append(
                    {
                        "extractor": "pseudocode",
                        "address": int(address),
                        "name": record["name"],
                        "reason": reason,
                        "fatal": False,
                    }
                )
                write_disassembly_artifact(record, disassembly_dir, max_disassembly_lines)

    disassembly_targets = sorted(
        address
        for address in analysis_target_set
        if functions.get(address, {}).get("decompilation_status") != "success"
        and functions.get(address, {}).get("disassembly_status") != "success"
    )
    if disassembly_targets:
        report_status(args, f"writing disassembly for {len(disassembly_targets)} target functions")
        for address in disassembly_targets:
            record = functions.get(address)
            if record:
                write_disassembly_artifact(record, disassembly_dir, max_disassembly_lines)

    for address, record in functions.items():
        if address in decompile_target_set or record["disassembly_status"] == "success":
            continue
        record["disassembly_status"] = "skipped"

    callers = {address: set() for address in functions}
    for edge in edges:
        if edge["callee"] in callers:
            callers[edge["callee"]].add(edge["caller"])
    for address, func_callers in callers.items():
        functions[address]["callers"] = sorted(func_callers)

    return list(functions.values()), edges, failures, all_xrefs


def collect_globals(function_addresses, string_addresses):
    import ida_bytes
    import ida_name
    import idautils

    records = []
    function_addresses = set(function_addresses)
    string_addresses = set(string_addresses)
    for ea, name in idautils.Names():
        ea = int(ea)
        if ea in function_addresses or ea in string_addresses:
            continue
        seg_name = segment_name(ea)
        if (seg_name or "").upper() == "XTRN":
            continue
        size = safe_call(None, ida_bytes.get_item_size, ea)
        records.append(
            {
                "address": ea,
                "name": name or f"data_{ea:x}",
                "size": int(size) if size else None,
                "type": safe_call(None, ida_name.get_demangled_name, ea, 0),
                "segment": seg_name,
                "xrefs": [],
                "referencing_functions": [],
            }
        )
    return records


def collect_types():
    records = []
    try:
        import ida_struct

        idx = ida_struct.get_first_struc_idx()
        while idx != -1:
            sid = ida_struct.get_struc_by_idx(idx)
            sptr = ida_struct.get_struc(sid)
            name = ida_struct.get_struc_name(sid)
            records.append({"name": name, "kind": "struct", "declaration": None, "metadata": {"size": ida_struct.get_struc_size(sptr)}})
            idx = ida_struct.get_next_struc_idx(idx)
    except Exception:
        pass
    return records


def main():
    args_path = Path(sys.argv[-1])
    args = json.loads(args_path.read_text(encoding="utf-8"))
    args["analysis_started_at"] = utc_now()

    import ida_auto
    import ida_loader
    import ida_pro

    report_status(args, "waiting for IDA auto-analysis")
    ida_auto.auto_wait()

    workspace_root = Path(args["workspace_root"])
    report_status(args, "preparing extraction workspace")
    workspace_root.joinpath("Analysis Data").mkdir(parents=True, exist_ok=True)
    workspace_root.joinpath("Raw Data").mkdir(parents=True, exist_ok=True)
    workspace_root.joinpath("IDB Files").mkdir(parents=True, exist_ok=True)

    report_status(args, "extracting imports")
    imports_by_address = collect_imports()
    report_status(args, "extracting strings")
    strings_by_address = collect_strings()
    report_status(args, "extracting functions and call graph")
    functions, edges, failures, function_xrefs = collect_functions(
        imports_by_address,
        strings_by_address,
        workspace_root,
        args,
    )
    report_status(args, "extracting exports")
    exports = collect_exports()
    report_status(args, "extracting segments")
    segments = collect_segments()
    report_status(args, "extracting globals")
    globals_ = collect_globals(
        [function["address"] for function in functions],
        strings_by_address.keys(),
    )
    report_status(args, "extracting types")
    types = collect_types()

    report_status(args, "saving original IDB")
    ida_loader.save_database(args["idb_path"], ida_loader.DBFL_COMP)

    report_status(args, "writing extraction JSON")
    bundle = {
        "metadata": collect_metadata(args),
        "functions": functions,
        "strings": list(strings_by_address.values()),
        "imports": list(imports_by_address.values()),
        "exports": exports,
        "globals": globals_,
        "segments": segments,
        "types": types,
        "xrefs": function_xrefs,
        "callgraph": {
            "nodes": [{"address": f["address"], "name": f["name"]} for f in functions],
            "edges": edges,
            "components": [],
        },
        "failures": failures,
        "stats": {},
    }
    Path(args["output_json"]).write_text(json.dumps(bundle), encoding="utf-8")
    ida_pro.qexit(0)


if __name__ == "__main__":
    import tempfile
    import traceback
    try:
        main()
    except Exception as exc:
        err_msg = traceback.format_exc()
        try:
            fail_path = Path(tempfile.gettempdir()) / "reai_ida_failure.txt"
            fail_path.write_text(err_msg, encoding="utf-8")
        except Exception:
            pass
        try:
            import ida_pro
            ida_pro.qexit(1)
        except Exception:
            sys.exit(1)
