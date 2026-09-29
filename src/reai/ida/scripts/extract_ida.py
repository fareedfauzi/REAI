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
    name = re.sub(r'[<>:"/\\|?*\x00-\x1f]', "_", value or "function")
    name = re.sub(r"\s+", "_", name)
    name = re.sub(r"_+", "_", name).strip(" ._")
    return (name or "function")[:96]


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
        "processor": info,
        "min_address": addr(min_ea),
        "max_address": addr(max_ea),
        "ida_version": safe_call(None, ida_idaapi.get_kernel_version),
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
                    "xref_type": str(safe_call(None, ida_xref.get_xref_type, ref)),
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


def collect_functions(imports_by_address, strings_by_address, workspace_root):
    import ida_bytes
    import ida_funcs
    import ida_hexrays
    import ida_idaapi
    import ida_lines
    import ida_name
    import ida_typeinf
    import ida_xref
    import idautils

    functions = {}
    edges = []
    failures = []
    all_xrefs = []
    pseudocode_dir = Path(workspace_root) / "pseudocode"
    disassembly_dir = Path(workspace_root) / "disassembly"
    pseudocode_dir.mkdir(parents=True, exist_ok=True)
    disassembly_dir.mkdir(parents=True, exist_ok=True)
    hexrays_available = bool(safe_call(False, ida_hexrays.init_hexrays_plugin))

    for start in idautils.Functions():
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

        dis_lines = []
        for head in idautils.Heads(func.start_ea, func.end_ea):
            text = safe_call("", ida_lines.generate_disasm_line, head, 0) or ""
            text = ida_lines.tag_remove(text)
            if text:
                dis_lines.append(f"{int(head):016x}: {text}")

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

        dis_name = artifact_filename(int(func.start_ea), name, "asm")
        (disassembly_dir / dis_name).write_text("\n".join(dis_lines) + "\n", encoding="utf-8", errors="replace")
        record["disassembly_status"] = "success"
        record["disassembly_path"] = str(Path("disassembly") / dis_name)

        if hexrays_available:
            try:
                cfunc = ida_hexrays.decompile(func.start_ea)
                pseudo_lines = [ida_lines.tag_remove(line.line) for line in cfunc.get_pseudocode()]
                pseudo_name = artifact_filename(int(func.start_ea), name, "c")
                (pseudocode_dir / pseudo_name).write_text(
                    "\n".join(pseudo_lines) + "\n",
                    encoding="utf-8",
                    errors="replace",
                )
                record["decompilation_status"] = "success"
                record["pseudocode_path"] = str(Path("pseudocode") / pseudo_name)
            except Exception as exc:
                record["decompilation_status"] = "failed"
                record["decompilation_error"] = str(exc)
                failures.append(
                    {
                        "extractor": "pseudocode",
                        "address": int(func.start_ea),
                        "name": name,
                        "reason": str(exc),
                        "fatal": False,
                    }
                )

        record["callees"] = sorted(set(record["callees"]))
        record["string_refs"] = sorted(set(record["string_refs"]))
        record["import_refs"] = sorted(set(record["import_refs"]))
        functions[int(func.start_ea)] = record

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

    ida_auto.auto_wait()

    workspace_root = Path(args["workspace_root"])
    workspace_root.joinpath("analysis").mkdir(parents=True, exist_ok=True)
    workspace_root.joinpath("raw").mkdir(parents=True, exist_ok=True)
    workspace_root.joinpath("ida").mkdir(parents=True, exist_ok=True)

    imports_by_address = collect_imports()
    strings_by_address = collect_strings()
    functions, edges, failures, function_xrefs = collect_functions(
        imports_by_address,
        strings_by_address,
        workspace_root,
    )
    exports = collect_exports()
    segments = collect_segments()
    globals_ = collect_globals(
        [function["address"] for function in functions],
        strings_by_address.keys(),
    )
    types = collect_types()

    ida_loader.save_database(args["idb_path"], ida_loader.DBFL_COMP)

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
    try:
        main()
    except Exception as exc:
        try:
            Path("reai_ida_failure.txt").write_text(str(exc), encoding="utf-8")
        finally:
            raise
