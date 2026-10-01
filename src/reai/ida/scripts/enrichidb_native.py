from __future__ import annotations

import json
import os
import re
import shutil
import sys
import time
import traceback
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path

import ida_auto
import ida_bytes
import ida_funcs
import ida_hexrays
import ida_idaapi
import ida_lines
import ida_loader
import ida_name
import idautils
import idc


def main() -> None:
    args = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
    report_status(args, 1, "waiting for IDA auto-analysis")
    ida_auto.auto_wait()

    report_status(args, 2, "collecting functions and call graph")
    functions = collect_functions()
    calls = collect_calls(functions)
    targets = [func for func in functions if is_target(func)]
    groups = bottom_up_groups([func["ea"] for func in targets], calls)
    target_by_ea = {func["ea"]: func for func in targets}
    child_findings = {}
    stats = {"function_renames": 0, "variable_renames": 0, "comments": 0, "failed": 0}

    ai = args["ai"]
    batch_size = max(1, int(args.get("batch_size") or 5))
    max_workers = max(1, int(args.get("max_workers") or 2))
    total = len(targets)
    processed = 0
    report_status(args, 3, f"using AI batches of up to {batch_size} functions with {max_workers} concurrent batch workers")

    for group in groups:
        pending = []
        for ea in group:
            func = target_by_ea.get(ea)
            if not func:
                continue
            processed += 1
            context = build_context(func, calls, child_findings)
            pending.append((processed, func, context))
        if not pending:
            continue
        batches = list(chunks(pending, batch_size))
        report_status(args, 3, f"analyzing {len(batches)} batch(es) in current bottom-up layer")
        with ThreadPoolExecutor(max_workers=min(max_workers, len(batches))) as executor:
            futures = {
                executor.submit(call_ai_batch_with_retry, ai, [item[2] for item in batch], args): batch
                for batch in batches
            }
            for future in as_completed(futures):
                batch = futures[future]
                try:
                    results = future.result()
                except Exception as exc:
                    stats["failed"] += len(batch)
                    report_status(args, 3, f"AI batch failed: {exc}")
                    continue
                by_address = {normalize_address(result.get("address")): result for result in results}
                for index, func, _context in batch:
                    result = by_address.get(func["address"])
                    if not result:
                        stats["failed"] += 1
                        continue
                    report_status(args, 3, f"applying function {index}/{total}: {func['name']} ({func['address']})")
                    applied = apply_result(func["ea"], result, args)
                    for key, value in applied.items():
                        stats[key] += value
                    child_findings[func["ea"]] = {
                        "address": func["address"],
                        "original_name": func["name"],
                        "proposed_name": result.get("proposed_name"),
                        "summary": result.get("summary"),
                        "confidence": result.get("confidence") or 0,
                    }

    report_status(args, 4, "saving renamed and commented IDB")
    final_idb = save_database(args["output_idb"])
    cleanup_side_effect_databases(args, keep_paths=[final_idb])
    stats["output_idb"] = str(final_idb)
    Path(args["result_path"]).write_text(json.dumps(stats, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    report_status(args, 4, "IDB enrichment complete")
    idc.qexit(0)


def report_status(args, phase, message):
    path = args.get("status_path")
    if not path:
        return
    try:
        with Path(path).open("a", encoding="utf-8") as handle:
            handle.write(json.dumps({"timestamp": datetime.now(timezone.utc).isoformat(), "phase": phase, "message": message}) + "\n")
    except Exception:
        pass


def collect_functions():
    rows = []
    for ea in idautils.Functions():
        func = ida_funcs.get_func(ea)
        if not func:
            continue
        flags = int(func.flags)
        rows.append(
            {
                "ea": int(func.start_ea),
                "end_ea": int(func.end_ea),
                "address": f"0x{int(func.start_ea):x}",
                "name": ida_funcs.get_func_name(func.start_ea) or f"sub_{int(func.start_ea):X}",
                "is_library": bool(flags & ida_funcs.FUNC_LIB),
                "is_thunk": bool(flags & ida_funcs.FUNC_THUNK),
            }
        )
    return rows


def collect_calls(functions):
    starts = {func["ea"] for func in functions}
    calls = []
    for func in functions:
        seen = set()
        for head in idautils.Heads(func["ea"], func["end_ea"]):
            for target in idautils.CodeRefsFrom(head, False):
                callee = ida_funcs.get_func(target)
                if not callee:
                    continue
                callee_ea = int(callee.start_ea)
                if callee_ea in starts and callee_ea != func["ea"] and callee_ea not in seen:
                    seen.add(callee_ea)
                    calls.append((func["ea"], callee_ea))
    return calls


def is_target(func):
    if func["is_library"] or func["is_thunk"]:
        return False
    return is_placeholder_name(func["name"])


def is_placeholder_name(name):
    lowered = (name or "").lower()
    return lowered.startswith("sub_") or lowered.startswith("nullsub_") or lowered.startswith("j_sub_")


def bottom_up_groups(targets, calls):
    target_set = set(targets)
    edges = {ea: set() for ea in target_set}
    indegree = {ea: 0 for ea in target_set}
    for caller, callee in calls:
        if caller in target_set and callee in target_set and caller != callee:
            if caller not in edges[callee]:
                edges[callee].add(caller)
                indegree[caller] += 1
    ready = sorted(ea for ea, degree in indegree.items() if degree == 0)
    groups = []
    seen = set()
    while ready:
        layer = ready
        ready = []
        groups.append(layer)
        for ea in layer:
            seen.add(ea)
            for parent in sorted(edges.get(ea, ())):
                indegree[parent] -= 1
                if indegree[parent] == 0:
                    ready.append(parent)
    remaining = sorted(target_set - seen)
    if remaining:
        groups.append(remaining)
    return groups


def build_context(func, calls, child_findings):
    pseudocode, variables = decompile_text_and_vars(func["ea"])
    return {
        "function": {"address": func["address"], "name": func["name"], "size": max(0, func["end_ea"] - func["ea"])},
        "pseudocode": pseudocode,
        "disassembly": "" if pseudocode else disassembly_text(func),
        "variables": variables,
        "callees": [f"0x{callee:x}" for caller, callee in calls if caller == func["ea"]],
        "callers": [f"0x{caller:x}" for caller, callee in calls if callee == func["ea"]],
        "child_findings": [child_findings[callee] for caller, callee in calls if caller == func["ea"] and callee in child_findings],
    }


def decompile_text_and_vars(ea):
    variables = []
    try:
        if ida_hexrays.init_hexrays_plugin():
            cfunc = ida_hexrays.decompile(ea)
            if cfunc:
                for lvar in cfunc.get_lvars():
                    if lvar.name:
                        variables.append(str(lvar.name))
                return str(cfunc), variables
    except Exception:
        pass
    return "", variables


def disassembly_text(func):
    lines = []
    for head in idautils.Heads(func["ea"], func["end_ea"]):
        if len(lines) >= 120:
            lines.append("; [TRUNCATED]")
            break
        text = ida_lines.generate_disasm_line(head, 0) or ""
        text = ida_lines.tag_remove(text)
        if text:
            lines.append(f"{int(head):x}: {text}")
    return "\n".join(lines)


def call_ai_batch_with_retry(ai, contexts, args):
    max_retries = int(ai.get("max_retries") or 2)
    cooldown = max(180, int(ai.get("rate_limit_cooldown_seconds") or 180))
    last_error = None
    for retry in range(max_retries + 1):
        try:
            return call_ai_batch(ai, contexts, args)
        except Exception as exc:
            last_error = exc
            if retry >= max_retries:
                break
            wait = retry_after_seconds(exc) or cooldown if is_rate_limited(exc) else min(64, 2 ** retry)
            report_status(args, 3, f"rate limited; waiting {int(wait)}s before retry" if is_rate_limited(exc) else f"AI error; retrying in {int(wait)}s")
            time.sleep(wait)
    raise last_error


def call_ai_batch(ai, contexts, args):
    provider = (ai.get("provider") or "openai").lower()
    if provider == "disabled":
        raise RuntimeError("AI provider is disabled")
    if provider == "anthropic":
        return call_anthropic(ai, contexts, args)
    return call_openai_compatible(ai, contexts, args)


def build_prompt(contexts, args):
    if args.get("function_rename_only"):
        return json.dumps(
            {
                "task": "Analyze IDA functions and return proposed function names only.",
                "instructions": [
                    "Return JSON only with a top-level results array.",
                    "Return exactly one result for each input function address.",
                    "Use concise snake_case function names.",
                    "Do not preserve sub_ names.",
                    "Do not return variable renames.",
                    "Do not return function comments or explanations.",
                ],
                "result_shape": {
                    "results": [
                        {
                            "address": "0x...",
                            "proposed_name": "snake_case_or_null",
                            "confidence": 0.0,
                        }
                    ]
                },
                "contexts": contexts,
            },
            sort_keys=True,
        )
    return json.dumps(
        {
            "task": "Analyze IDA functions and return proposed names, comments, and variable renames.",
            "instructions": [
                "Return JSON only with a top-level results array.",
                "Return exactly one result for each input function address.",
                "Use concise snake_case function and variable names.",
                "Do not preserve sub_ names.",
                "Variable original names must exactly match IDA decompiler local variable names.",
            ],
            "result_shape": {
                "results": [
                    {
                        "address": "0x...",
                        "proposed_name": "snake_case_or_null",
                        "summary": "short function comment",
                        "confidence": 0.0,
                        "variables": [{"original": "v1", "proposed": "buffer_len", "confidence": 0.0, "evidence": "why"}],
                    }
                ]
            },
            "contexts": contexts,
        },
        sort_keys=True,
    )


def call_openai_compatible(ai, contexts, args):
    provider = (ai.get("provider") or "openai").lower()
    base_url = ai.get("base_url") or {
        "openai": "https://api.openai.com/v1",
        "lmstudio": "http://localhost:1234/v1",
        "ollama": "http://localhost:11434/v1",
        "hermes": "http://localhost:8080/v1",
        "openai-compatible": "",
    }.get(provider, "")
    if not base_url:
        raise RuntimeError("base_url is required for openai-compatible provider")
    key = ai.get("api_key") or os.environ.get("REAI_AI_API_KEY") or os.environ.get("OPENAI_API_KEY") or ("ollama" if provider == "ollama" else "reai-local")
    payload = {
        "model": ai.get("model"),
        "messages": [
            {"role": "system", "content": "You are a malware reverse-engineering assistant. Return JSON only."},
            {"role": "user", "content": build_prompt(contexts, args)},
        ],
        "temperature": 0,
        "response_format": {"type": "json_object"},
    }
    data = http_json(
        base_url.rstrip("/") + "/chat/completions",
        payload,
        {
            "Authorization": f"Bearer {key}",
            "Content-Type": "application/json",
        },
        int(ai.get("timeout_seconds") or 120),
    )
    content = data["choices"][0]["message"]["content"]
    return parse_results(content)


def call_anthropic(ai, contexts, args):
    key = ai.get("api_key") or os.environ.get("REAI_AI_API_KEY") or os.environ.get("ANTHROPIC_API_KEY")
    if not key:
        raise RuntimeError("Anthropic API key is required")
    base_url = (ai.get("base_url") or "https://api.anthropic.com").rstrip("/")
    payload = {
        "model": ai.get("model"),
        "max_tokens": 12000,
        "temperature": 0,
        "system": "You are a malware reverse-engineering assistant. Return JSON only.",
        "messages": [{"role": "user", "content": build_prompt(contexts, args)}],
    }
    data = http_json(
        base_url + "/v1/messages",
        payload,
        {
            "x-api-key": key,
            "anthropic-version": "2023-06-01",
            "Content-Type": "application/json",
        },
        int(ai.get("timeout_seconds") or 120),
    )
    content = "\n".join(block.get("text", "") for block in data.get("content", []) if block.get("type") == "text")
    return parse_results(content)


def http_json(url, payload, headers, timeout):
    request = urllib.request.Request(url, data=json.dumps(payload).encode("utf-8"), headers=headers, method="POST")
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return json.loads(response.read().decode("utf-8", "replace"))
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", "replace")
        wrapped = RuntimeError(f"HTTP {exc.code}: {body}")
        wrapped.headers = exc.headers
        raise wrapped


def parse_results(content):
    start = content.find("{")
    end = content.rfind("}")
    if start == -1 or end == -1 or end <= start:
        raise RuntimeError("AI response did not contain JSON")
    data = json.loads(content[start : end + 1])
    results = data.get("results")
    if not isinstance(results, list):
        raise RuntimeError("AI response missing results array")
    return results


def apply_result(ea, result, args):
    stats = {"function_renames": 0, "variable_renames": 0, "comments": 0, "failed": 0}
    current = ida_funcs.get_func_name(ea) or f"sub_{ea:X}"
    proposed = sanitize_identifier(result.get("proposed_name") or "")
    if proposed and is_placeholder_name(current):
        proposed = unique_name(proposed, ea)
        if ida_name.set_name(ea, proposed, ida_name.SN_NOWARN | ida_name.SN_FORCE):
            stats["function_renames"] += 1
        else:
            stats["failed"] += 1
    if args.get("function_rename_only"):
        try:
            ida_hexrays.mark_cfunc_dirty(ea)
        except Exception:
            pass
        return stats
    summary = str(result.get("summary") or "").strip()
    if summary:
        func = ida_funcs.get_func(ea)
        existing = ida_funcs.get_func_cmt(func, False) if func else ""
        managed = f"{args.get('comment_marker_begin')}\nPurpose: {summary}\nConfidence: {float(result.get('confidence') or 0):.2f}\n{args.get('comment_marker_end')}"
        ida_funcs.set_func_cmt(func, merge_comment(existing or "", managed, args.get("comment_marker_begin"), args.get("comment_marker_end")), False)
        stats["comments"] += 1
    for var in result.get("variables") or []:
        old = clean_var(var.get("original"))
        new = sanitize_identifier(var.get("proposed") or "")
        if old and new and rename_lvar(ea, old, new):
            stats["variable_renames"] += 1
    try:
        ida_hexrays.mark_cfunc_dirty(ea)
    except Exception:
        pass
    return stats


def rename_lvar(ea, old, new):
    try:
        if ida_hexrays.init_hexrays_plugin() and ida_hexrays.rename_lvar(ea, old, new):
            return True
    except Exception:
        return False
    return False


def sanitize_identifier(value):
    name = re.sub(r"[^A-Za-z0-9_]", "_", str(value or ""))
    name = re.sub(r"_+", "_", name).strip("_")
    if not name:
        return ""
    if not re.match(r"^[A-Za-z_]", name):
        name = "fn_" + name
    if name.lower().startswith("sub_"):
        name = name[4:]
    return name[:96]


def clean_var(value):
    if not value:
        return ""
    text = str(value).strip()
    if ":" in text:
        text = text.split(":", 1)[0]
    if "(" in text:
        text = text.split("(", 1)[0]
    match = re.search(r"[A-Za-z_][A-Za-z0-9_]*", text)
    return match.group(0) if match else ""


def unique_name(base, ea):
    if idc.get_name_ea_simple(base) in (ida_idaapi.BADADDR, ea):
        return base
    suffix = 2
    while True:
        tail = f"_{suffix}"
        candidate = f"{base[: 96 - len(tail)]}{tail}"
        if idc.get_name_ea_simple(candidate) in (ida_idaapi.BADADDR, ea):
            return candidate
        suffix += 1


def merge_comment(existing, managed, begin, end):
    pattern = re.compile(rf"\n?{re.escape(begin)}.*?{re.escape(end)}\n?", re.DOTALL)
    cleaned = pattern.sub("\n", existing or "").strip()
    return f"{cleaned}\n\n{managed}".strip() if cleaned else managed


def save_database(output_idb):
    requested = Path(output_idb)
    output = str(requested)
    try:
        ida_loader.save_database(output, ida_loader.DBFL_COMP)
    except Exception:
        ida_loader.save_database(output, 0)
    return ensure_requested_database_path(requested)


def ensure_requested_database_path(requested):
    requested = Path(requested)
    if requested.exists():
        return requested

    candidates = [
        requested.with_suffix(".i64"),
        requested.with_suffix(".idb"),
        requested.parent / f"{requested.name}.i64",
        requested.parent / f"{requested.stem}.i64",
    ]
    try:
        current_idb = idc.get_idb_path()
        if current_idb:
            candidates.append(Path(current_idb))
    except Exception:
        pass

    for candidate in candidates:
        try:
            if candidate.resolve() == requested.resolve():
                continue
            if candidate.is_file():
                shutil.copy2(candidate, requested)
                try:
                    candidate.unlink()
                except Exception:
                    pass
                return requested
        except Exception:
            continue

    raise RuntimeError(f"IDA did not create requested database path: {requested}")


def cleanup_side_effect_databases(args, keep_paths=None):
    sample = Path(args["sample_path"])
    output = Path(args["output_idb"]).resolve()
    keep = {sample.resolve(), output}
    for path in keep_paths or []:
        try:
            keep.add(Path(path).resolve())
        except Exception:
            pass
    candidates = [
        sample.with_suffix(".i64"),
        sample.with_suffix(".idb"),
        sample.parent / f"{sample.name}.i64",
        sample.parent / f"{sample.name}.idb",
    ]
    for ext in (".id0", ".id1", ".id2", ".nam", ".til"):
        candidates.append(sample.with_suffix(ext))
        candidates.append(sample.parent / f"{sample.name}{ext}")
    for path in set(candidates):
        try:
            if path.resolve() not in keep and path.is_file():
                path.unlink()
        except Exception:
            pass


def normalize_address(value):
    try:
        if isinstance(value, str):
            return f"0x{int(value, 16):x}"
        return f"0x{int(value):x}"
    except Exception:
        return str(value or "").lower()


def chunks(items, size):
    return [items[index : index + size] for index in range(0, len(items), size)]


def is_rate_limited(exc):
    text = str(exc).lower()
    return "429" in text or "rate limit" in text or "too many" in text


def retry_after_seconds(exc):
    headers = getattr(exc, "headers", None)
    if headers:
        for key in ("Retry-After", "retry-after"):
            try:
                value = headers.get(key)
                if value:
                    return max(1, float(value))
            except Exception:
                pass
    match = re.search(r"retry(?:\s|-)?after[^\d]*(\d+(?:\.\d+)?)", str(exc), re.I)
    return max(1, float(match.group(1))) if match else None


if __name__ == "__main__":
    try:
        main()
    except Exception:
        try:
            fail_path = Path(os.environ.get("TEMP") or "/tmp") / "reai_enrichidb_native_failure.txt"
            fail_path.write_text(traceback.format_exc(), encoding="utf-8")
        except Exception:
            pass
        try:
            idc.qexit(1)
        except Exception:
            sys.exit(1)
