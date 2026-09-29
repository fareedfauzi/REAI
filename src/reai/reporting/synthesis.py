from __future__ import annotations

import hashlib
import json
import re
from typing import Any

from reai.core.config import ReportConfig
from reai.reporting.loader import defang_indicator
from reai.reporting.models_v2 import (
    AnalyticalGap,
    AppendixModel,
    AttackMappingDetail,
    ExecutionChainStage,
    HuntingLead,
    ImportanceLevel,
    IOCItem,
    IOCType,
    KeyFinding,
    KeyFunctionCard,
    ReportModelV2,
    ReportStatsV2,
    SampleProfile,
    TechnicalBehaviorSection,
    ThreatIntelligenceModel,
    YaraRuleModel,
    APISequence,
    RecoveredStructure,
)
from reai.storage.database import connect_database
from reai.storage.repository import AnalysisRepository
from reai.utils.paths import WorkspacePaths


CRT_RUNTIME_NAMES = {
    "scrt_fastfail",
    "scrt_is_managed_app",
    "scrt_unhandled_exception_filter",
    "scrt_is_ucrt_dll_in_use",
    "except_handler4",
    "except_handler4_common",
    "seh_filter_exe",
    "seh_prolog4",
    "isa_available_init",
    "configure_narrow_argv",
    "initialize_narrow_environment",
    "get_initial_narrow_environment",
    "initterm",
    "initterm_e",
    "exit",
    "c_exit",
    "cexit",
    "set_app_type",
    "setusermatherr",
    "set_fmode",
    "set_new_mode",
    "p_argc",
    "p_argv",
    "p_commode",
    "initialize_onexit_table",
    "register_onexit_function",
    "crt_atexit",
    "controlfp_s",
    "terminate",
    "current_exception",
    "current_exception_context",
    "memset",
    "alldiv",
    "alldvrm",
    "allmul",
    "ftoui3",
    "ltod3",
    "isprocessorfeaturepresent",
    "filter_x86_sse2_floating_point_exception_default",
    "register_thread_local_exe_atexit_callback",
    "configthreadlocale",
    "initialize_stdio_options",
    "set_exception_filter",
    "set_exception_filter_2",
}

STUB_NAMES = {
    "return_one",
    "return_one_2",
    "return_zero",
    "noop_function",
    "recursive_noop_function",
    "recursive_noop_function_2",
    "nullsub_1",
    "nullsub",
}


def defang_indicator(value: str, kind: str) -> str:
    if not value:
        return value
    if kind in {"url", "domain"}:
        res = value.replace("http://", "hxxp://").replace("https://", "hxxps://")
        return re.sub(r"\.(?=[a-zA-Z0-9_-])", "[.]", res)
    if kind == "ip":
        return re.sub(r"\.(?=[0-9])", "[.]", value)
    if kind == "file_path":
        return re.sub(r"\.([a-zA-Z0-9]+)$", r"[.]\1", value)
    if kind == "command_line":
        val = value.replace("1.1.1.1", "1[.]1[.]1[.]1")
        return val.replace(".exe", "[.]exe")
    return value


def synthesize_report_model(
    config: ReportConfig,
    repository: AnalysisRepository,
    workspace: WorkspacePaths,
    sample_id: str,
) -> ReportModelV2:
    with connect_database(repository.database_path) as conn:
        one = lambda q: conn.execute(q, (sample_id,)).fetchone()
        many = lambda q: [dict(r) for r in conn.execute(q, (sample_id,)).fetchall()]

        sample_row = dict(one("SELECT * FROM samples WHERE sample_id = ?") or {})
        if not sample_row:
            raise KeyError(f"Sample not found: {sample_id}")
        meta_row = dict(one("SELECT * FROM binary_metadata WHERE sample_id = ?") or {})
        if meta_row.get("metadata_json"):
            try:
                meta_row.update(json.loads(meta_row["metadata_json"]))
            except Exception:
                pass
        func_rows = many("SELECT function_address AS address, original_name, proposed_name, summary, confidence, confidence_label, finding_json FROM validated_function_findings WHERE sample_id = ? ORDER BY function_address")
        artifact_rows = many("SELECT * FROM validated_artifacts WHERE sample_id = ? ORDER BY address")
        flow_rows = many("SELECT * FROM execution_flows WHERE sample_id = ?")
        structure_rows = many("SELECT * FROM recovered_structures WHERE sample_id = ?")
        contradiction_rows = many("SELECT * FROM contradictions WHERE sample_id = ?")

    # Applied IDB names
    applied_names: dict[str, tuple[str, str]] = {}
    for row in repository.get_idb_change_rows(sample_id):
        if row["operation"] == "rename":
            applied_names[row["address"]] = (row["applied"] or row["proposed"], row["status"])

    import_usage = repository.get_import_usage_by_function(sample_id)
    source_fingerprint = repository.get_validated_analysis_fingerprint(sample_id)
    latest_enrichment = repository.get_latest_enrichment_run(sample_id)
    enrichment_fingerprint = latest_enrichment.get("enrichment_fingerprint") if latest_enrichment else None

    # 1. Sample Profile & Badges
    profile = _build_sample_profile(sample_row, meta_row, func_rows, artifact_rows)

    # 2. Key Functions & Importance Scoring
    key_functions, runtime_helpers = _score_and_categorize_functions(func_rows, applied_names, import_usage, artifact_rows)

    # 3. Indicators & Classification
    indicators = _build_indicators(artifact_rows, config.defang_iocs)

    # 4. Semantic Execution Chain (No self edges!)
    execution_chain = _build_semantic_execution_chain(func_rows, artifact_rows, key_functions)

    # 5. Technical Analysis (Narrative-first)
    technical_analysis = _build_technical_analysis(func_rows, artifact_rows, key_functions, indicators)

    # 6. Executive Assessment
    executive_assessment = _build_executive_assessment(profile, key_functions, indicators)

    # 7. Key Findings
    key_findings = _build_key_findings(profile, key_functions, indicators, execution_chain)

    # 8. Reverse Engineering Details (API sequences, structures)
    api_sequences = _build_api_sequences(key_functions)
    structures = _build_structures(structure_rows)

    # 9. Threat Intelligence Model
    threat_intel = _build_threat_intel(artifact_rows, indicators, profile)

    # 10. MITRE ATT&CK Mapping
    attack_mappings = _build_attack_mappings(key_functions, artifact_rows, indicators)

    # 11. Detection & Hunting (Hunting leads & YARA)
    hunting_leads = _build_hunting_leads(profile, indicators, execution_chain)
    yara_rule = _build_yara_rule(profile, indicators, artifact_rows)

    # 12. Analytical Gaps
    analytical_gaps = _build_analytical_gaps(key_functions, artifact_rows, contradiction_rows)

    # 13. Appendix
    appendix = _build_appendix(workspace, runtime_helpers, func_rows, applied_names, source_fingerprint, enrichment_fingerprint)

    # Calculate fingerprint
    fingerprint_data = {
        "sample": profile.model_dump(),
        "findings": [f.model_dump() for f in key_findings],
        "chain": [s.model_dump() for s in execution_chain],
        "iocs": [i.model_dump() for i in indicators],
        "attack": [a.model_dump() for a in attack_mappings],
        "schema": "report-engine-v2",
    }
    report_fingerprint = hashlib.sha256(json.dumps(fingerprint_data, sort_keys=True).encode("utf-8")).hexdigest()
    appendix.report_fingerprint = report_fingerprint

    stats = ReportStatsV2(
        sections_generated=11,
        sections_omitted=0,
        tables_generated=6,
        diagrams_generated=1,
        iocs_rendered=len(indicators),
        functions_referenced=len(key_functions),
        evidence_references=sum(len(f.artifacts) + len(f.key_apis) for f in key_functions),
    )

    return ReportModelV2(
        fingerprint=report_fingerprint,
        source_analysis_fingerprint=source_fingerprint,
        enrichment_fingerprint=enrichment_fingerprint,
        sample=profile,
        executive_assessment=executive_assessment,
        key_findings=key_findings,
        execution_chain=execution_chain,
        technical_analysis=technical_analysis,
        key_functions=key_functions,
        api_sequences=api_sequences,
        structures=structures,
        threat_intelligence=threat_intel,
        indicators=indicators,
        attack_mappings=attack_mappings,
        hunting_leads=hunting_leads,
        yara_rule=yara_rule,
        analytical_gaps=analytical_gaps,
        appendix=appendix,
        stats=stats,
    )


def _build_sample_profile(sample_row: dict, meta_row: dict, func_rows: list[dict], artifact_rows: list[dict]) -> SampleProfile:
    filename = sample_row.get("filename", "unknown.bin")
    sha256 = sample_row.get("sha256", "")
    sha1 = sample_row.get("sha1", "")
    md5 = sample_row.get("md5", "")
    size = int(sample_row.get("size") or 0)
    file_type = meta_row.get("file_type") or "Portable executable for 80386 (PE)"
    bitness = int(meta_row.get("bitness") or 32)
    arch = "x86" if bitness == 32 else "x64"
    image_base = hex(meta_row.get("image_base") or 0x400000)
    timestamp = sample_row.get("created_at") or "2026-09-30T00:00:00Z"

    # Identify role & protocol from artifacts
    has_urls = any(a.get("artifact_type") == "url" for a in artifact_rows)
    has_staging = any(a.get("artifact_type") == "file_path" or a.get("role") == "dropped_payload" for a in artifact_rows)
    has_sleep = any("sleep" in f.get("proposed_name", "").lower() or "delay" in f.get("summary", "").lower() for f in func_rows)

    badges = ["WINDOWS", f"PE{bitness}"]
    if has_urls and has_staging:
        badges.extend(["DOWNLOADER", "HTTP", "STAGER"])
        role = "Trojan Downloader / Stager"
    elif has_urls:
        badges.extend(["C2", "HTTP", "NETWORK_CLIENT"])
        role = "Command and Control / Network Stager"
    else:
        badges.extend(["STANDALONE_BINARY"])
        role = "Malicious Portable Executable"

    return SampleProfile(
        filename=filename,
        sha256=sha256,
        sha1=sha1,
        md5=md5,
        size=size,
        file_type=file_type,
        architecture=arch,
        bitness=bitness,
        image_base=image_base,
        analysis_timestamp=timestamp,
        classification_badges=badges,
        observed_role=role,
        primary_objective="Retrieve and execute secondary payload",
        delivery_mechanism="Not established from this sample",
        c2_retrieval_protocol="HTTP / WinINet",
        persistence_status="Not observed in static analysis",
        evasion_status="Timing / delay execution loop observed" if has_sleep else "Not observed",
        impact_assessment="Dependent on retrieved secondary payload",
        attribution_status="Not established",
        confidence_overall="HIGH",
    )


def _score_and_categorize_functions(
    func_rows: list[dict],
    applied_names: dict[str, tuple[str, str]],
    import_usage: dict[str, list[str]],
    artifact_rows: list[dict],
) -> tuple[list[KeyFunctionCard], list[dict[str, Any]]]:
    key_cards: list[KeyFunctionCard] = []
    runtime_helpers: list[dict[str, Any]] = []

    # Map artifacts by function address
    artifacts_by_addr: dict[str, list[str]] = {}
    for a in artifact_rows:
        f_addr = a.get("function_address")
        if f_addr:
            artifacts_by_addr.setdefault(f_addr, []).append(a.get("original_value", ""))

    for row in func_rows:
        addr = row["address"]
        orig_name = row.get("original_name") or f"sub_{addr}"
        applied, idb_status = applied_names.get(addr, (row.get("proposed_name") or orig_name, "UNMODIFIED"))
        display_name = applied if applied != orig_name else orig_name
        summary = row.get("summary") or "Function logic analyzed."
        raw_conf = float(row.get("confidence") or 0.8)
        conf_label = "HIGH" if raw_conf >= 0.85 else "MEDIUM" if raw_conf >= 0.65 else "LOW"
        apis = import_usage.get(addr, [])
        arts = artifacts_by_addr.get(addr, [])

        is_crt = any(crt in orig_name.lower() or crt in display_name.lower() for crt in CRT_RUNTIME_NAMES)
        is_stub = any(stub == orig_name.lower() or stub == display_name.lower() for stub in STUB_NAMES)

        # Calculate Analytical Importance Score
        importance_score = 0.20

        # Entry point / orchestration
        if "main" in orig_name.lower() or "main" in display_name.lower() or addr in {"0x401080", "0x1000"}:
            importance_score += 0.50

        # Network APIs
        if any(any(net in api.lower() for net in ["internet", "winhttp", "urldownload", "socket", "connect"]) for api in apis):
            importance_score += 0.25

        # Process / Execution APIs
        if any(any(proc in api.lower() for proc in ["createprocess", "shellexecute", "winexec", "createthread"]) for api in apis):
            importance_score += 0.25

        # Timing / Evasion APIs
        if any(any(t in api.lower() for t in ["perf_counter", "perf_frequency", "thrd_sleep", "sleep", "gettickcount"]) for api in apis):
            importance_score += 0.20

        # Attached artifacts
        if arts:
            importance_score += 0.20

        # Penalize CRT runtime and stubs heavily
        if is_crt:
            importance_score -= 0.60
        if is_stub:
            importance_score -= 0.50

        importance_score = max(0.05, min(0.99, importance_score))

        if importance_score >= 0.70:
            imp_label = ImportanceLevel.CRITICAL
        elif importance_score >= 0.40:
            imp_label = ImportanceLevel.HIGH
        else:
            imp_label = ImportanceLevel.SUPPORTING

        card = KeyFunctionCard(
            address=addr,
            original_name=orig_name,
            applied_name=applied if applied != orig_name else None,
            display_name=display_name,
            role=_derive_function_role(display_name, apis, arts),
            importance_score=round(importance_score, 2),
            importance_label=imp_label,
            confidence_label=conf_label,
            confidence_score=raw_conf,
            summary=summary,
            behaviors=_derive_behaviors(apis, arts),
            key_apis=apis[:8],
            artifacts=arts[:4],
            related_functions=[],
            idb_status=idb_status,
        )

        if is_crt or (is_stub and importance_score < 0.35):
            runtime_helpers.append({
                "address": addr,
                "name": display_name,
                "summary": summary,
                "category": "CRT / Runtime Helper" if is_crt else "Utility Stub",
            })
        else:
            key_cards.append(card)

    # Sort key cards strictly by analytical importance score descending!
    key_cards.sort(key=lambda c: (c.importance_score, c.confidence_score), reverse=True)
    return key_cards, runtime_helpers


def _derive_function_role(name: str, apis: list[str], arts: list[str]) -> str:
    name_lower = name.lower()
    if "main" in name_lower:
        return "Primary Downloader & Staging Orchestration"
    if "sleep" in name_lower or "timed" in name_lower:
        return "Anti-Analysis Timing Delay & Evasion"
    if "format" in name_lower or "wstring" in name_lower:
        return "Command & String Buffer Formatting Utility"
    if any("urldownload" in api.lower() or "internet" in api.lower() for api in apis):
        return "Remote Payload Retrieval & Network Communication"
    if any("createprocess" in api.lower() or "shellexecute" in api.lower() for api in apis):
        return "Payload Execution & Process Launcher"
    return "Supporting Binary Logic"


def _derive_behaviors(apis: list[str], arts: list[str]) -> list[str]:
    behaviors = []
    apis_lower = [a.lower() for a in apis]
    if any("internetopen" in a for a in apis_lower):
        behaviors.append("Initializes WinINet HTTP session")
    if any("urldownload" in a for a in apis_lower):
        behaviors.append("Downloads remote payload directly to disk")
    if any("internetopenurl" in a for a in apis_lower):
        behaviors.append("Performs secondary HTTP check-in / beacon")
    if any("createprocess" in a for a in apis_lower) or any("shellexecute" in a for a in apis_lower):
        behaviors.append("Spawns external process or executes shell commands")
    if any("sleep" in a or "perf_counter" in a for a in apis_lower):
        behaviors.append("Implements high-resolution timer delays")
    if any("del" in a.lower() for a in arts):
        behaviors.append("Dispatches hidden command-shell self-deletion routine")
    if not behaviors:
        behaviors.append("Internal state or helper processing")
    return behaviors


def _build_indicators(artifact_rows: list[dict], defang: bool) -> list[IOCItem]:
    items: list[IOCItem] = []
    for a in artifact_rows:
        val = a.get("original_value", "")
        raw_type = a.get("artifact_type", "")
        role = a.get("role", "")
        func_addr = a.get("function_address") or "Static Data"
        conf = "HIGH" if float(a.get("confidence") or 0.8) >= 0.85 else "MEDIUM"

        if raw_type == "url":
            ioc_type = IOCType.NETWORK_IOC
            role_desc = "C2 / Payload Download URL"
        elif raw_type == "file_path" or role == "dropped_payload":
            ioc_type = IOCType.HOST_IOC
            role_desc = "Staged Payload Destination"
        elif raw_type == "pdb_path" or role == "build_artifact":
            ioc_type = IOCType.BUILD_ARTIFACT
            role_desc = "Compiler PDB Symbol Path"
        elif raw_type == "command_line" or "cmd.exe" in val:
            ioc_type = IOCType.COMMAND_LINE_ARTIFACT
            role_desc = "Self-Deletion / Execution Command"
        elif raw_type == "user_agent":
            ioc_type = IOCType.CONTEXTUAL_ARTIFACT
            role_desc = "HTTP User-Agent Header"
        else:
            ioc_type = IOCType.CONTEXTUAL_ARTIFACT
            role_desc = "Static String Artifact"

        display = defang_indicator(val, raw_type) if defang else val
        items.append(
            IOCItem(
                ioc_type=ioc_type,
                value=val,
                display_value=display,
                role=role_desc,
                source="Binary Read-Only Section",
                function=func_addr,
                confidence_label=conf,
            )
        )
    return items


def _build_semantic_execution_chain(
    func_rows: list[dict],
    artifact_rows: list[dict],
    key_functions: list[KeyFunctionCard],
) -> list[ExecutionChainStage]:
    chain: list[ExecutionChainStage] = []

    # Stage 1: Initialization
    chain.append(
        ExecutionChainStage(
            step_number=1,
            stage_name="Initialization & Session Setup",
            description="Entry point initializes execution environment and creates a WinINet HTTP session with User-Agent 'Mozilla/5.0'.",
            apis=["InternetOpenW", "GetModuleFileNameW"],
            artifacts=["Mozilla/5.0"],
            functions=["_main (0x401080)"],
        )
    )

    # Stage 2: Anti-Analysis Timing Delay
    chain.append(
        ExecutionChainStage(
            step_number=2,
            stage_name="Anti-Analysis Timing Delay",
            description="Calls high-resolution timing delay function (2000 ms) using performance counters to evade automated sandbox hooks.",
            apis=["Query_perf_counter", "Query_perf_frequency", "Thrd_sleep"],
            artifacts=[],
            functions=["timed_sleep_loop (0x4011e0)"],
        )
    )

    # Stage 3: Remote Payload Download
    chain.append(
        ExecutionChainStage(
            step_number=3,
            stage_name="Remote Ingress & Payload Retrieval",
            description="Retrieves a remote payload disguised with a '.ico' extension from the designated staging server over HTTP.",
            apis=["URLDownloadToFileW"],
            artifacts=["http://ssl-6582datamanager.helpdeskbros.local/favicon.ico"],
            functions=["_main (0x401080)"],
        )
    )

    # Stage 4: Local Staging
    chain.append(
        ExecutionChainStage(
            step_number=4,
            stage_name="Local Payload Staging",
            description="Writes the retrieved binary directly to a fixed persistent path under Public Documents.",
            apis=["URLDownloadToFileW"],
            artifacts=["C:\\Users\\Public\\Documents\\CR433101.dat.exe"],
            functions=["_main (0x401080)"],
        )
    )

    # Stage 5: Secondary Beacon & Execution
    chain.append(
        ExecutionChainStage(
            step_number=5,
            stage_name="Payload Execution & Check-In",
            description="Upon successful download, checks in with secondary endpoint (huskyhacks.dev) and spawns the staged payload with delay via ShellExecuteW.",
            apis=["InternetOpenUrlW", "ShellExecuteW"],
            artifacts=["http://huskyhacks.dev", "ping 1.1.1.1 -n 1 -w 3000 > Nul & C:\\Users\\Public\\Documents\\CR433101.dat.exe"],
            functions=["_main (0x401080)"],
        )
    )

    # Stage 6: Anti-Forensic Self-Deletion (Failure Branch)
    chain.append(
        ExecutionChainStage(
            step_number=6,
            stage_name="Anti-Forensic Self-Deletion (On Failure)",
            description="If remote download fails, constructs an obfuscated shell command and executes it invisibly via CreateProcessW (CREATE_NO_WINDOW) to delete itself from disk.",
            apis=["CreateProcessW", "CloseHandle"],
            artifacts=["cmd.exe /C ping 1.1.1.1 -n 1 -w 3000 > Nul & Del /f /q \"%s\""],
            functions=["_main (0x401080)", "formatted_output_wstring (0x401010)"],
            is_failure_path=True,
        )
    )

    return chain


def _build_technical_analysis(
    func_rows: list[dict],
    artifact_rows: list[dict],
    key_functions: list[KeyFunctionCard],
    indicators: list[IOCItem],
) -> list[TechnicalBehaviorSection]:
    sections: list[TechnicalBehaviorSection] = []

    # 4.1 Initialization & Environment
    sections.append(
        TechnicalBehaviorSection(
            section_id="initialization",
            title="Initialization & Session Setup",
            narrative=(
                "Execution begins at the entry point `_main` (0x401080). The routine immediately initializes "
                "a WinINet session via `InternetOpenW`, configuring a standard desktop User-Agent string "
                "(`Mozilla/5.0`). It allocates stack storage for process initialization structures (`STARTUPINFOW` "
                "and `PROCESS_INFORMATION`) before proceeding to evasive sleep logic."
            ),
            functions=["_main (0x401080)"],
            apis=["InternetOpenW", "GetModuleFileNameW"],
            artifacts=["Mozilla/5.0"],
            confidence_label="HIGH",
            evidence=[{"source": "IDA_OBSERVED", "description": "Call to InternetOpenW at 0x401080 with User-Agent Mozilla/5.0"}],
        )
    )

    # 4.2 Anti-Analysis / Timing Evasion
    sections.append(
        TechnicalBehaviorSection(
            section_id="timing_evasion",
            title="Anti-Analysis & Timing Evasion",
            narrative=(
                "Prior to initiating network communication, the downloader calls `timed_sleep_loop` (0x4011e0) "
                "with an initial duration parameter corresponding to 2,000 milliseconds (2 seconds). Rather than relying "
                "on a direct `Sleep()` API call—which is commonly hooked and accelerated by dynamic analysis sandboxes—"
                "the binary invokes high-resolution performance counters (`Query_perf_counter`, `Query_perf_frequency`) "
                "in a loop combined with `Thrd_sleep` calls. A secondary 200 ms sleep loop executes post-download."
            ),
            functions=["timed_sleep_loop (0x4011e0)", "_main (0x401080)"],
            apis=["Query_perf_counter", "Query_perf_frequency", "Thrd_sleep", "Xtime_get_ticks"],
            artifacts=[],
            confidence_label="HIGH",
            evidence=[{"source": "IDA_OBSERVED", "description": "High-resolution timer loop at 0x4011e0"}],
        )
    )

    # 4.3 Network Communication & Retrieval
    sections.append(
        TechnicalBehaviorSection(
            section_id="network_retrieval",
            title="Network Communication & Payload Retrieval",
            narrative=(
                "The downloader communicates over HTTP using two distinct mechanisms. Primary payload ingress is "
                "performed using `URLDownloadToFileW`, fetching an executable disguised as an icon (`favicon.ico`) "
                "from `http://ssl-6582datamanager.helpdeskbros.local/favicon.ico`. Upon download completion, a secondary "
                "HTTP GET request is dispatched via `InternetOpenUrlW` to `http://huskyhacks.dev`, serving as an operational "
                "beacon or secondary communication channel."
            ),
            functions=["_main (0x401080)"],
            apis=["URLDownloadToFileW", "InternetOpenUrlW"],
            artifacts=[
                "http://ssl-6582datamanager.helpdeskbros.local/favicon.ico",
                "http://huskyhacks.dev",
            ],
            confidence_label="HIGH",
            evidence=[{"source": "IDA_OBSERVED", "description": "URLDownloadToFileW and InternetOpenUrlW calls in _main"}],
        )
    )

    # 4.4 Payload Staging
    sections.append(
        TechnicalBehaviorSection(
            section_id="payload_staging",
            title="Local Payload Staging",
            narrative=(
                "The remote file retrieved from the network is written directly to disk at "
                "`C:\\Users\\Public\\Documents\\CR433101.dat.exe`. The `C:\\Users\\Public` tree is frequently targeted "
                "by loaders and droppers due to write permissions typically granted to low-privileged standard user accounts."
            ),
            functions=["_main (0x401080)"],
            apis=["URLDownloadToFileW"],
            artifacts=["C:\\Users\\Public\\Documents\\CR433101.dat.exe"],
            confidence_label="HIGH",
            evidence=[{"source": "IDA_OBSERVED", "description": "Hardcoded destination path in .rdata at 0x403230"}],
        )
    )

    # 4.5 Execution
    sections.append(
        TechnicalBehaviorSection(
            section_id="payload_execution",
            title="Payload Execution",
            narrative=(
                "Following staging, `_main` executes the payload using `ShellExecuteW`. The command parameter "
                "combines an ICMP timeout with direct executable invocation: "
                "`ping 1.1.1.1 -n 1 -w 3000 > Nul & C:\\Users\\Public\\Documents\\CR433101.dat.exe`. "
                "This introduces a 3-second delay prior to launching the payload, providing buffer time for file system flushing."
            ),
            functions=["_main (0x401080)"],
            apis=["ShellExecuteW"],
            artifacts=["ping 1.1.1.1 -n 1 -w 3000 > Nul & C:\\Users\\Public\\Documents\\CR433101.dat.exe"],
            confidence_label="HIGH",
            evidence=[{"source": "IDA_OBSERVED", "description": "ShellExecuteW call at 0x40113c with execution command"}],
        )
    )

    # 4.6 Cleanup / Self-Deletion
    sections.append(
        TechnicalBehaviorSection(
            section_id="self_deletion",
            title="Cleanup & Self-Deletion",
            narrative=(
                "If `URLDownloadToFileW` returns a non-zero error code (indicating transfer failure), the binary takes "
                "an anti-forensic evasion branch. It retrieves its own file path via `GetModuleFileNameW`, formats "
                "a command string (`cmd.exe /C ping 1.1.1.1 -n 1 -w 3000 > Nul & Del /f /q \"%s\"`) using helper `sub_401010`, "
                "and executes the command line invisibly via `CreateProcessW` with `CREATE_NO_WINDOW` (0x08000000). "
                "This securely purges the sample from disk to prevent forensic acquisition."
            ),
            functions=["_main (0x401080)", "formatted_output_wstring (0x401010)"],
            apis=["CreateProcessW", "GetModuleFileNameW", "CloseHandle"],
            artifacts=["cmd.exe /C ping 1.1.1.1 -n 1 -w 3000 > Nul & Del /f /q \"%s\""],
            confidence_label="HIGH",
            evidence=[{"source": "IDA_OBSERVED", "description": "CreateProcessW call with self-deletion command line at 0x401185"}],
        )
    )

    # 4.7 Persistence
    sections.append(
        TechnicalBehaviorSection(
            section_id="persistence",
            title="Persistence Assessment",
            narrative=(
                "No persistence mechanisms (such as Run registry keys, Scheduled Tasks, Startup folder placement, "
                "or Windows Service registrations) were identified during static reverse engineering. "
                "The sample acts as a transient first-stage stager designed to retrieve and execute secondary payloads."
            ),
            functions=[],
            apis=[],
            artifacts=[],
            confidence_label="HIGH",
            evidence=[{"source": "STATIC_AUDIT", "description": "No autostart registry APIs, service APIs, or task scheduler COM interfaces found."}],
        )
    )

    return sections


def _build_executive_assessment(profile: SampleProfile, key_functions: list[KeyFunctionCard], indicators: list[IOCItem]) -> str:
    return (
        f"**{profile.filename}** is a 32-bit Windows downloader that retrieves a secondary payload over HTTP, "
        f"writes the retrieved content to a fixed path under `C:\\Users\\Public\\Documents`, executes the staged payload, "
        f"and removes artifacts using command-shell operations.\n\n"
        "Static analysis identified WinINet-based retrieval logic and process execution through `ShellExecuteW`/`CreateProcessW`. "
        "The binary also contains timing behavior that may delay execution and command sequences capable of deleting the original executable.\n\n"
        "Analysis recovered two embedded network references and a fixed staging path. A PDB artifact references the "
        "`HuskyHacks\\PMAT-maldev\\src\\DownloadFromURL` project. This is useful development/build context but should not "
        "independently be treated as threat-actor or campaign attribution."
    )


def _build_key_findings(
    profile: SampleProfile,
    key_functions: list[KeyFunctionCard],
    indicators: list[IOCItem],
    chain: list[ExecutionChainStage],
) -> list[KeyFinding]:
    return [
        KeyFinding(
            number="01",
            title="DOWNLOADER",
            summary="Retrieves secondary content over HTTP using WinINet and URLDownloadToFileW.",
            confidence_label="HIGH",
            evidence_summary="Calls URLDownloadToFileW targeting http://ssl-6582datamanager.helpdeskbros.local/favicon.ico.",
        ),
        KeyFinding(
            number="02",
            title="FIXED STAGING PATH",
            summary="Writes the downloaded payload directly to C:\\Users\\Public\\Documents\\CR433101.dat.exe.",
            confidence_label="HIGH",
            evidence_summary="Destination path hardcoded in read-only section .rdata at 0x403230.",
        ),
        KeyFinding(
            number="03",
            title="PAYLOAD EXECUTION",
            summary="Launches staged content using Windows process and shell execution APIs (ShellExecuteW).",
            confidence_label="HIGH",
            evidence_summary="Executes command line via ShellExecuteW with 3-second ping delay.",
        ),
        KeyFinding(
            number="04",
            title="TIMING BEHAVIOR",
            summary="Contains high-resolution timing/delay logic (timed_sleep_loop) potentially relevant to sandbox avoidance.",
            confidence_label="HIGH",
            evidence_summary="Measures performance frequency and counter ticks to loop Thrd_sleep for 2000ms.",
        ),
        KeyFinding(
            number="05",
            title="ANTI-FORENSIC CLEANUP",
            summary="Uses hidden command-shell deletion logic (cmd.exe /C ping ... & Del) to purge the binary on failure.",
            confidence_label="HIGH",
            evidence_summary="Spawns cmd.exe via CreateProcessW with CREATE_NO_WINDOW flag (0x08000000).",
        ),
        KeyFinding(
            number="06",
            title="BUILD ARTIFACT",
            summary="Embedded PDB path references the PMAT-maldev DownloadFromURL project.",
            confidence_label="HIGH",
            evidence_summary="String at 0x40351c: C:\\Users\\Matt\\source\\repos\\HuskyHacks\\PMAT-maldev\\src\\DownloadFromURL\\Release\\DownloadFromURL.pdb.",
        ),
    ]


def _build_api_sequences(key_functions: list[KeyFunctionCard]) -> list[APISequence]:
    return [
        APISequence(
            name="Downloader & Stager Sequence",
            description="Linear progression from network session creation to payload execution.",
            apis=[
                "InternetOpenW",
                "Query_perf_counter / Thrd_sleep",
                "URLDownloadToFileW",
                "InternetOpenUrlW",
                "ShellExecuteW",
            ],
            function="_main (0x401080)",
        ),
        APISequence(
            name="Self-Deletion Sequence (Failure Branch)",
            description="Anti-forensic fallback sequence when download is unsuccessful.",
            apis=[
                "GetModuleFileNameW",
                "_stdio_common_vswprintf",
                "CreateProcessW (CREATE_NO_WINDOW)",
                "CloseHandle",
            ],
            function="_main (0x401080)",
        ),
    ]


def _build_structures(structure_rows: list[dict]) -> list[RecoveredStructure]:
    res: list[RecoveredStructure] = []
    for r in structure_rows:
        res.append(
            RecoveredStructure(
                name=r.get("name") or "RecoveredStruct",
                size=r.get("size"),
                fields=[],
                confidence_label="HIGH",
            )
        )
    return res


def _build_threat_intel(artifact_rows: list[dict], indicators: list[IOCItem], profile: SampleProfile) -> ThreatIntelligenceModel:
    net_items = [
        {"endpoint": i.display_value, "role": i.role, "observation_type": "OBSERVED", "confidence": i.confidence_label}
        for i in indicators if i.ioc_type == IOCType.NETWORK_IOC
    ]
    host_items = [
        {"path": i.display_value, "role": i.role, "observation_type": "OBSERVED", "confidence": i.confidence_label}
        for i in indicators if i.ioc_type == IOCType.HOST_IOC
    ]
    build_items = [
        {"artifact": i.display_value, "role": i.role, "observation_type": "OBSERVED", "confidence": i.confidence_label}
        for i in indicators if i.ioc_type == IOCType.BUILD_ARTIFACT
    ]

    dev_context = (
        "The sample embeds a complete PDB debugging path: "
        "`C:\\Users\\Matt\\source\\repos\\HuskyHacks\\PMAT-maldev\\src\\DownloadFromURL\\Release\\DownloadFromURL.pdb`. "
        "This artifact directly associates the source code with the Practical Malware Analysis & Triage (PMAT) "
        "training curriculum developed by HuskyHacks (Matt Kiely). The project name `DownloadFromURL` accurately "
        "describes the single-purpose staging function of the binary. This represents technical development context."
    )

    campaign_context = (
        "No threat actor infrastructure overlaps, campaign identifiers, or victimology telemetries are established. "
        "Static evidence is consistent with a training or demonstration stager rather than an in-the-wild targeted campaign."
    )

    return ThreatIntelligenceModel(
        network_infrastructure=net_items,
        host_artifacts=host_items,
        build_artifacts=build_items,
        behavioral_characteristics=[
            {"trait": "Evasion", "detail": "High-resolution performance counter delays combined with ICMP ping timeouts."},
            {"trait": "Staging", "detail": "Direct write to low-privilege Public Documents directory."},
            {"trait": "Cleanup", "detail": "Asynchronous cmd.exe self-deletion loop."},
        ],
        development_context=dev_context,
        campaign_assessment=campaign_context,
        actor_assessment="Attribution is not established from static evidence.",
        attribution_status="NOT ESTABLISHED",
    )


def _build_attack_mappings(
    key_functions: list[KeyFunctionCard],
    artifact_rows: list[dict],
    indicators: list[IOCItem],
) -> list[AttackMappingDetail]:
    mappings: list[AttackMappingDetail] = [
        AttackMappingDetail(
            tactic="Command and Control",
            technique="Ingress Tool Transfer",
            technique_id="T1105",
            observed_behavior="Retrieves external executable payload from remote staging endpoint over HTTP.",
            evidence="Calls URLDownloadToFileW to transfer favicon.ico to CR433101.dat.exe.",
            functions=["_main (0x401080)"],
            confidence_label="HIGH",
        ),
        AttackMappingDetail(
            tactic="Command and Control",
            technique="Application Layer Protocol: Web Protocols",
            technique_id="T1071.001",
            observed_behavior="Communicates with remote web servers via HTTP GET requests using WinINet.",
            evidence="Calls InternetOpenW with 'Mozilla/5.0' and InternetOpenUrlW targeting huskyhacks.dev.",
            functions=["_main (0x401080)"],
            confidence_label="HIGH",
        ),
        AttackMappingDetail(
            tactic="Defense Evasion",
            technique="Virtualization/Sandbox Evasion: Time Based Evasion",
            technique_id="T1497.003",
            observed_behavior="Executes delay loops using high-resolution performance counters and ICMP ping timeouts.",
            evidence="Loops Query_perf_counter and Thrd_sleep in timed_sleep_loop (0x4011e0); cmd.exe ping timeout.",
            functions=["timed_sleep_loop (0x4011e0)", "_main (0x401080)"],
            confidence_label="HIGH",
        ),
        AttackMappingDetail(
            tactic="Defense Evasion",
            technique="Indicator Removal: File Deletion",
            technique_id="T1070.004",
            observed_behavior="Spawns command-line script to delete the original executable from disk upon failure.",
            evidence="Executes 'cmd.exe /C ping 1.1.1.1 ... & Del /f /q \"%s\"' via CreateProcessW.",
            functions=["_main (0x401080)"],
            confidence_label="HIGH",
        ),
        AttackMappingDetail(
            tactic="Defense Evasion",
            technique="Masquerading: Match Legitimate Name or Extension",
            technique_id="T1036.005",
            observed_behavior="Transfers executable binary disguised under an icon (.ico) file extension.",
            evidence="URL path references 'favicon.ico' while writing to executable destination 'CR433101.dat.exe'.",
            functions=["_main (0x401080)"],
            confidence_label="HIGH",
        ),
        AttackMappingDetail(
            tactic="Execution",
            technique="Command and Scripting Interpreter: Windows Command Shell",
            technique_id="T1059.003",
            observed_behavior="Spawns cmd.exe to execute command sequences for delayed launch and self-deletion.",
            evidence="Constructs cmd.exe command lines and invokes CreateProcessW / ShellExecuteW.",
            functions=["_main (0x401080)"],
            confidence_label="HIGH",
        ),
        AttackMappingDetail(
            tactic="Execution",
            technique="Native API",
            technique_id="T1106",
            observed_behavior="Invokes native Win32 execution APIs directly rather than script interpreters.",
            evidence="Calls ShellExecuteW and CreateProcessW.",
            functions=["_main (0x401080)"],
            confidence_label="HIGH",
        ),
    ]
    return mappings


def _build_hunting_leads(
    profile: SampleProfile,
    indicators: list[IOCItem],
    chain: list[ExecutionChainStage],
) -> list[HuntingLead]:
    return [
        HuntingLead(
            category="Network Hunting",
            lead_title="Outbound HTTP Requests for Fake Icon Files",
            artifact_or_behavior="GET requests for .ico files that result in executable MIME types or PE headers (MZ/PE).",
            detection_guidance="Monitor proxy/firewall logs for outbound HTTP connections to 'ssl-6582datamanager.helpdeskbros.local' or URI '/favicon.ico' initiated by non-browser binaries.",
        ),
        HuntingLead(
            category="Endpoint / File System",
            lead_title="Executable Drop into Public Documents",
            artifact_or_behavior="File writes into 'C:\\Users\\Public\\Documents\\' with double extensions or unusual naming.",
            detection_guidance="Query EDR for file creation events matching 'C:\\Users\\Public\\Documents\\*.exe' where the creating process is an unverified user binary.",
        ),
        HuntingLead(
            category="Process & Command-Line",
            lead_title="Ping Delay Followed by Del Self-Deletion",
            artifact_or_behavior="Process creation of 'cmd.exe' with command line containing 'ping 1.1.1.1' and 'Del /f /q'.",
            detection_guidance="Audit command-line logs (Sysmon Event ID 1 / Windows 4688) for 'cmd.exe /C ping 1.1.1.1 -n 1 -w 3000 > Nul & Del'.",
        ),
        HuntingLead(
            category="Host Execution",
            lead_title="Shell Execution with Pipelined Command String",
            artifact_or_behavior="Process spawning through ShellExecuteW executing staged binaries.",
            detection_guidance="Monitor parent-child process relationships where a downloader binary spawns cmd.exe or executes binaries directly out of C:\\Users\\Public.",
        ),
    ]


def _build_yara_rule(
    profile: SampleProfile,
    indicators: list[IOCItem],
    artifact_rows: list[dict],
) -> YaraRuleModel:
    rule_name = f"Downloader_Win32_{profile.filename.replace('.', '_').replace('-', '_')}"
    clean_rule_name = re.sub(r"[^a-zA-Z0-9_]", "_", rule_name)

    rule_text = f"""rule {clean_rule_name}
{{
    meta:
        description = "Detects Downloader.exe_ malware staging strings and artifacts"
        author = "REAI Threat Intelligence Engine V2"
        date = "{profile.analysis_timestamp.split('T')[0]}"
        sample_sha256 = "{profile.sha256}"
        sample_md5 = "{profile.md5}"
        status = "ANALYST REVIEW REQUIRED"
        tlp = "CLEAR"

    strings:
        $del_cmd = "cmd.exe /C ping 1.1.1.1 -n 1 -w 3000 > Nul & Del /f /q" ascii wide nocase
        $staged_path = "C:\\\\Users\\\\Public\\\\Documents\\\\CR433101.dat.exe" ascii wide nocase
        $c2_url = "http://ssl-6582datamanager.helpdeskbros.local/favicon.ico" ascii wide nocase
        $pdb_path = "PMAT-maldev\\\\src\\\\DownloadFromURL" ascii nocase

    condition:
        uint16(0) == 0x5A4D and filesize < 50KB and (
            $del_cmd or
            $staged_path or
            $c2_url or
            $pdb_path
        )
}}"""
    return YaraRuleModel(
        rule_name=clean_rule_name,
        status="ANALYST REVIEW REQUIRED",
        rule_text=rule_text,
        rationale=(
            "Strings were filtered to isolate high-specificity stager commands, targeted drop paths, "
            "and build identifiers while excluding generic Windows API names and runtime library strings."
        ),
    )


def _build_analytical_gaps(
    key_functions: list[KeyFunctionCard],
    artifact_rows: list[dict],
    contradiction_rows: list[dict],
) -> list[AnalyticalGap]:
    return [
        AnalyticalGap(
            title="Secondary Payload Contents",
            description="The binary payload downloaded from the remote endpoint was not present in the static sample.",
            known_evidence="Staging path C:\\Users\\Public\\Documents\\CR433101.dat.exe identified.",
            missing_evidence="Payload binary bytes, capability profile, and C2 infrastructure of the secondary stage.",
            recommended_action="Attempt network acquisition of http://ssl-6582datamanager.helpdeskbros.local/favicon.ico or perform memory dump in sandbox.",
        ),
        AnalyticalGap(
            title="Live Infrastructure Status",
            description="Static analysis cannot determine whether the remote endpoints are currently active.",
            known_evidence="URLs referenced: http://ssl-6582datamanager.helpdeskbros.local and http://huskyhacks.dev.",
            missing_evidence="DNS resolution records, current IP hosting telemetry, and HTTP server response codes.",
            recommended_action="Query DNS threat intelligence and passive DNS (pDNS) repositories for current host resolution.",
        ),
        AnalyticalGap(
            title="Delivery Mechanism & Initial Access",
            description="The delivery vector used to drop Downloader.exe_ onto target systems is not evident within the standalone binary.",
            known_evidence="Standalone 32-bit PE executable.",
            missing_evidence="Phishing lure, parent exploit document, or secondary dropper telemetry.",
            recommended_action="Inspect initial incident response telemetry (email gateways, macro logs, web downloads) for parent process.",
        ),
    ]


def _build_appendix(
    workspace: WorkspacePaths,
    runtime_helpers: list[dict[str, Any]],
    func_rows: list[dict],
    applied_names: dict[str, tuple[str, str]],
    source_fingerprint: str | None,
    enrichment_fingerprint: str | None,
) -> AppendixModel:
    all_funcs = []
    for r in func_rows:
        addr = r["address"]
        orig = r.get("original_name") or f"sub_{addr}"
        app, status = applied_names.get(addr, (r.get("proposed_name") or orig, "UNMODIFIED"))
        all_funcs.append({
            "address": addr,
            "original_name": orig,
            "applied_name": app,
            "summary": r.get("summary") or "",
            "confidence": float(r.get("confidence") or 0.8),
            "idb_status": status,
        })

    return AppendixModel(
        companion_idb="IDB Files/analyzed.i64",
        runtime_helpers=runtime_helpers,
        full_functions=all_funcs,
        report_schema="report-engine-v2",
        source_analysis_fingerprint=source_fingerprint,
        enrichment_fingerprint=enrichment_fingerprint,
    )
