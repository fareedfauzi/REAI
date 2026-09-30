from __future__ import annotations

import json
import logging
from pathlib import Path

from openai import OpenAI

from reai.core.config import build_config
from reai.storage.repository import AnalysisRepository
from reai.utils.paths import WorkspacePaths
from reai.reporting.synthesis import synthesize_report_model
from reai.reporting.generator import ReportConfig

LOGGER = logging.getLogger(__name__)

SYSTEM_PROMPT = """You are writing the Technical Analysis section of a professional malware analysis report.

You are given validated analysis data from every analysis phase — bottom-up AI analysis, autonomous MCP investigation, semantic validation, raw extraction data, phase finding summaries, and curated analyst notebooks — alongside cleaned and original decompiled code.

Requirements:
- Synthesize ALL provided analysis data into a single cohesive narrative — do not just describe the code
- Explain WHAT the malware does, WHY each behavior matters (evasion, staging, persistence, execution, cleanup)
- Reference specific IOCs, APIs, configuration values, and MITRE ATT&CK techniques where relevant
- Incorporate MCP investigation findings and analyst notebook context to add depth
- Write in natural, well-structured paragraphs — no bullet points
- Keep the tone formal, direct, and readable — written for a security analyst audience
- Avoid robotic or AI-like phrasing: no "By using...", "This demonstrates...", "Essentially...", "Overall...", "It should be noted that...", "In order to..."
- Avoid redundant wording and repetitive sentence structures
- MUST include 1-3 short C code snippets (2-6 lines each) formatted with ```c markdown fences to demonstrate exactly how the malware achieves its critical behaviors. Pull these snippets directly from the provided Readable Code.
- Do not speculate beyond what the evidence supports
- Write in a style consistent with Mandiant, Google TAG, Kaspersky, or Elastic Security threat analysis reports"""


def _read_file_safe(path: Path, max_chars: int = 8000) -> str:
    """Read a file safely, returning empty string on failure."""
    try:
        if path.exists():
            content = path.read_text(encoding="utf-8", errors="replace").strip()
            return content[:max_chars] if len(content) > max_chars else content
    except Exception:
        pass
    return ""


def _read_json_safe(path: Path) -> list | dict | None:
    """Read a JSON file safely."""
    try:
        if path.exists():
            return json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except Exception:
        pass
    return None


def generate_ai_narrative(sample_id: str, workspace_root: Path | None = None) -> None:
    config = build_config()

    if workspace_root:
        workspace = WorkspacePaths.from_root(workspace_root)
        repository = AnalysisRepository(workspace.database)
    else:
        print("[-] workspace_root is required to locate the database.")
        return

    ai_config = config.ai
    if ai_config.provider == "anthropic":
        print("[-] This script currently only supports OpenAI compatible providers.")
        return

    base_url = None
    if ai_config.provider == "local":
        base_url = f"http://{ai_config.host}:{ai_config.port}/v1"

    client = OpenAI(
        api_key=ai_config.api_key or "sk-dummy",
        base_url=base_url
    )

    print(f"[*] Synthesizing report model for {sample_id}...")
    report_config = ReportConfig()
    model = synthesize_report_model(report_config, repository, workspace, sample_id)

    # Prefer CRITICAL/HIGH functions, fall back to top functions
    target_functions = [f for f in model.key_functions if f.importance_label in ("CRITICAL", "HIGH")]
    if not target_functions:
        target_functions = model.key_functions[:3]
    if not target_functions:
        print("[-] No key functions found to analyze.")
        return

    print(f"[*] Found {len(target_functions)} key functions. Building comprehensive analysis context...")

    sections: list[str] = []

    # ================================================================== #
    # ANALYSIS DATA — Database-derived structured intelligence
    # ================================================================== #

    # Phase 3: Bottom-up AI analysis
    phase3_lines = ["=== ANALYSIS DATA / PHASE 3: BOTTOM-UP AI FUNCTION ANALYSIS ==="]
    for fn in target_functions:
        phase3_lines.append(f"\nFunction: {fn.display_name} @ {fn.address}  [{fn.importance_label} / {fn.confidence_label}]")
        phase3_lines.append(f"  Summary   : {fn.summary}")
        if fn.behaviors:
            phase3_lines.append(f"  Behaviors : {'; '.join(fn.behaviors)}")
        if fn.key_apis:
            phase3_lines.append(f"  Key APIs  : {', '.join(fn.key_apis)}")
        if fn.artifacts:
            phase3_lines.append(f"  Artifacts : {', '.join(fn.artifacts)}")
    sections.append("\n".join(phase3_lines))

    # Phase 4: MCP investigation findings from DB
    mcp_lines = ["=== ANALYSIS DATA / PHASE 4: MCP INVESTIGATION FINDINGS ==="]
    try:
        for fn in target_functions:
            evidence_rows = repository.get_mcp_evidence_rows(sample_id, fn.address)
            for row in evidence_rows[:10]:
                content = str(row.get("content") or row.get("summary") or "").strip()
                if content and len(content) > 20:
                    mcp_lines.append(f"  [{fn.display_name}] {content[:400]}")
    except Exception:
        pass
    if len(mcp_lines) > 1:
        sections.append("\n".join(mcp_lines))

    # Phase 5: Validated IOCs
    ioc_lines = ["=== ANALYSIS DATA / PHASE 5: VALIDATED IOCs ==="]
    for ioc in model.indicators:
        ioc_type = ioc.ioc_type.value if hasattr(ioc.ioc_type, "value") else str(ioc.ioc_type)
        ioc_lines.append(f"  [{ioc_type}] {ioc.display_value}  —  {ioc.role}")
    if len(ioc_lines) > 1:
        sections.append("\n".join(ioc_lines))

    # Phase 5: Configuration items
    config_lines = ["=== ANALYSIS DATA / PHASE 5: VALIDATED CONFIGURATION ITEMS ==="]
    try:
        with repository._connect() as conn:
            cfg_rows = conn.execute(
                "SELECT key, value, confidence FROM configuration_items WHERE sample_id = ? ORDER BY confidence DESC",
                (sample_id,)
            ).fetchall()
            for row in cfg_rows[:10]:
                config_lines.append(f"  {row['key']}: {str(row['value'])!r}  (confidence {float(row['confidence']):.0%})")
    except Exception:
        pass
    if len(config_lines) > 1:
        sections.append("\n".join(config_lines))

    # Phase 5: MITRE ATT&CK
    attack_lines = ["=== ANALYSIS DATA / PHASE 5: MITRE ATT&CK MAPPINGS ==="]
    for mapping in model.attack_mappings[:6]:
        tech = getattr(mapping, "technique", None) or getattr(mapping, "technique_name", "")
        tactic = getattr(mapping, "tactic", "")
        tid = getattr(mapping, "technique_id", "")
        behavior = getattr(mapping, "observed_behavior", None) or getattr(mapping, "justification", "")
        attack_lines.append(f"  {tid}: {tech} [{tactic}]  —  {behavior}")
    if len(attack_lines) > 1:
        sections.append("\n".join(attack_lines))

    # Phase 5: Validated function findings (rename rationale + comments)
    findings_lines = ["=== ANALYSIS DATA / PHASE 5: VALIDATED FUNCTION FINDINGS ==="]
    try:
        findings_map = repository.get_validated_function_finding_rows(sample_id)
        for fn in target_functions:
            finding = findings_map.get(fn.address)
            if finding:
                comment = str(finding.get("comment") or "").strip()
                rationale = str(finding.get("rename_rationale") or "").strip()
                if comment:
                    findings_lines.append(f"  [{fn.display_name}] Comment: {comment}")
                if rationale:
                    findings_lines.append(f"  [{fn.display_name}] Rename rationale: {rationale}")
    except Exception:
        pass
    if len(findings_lines) > 1:
        sections.append("\n".join(findings_lines))

    # ================================================================== #
    # ANALYSIS FINDINGS — Pre-formatted per-phase markdown summaries
    # ================================================================== #
    findings_dir = workspace.findings

    # Analyst notebook (curated bridge document)
    notebook = _read_file_safe(findings_dir / "analyst-notebook.md", max_chars=6000)
    if notebook:
        sections.append(f"=== ANALYSIS FINDINGS / ANALYST NOTEBOOK ===\n{notebook}")

    # Phase 3 bottom-up AI findings summary
    p3_md = _read_file_safe(findings_dir / "phase-3-bottom-up-ai.md", max_chars=4000)
    if p3_md:
        sections.append(f"=== ANALYSIS FINDINGS / PHASE 3 SUMMARY ===\n{p3_md}")

    # Phase 4 MCP investigation findings summary
    p4_md = _read_file_safe(findings_dir / "phase-4-mcp-investigation.md", max_chars=3000)
    if p4_md:
        sections.append(f"=== ANALYSIS FINDINGS / PHASE 4 SUMMARY ===\n{p4_md}")

    # Phase 5 semantic validation findings summary
    p5_md = _read_file_safe(findings_dir / "phase-5-semantic-validation.md", max_chars=3000)
    if p5_md:
        sections.append(f"=== ANALYSIS FINDINGS / PHASE 5 SUMMARY ===\n{p5_md}")

    # Phase 6 IDB enrichment findings summary
    p6_md = _read_file_safe(findings_dir / "phase-6-idb-enrichment.md", max_chars=2000)
    if p6_md:
        sections.append(f"=== ANALYSIS FINDINGS / PHASE 6 ENRICHMENT SUMMARY ===\n{p6_md}")

    # ================================================================== #
    # RAW DATA — Strings, imports, exports with malware-relevant filtering
    # ================================================================== #
    raw_dir = workspace.raw

    # Meaningful strings (non-trivial, skip CRT noise)
    strings_data = _read_json_safe(raw_dir / "strings.json")
    if strings_data:
        raw_strings = strings_data if isinstance(strings_data, list) else strings_data.get("strings", [])
        meaningful = [
            s.get("value", "") for s in raw_strings
            if isinstance(s, dict)
            and len(s.get("value", "")) > 6
            and not s.get("value", "").startswith("_")
            and not s.get("value", "").startswith("api-ms-win")
            and s.get("referencing_functions")
        ][:30]
        if meaningful:
            sections.append(f"=== RAW DATA / REFERENCED STRINGS (filtered) ===\n" + "\n".join(f"  {v}" for v in meaningful))

    # Imports
    imports_data = _read_json_safe(raw_dir / "imports.json")
    if imports_data:
        imp_list = imports_data if isinstance(imports_data, list) else imports_data.get("imports", [])
        imp_names = [f"  {i.get('module','')}.{i.get('name','')}" for i in imp_list if isinstance(i, dict)][:40]
        if imp_names:
            sections.append(f"=== RAW DATA / IMPORTS ===\n" + "\n".join(imp_names))

    # ================================================================== #
    # READABLE CODE + ORIGINAL DECOMPILED CODE
    # ================================================================== #

    # AI readable C rewrite
    readable_blocks = []
    for fn in target_functions:
        readable_path = workspace.readable_code / f"{fn.address}.c"
        if readable_path.exists():
            readable_content = readable_path.read_text(encoding="utf-8", errors="replace").strip()
            readable_blocks.append(f"// {fn.display_name} @ {fn.address} [AI readable rewrite]\n{readable_content}")
    if readable_blocks:
        sections.append(f"=== READABLE CODE / AI REWRITE ===\n```c\n" + "\n\n".join(readable_blocks) + "\n```")

    # Original decompiled pseudocode (or ASM fallback)
    code_blocks = []
    for fn in target_functions:
        if fn.original_decompiled_code:
            code_blocks.append(f"// {fn.display_name} @ {fn.address}\n{fn.original_decompiled_code}")
    if code_blocks:
        sections.append(f"=== EXTRACTED CODES / ORIGINAL DECOMPILED CODE ===\n```c\n" + "\n\n".join(code_blocks) + "\n```")

    # ================================================================== #
    # Assemble final context
    # ================================================================== #
    analysis_context = "\n\n".join(sections)
    full_code = "\n\n".join(code_blocks)  # needed for flow tree prompt

    prompt = (
        "Use ALL of the following validated analysis data gathered across every analysis phase "
        "to write a comprehensive, analyst-grade Technical Analysis section:\n\n"
        f"{analysis_context}\n\n"
        "Write the full Technical Analysis now."
    )

    print(f"[*] Sending {len(sections)} context sections to AI for narrative generation...")

    # ================================================================== #
    # Call 1: Technical Analysis Narrative
    # ================================================================== #
    try:
        response = client.chat.completions.create(
            model=ai_config.model,
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": prompt},
            ],
            temperature=0.2,
        )
        result = response.choices[0].message.content
        if result:
            out_path = workspace.analysis / "ai_narrative.md"
            out_path.write_text(result.strip(), encoding="utf-8")
            print(f"[+] Saved AI technical narrative to {out_path}")
        else:
            print("[-] No response from AI for narrative.")
            return
    except Exception as e:
        print(f"[-] Error generating narrative: {e}")
        return

    # ================================================================== #
    # Call 2: High-level Execution Flow Tree
    # ================================================================== #
    fn_name = target_functions[0].display_name if target_functions else "main_function"
    flow_prompt = (
        f"Based on the following validated malware analysis data, generate a concise high-level execution flow tree.\n\n"
        f"Rules:\n"
        f"- Use tree notation: |-- for intermediate steps, `-- for the final step\n"
        f"- Each step must describe WHAT happens and WHY it matters in plain English\n"
        f"- Reflect real attacker behavior — staging, evasion, execution, cleanup\n"
        f"- Do NOT use raw API names as steps — translate them to behavioral meaning\n"
        f"- Do NOT list artifacts (URLs, paths, commands) as standalone steps\n"
        f"- Each step is one clear, concise sentence\n"
        f"- Always start with: |-- Start {fn_name}\n"
        f"- Always end with: `-- End function\n"
        f"- 5-8 steps total\n\n"
        f"GOOD example:\n"
        f"|-- Start main_execution_handler\n"
        f"|-- Spoofs a browser identity to open an internet session and evade simple network filters\n"
        f"|-- Downloads a staged payload to a publicly accessible user directory\n"
        f"|-- Delays self-deletion with a timed network ping to outlast short-lived sandbox analysis\n"
        f"|-- Spawns the payload as a child process using a native Windows API\n"
        f"|-- Wipes the dropper from disk and falls back to ShellExecute if process creation fails\n"
        f"`-- End function\n\n"
        f"BAD example (do NOT do this):\n"
        f"|-- Calls InternetOpenW\n"
        f"|-- Uses URLDownloadToFileW\n"
        f"|-- Evaluate branch conditions\n\n"
        f"Analysis data:\n{analysis_context}\n\n"
        f"Return ONLY the tree. No explanation, no markdown headers."
    )

    try:
        flow_response = client.chat.completions.create(
            model=ai_config.model,
            messages=[{"role": "user", "content": flow_prompt}],
            temperature=0.2,
        )
        flow_result = flow_response.choices[0].message.content
        if flow_result:
            import re
            match = re.search(r"```[a-zA-Z]*\n(.*?)```", flow_result, re.DOTALL)
            if match:
                flow_result = match.group(1)
            else:
                if flow_result.startswith("```"):
                    flow_result = re.sub(r"^```[a-zA-Z]*\n?", "", flow_result)
                if flow_result.endswith("```"):
                    flow_result = re.sub(r"\n?```$", "", flow_result)
            flow_path = workspace.analysis / "ai_execution_flow.txt"
            flow_path.write_text(flow_result.strip(), encoding="utf-8")
            print(f"[+] Saved AI execution flow to {flow_path}")
    except Exception as e:
        print(f"[-] Error generating execution flow: {e}")


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Generate AI threat intel narrative and execution flow.")
    parser.add_argument("sample_id", help="The sample ID to process")
    args = parser.parse_args()
    generate_ai_narrative(args.sample_id)
