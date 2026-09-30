from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from openai import OpenAI

from reai.core.config import build_config
from reai.core.sample import Sample
from reai.storage.repository import AnalysisRepository
from reai.utils.paths import WorkspacePaths
from reai.reporting.synthesis import synthesize_report_model
from reai.reporting.generator import ReportConfig

LOGGER = logging.getLogger(__name__)

def generate_ai_readable_code(sample_id: str, workspace_root: Path | None = None) -> None:
    config = build_config()
    
    if workspace_root:
        workspace = WorkspacePaths.from_root(workspace_root)
        repository = AnalysisRepository(workspace.database)
    else:
        print(f"[-] workspace_root is required to locate the database.")
        return
        
    ai_config = config.ai
    
    # Try to initialize OpenAI client
    if ai_config.provider == "anthropic":
        print("[-] This script currently only supports OpenAI compatible providers for rewriting.")
        return
        
    base_url = None
    if ai_config.provider == "local":
        base_url = f"http://{ai_config.host}:{ai_config.port}/v1"
    
    client = OpenAI(
        api_key=ai_config.api_key or "sk-dummy",
        base_url=base_url
    )
    
    print(f"[*] Synthesizing report model for {sample_id} to find malicious/suspicious functions...")
    # We pass a dummy ReportConfig just to get the model
    report_config = ReportConfig()
    model = synthesize_report_model(report_config, repository, workspace, sample_id)
    
    readable_c_dir = workspace.readable_code
    readable_c_dir.mkdir(parents=True, exist_ok=True)
    
    target_functions = [
        f for f in model.key_functions 
        if f.importance_label in ("CRITICAL", "HIGH")
    ]
    
    print(f"[*] Found {len(target_functions)} target functions for AI rewriting.")
    
    for fn in target_functions:
        out_path = readable_c_dir / f"{fn.address}.c"
        if out_path.exists():
            print(f"  [+] Skipping {fn.address} ({fn.display_name}) - already rewritten.")
            continue
            
        print(f"  [*] Rewriting {fn.address} ({fn.display_name})...")
        
        # In the report model, if original_decompiled_code is present, use it
        original_code = fn.original_decompiled_code
        if not original_code:
            print(f"  [-] No original code found for {fn.address}")
            continue
            
        prompt = (
            "Convert this pseudocode to Readable C code\n\n"
            f"```c\n{original_code}\n```"
        )
        
        try:
            response = client.chat.completions.create(
                model=ai_config.model,
                messages=[
                    {"role": "system", "content": "You are a helpful expert reverse engineer."},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.1
            )
            
            result = response.choices[0].message.content
            if result:
                import re
                match = re.search(r"```[a-zA-Z]*\n(.*?)```", result, re.DOTALL)
                if match:
                    result = match.group(1)
                else:
                    if result.startswith("```"):
                        result = re.sub(r"^```[a-zA-Z]*\n?", "", result)
                    if result.endswith("```"):
                        result = re.sub(r"\n?```$", "", result)
                    
                out_path.write_text(result.strip(), encoding="utf-8")
                print(f"  [+] Saved rewritten code for {fn.address}")
            else:
                print(f"  [-] Failed to get response for {fn.address}")
        except Exception as e:
            print(f"  [-] Error rewriting {fn.address}: {e}")

if __name__ == "__main__":
    import sys
    import argparse
    
    parser = argparse.ArgumentParser(description="Rewrite malicious/suspicious functions to readable C code using AI.")
    parser.add_argument("sample_id", help="The sample ID to process")
    args = parser.parse_args()
    
    generate_ai_readable_code(args.sample_id)
