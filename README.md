# REAI

REAI is an autonomous first-pass malware reverse-engineering pipeline built around IDA.

Give it a binary:

```bash
python -m reai malware.exe
```

<img width="1113" height="873" alt="image" src="https://github.com/user-attachments/assets/e91a48db-d7ef-416c-9716-5118fffb8c42" />


REAI runs static analysis, exports IDA context, analyzes unnamed functions bottom-up, uses targeted MCP queries to investigate important or unresolved behavior, validates findings, enriches a separate IDB copy, and writes a technical report.

Primary outputs:

```text
ida/analyzed.i64
report/report.pdf
```

The analyst then verifies the result manually. REAI is not a sandbox, emulator, debugger, malware verdict engine, or replacement for a reverse engineer.

## Workflow

```text
Malware Sample
      |
      v
Autonomous First-Pass Reverse Engineering
      |
      +----------------+
      v                v
 Enriched IDB      RE Report
      |                |
      +-------+--------+
              v
      Analyst Verification
```

## Why REAI?

Opening a new malware sample often starts with the same work: waiting for IDA analysis, reviewing `sub_*` functions, following callers and callees, checking strings/imports, renaming obvious functions, documenting behavior, collecting IOCs, and mapping important execution paths.

REAI automates that repetitive first pass and leaves the analyst with a more useful starting point: an enriched IDB and an evidence-backed report.

## Features

- Headless IDA auto-analysis and bulk extraction.
- Structured exports for functions, call graph, strings, imports, exports, globals, segments, types, xrefs, pseudocode, and disassembly.
- Bottom-up analysis of unnamed `sub_*` functions using call-graph order and already-understood callees.
- OpenAI, Anthropic, and OpenAI-compatible AI providers for function understanding.
- Confidence calibration, evidence storage, retry accounting, and token/timing metadata.
- Core bounded read-only MCP investigation for ambiguous or high-value functions.
- Analytical-importance scoring and persisted investigation questions so high-confidence malware-relevant functions can still be inspected.
- Multi-pass context propagation, subsystem/capability grouping, IOC and configuration extraction, command-handler recovery, and contradiction tracking.
- Safe IDB enrichment into `ida/analyzed.i64`, preserving `ida/original.i64`.
- Evidence-backed malware intelligence reports in Markdown, HTML, and PDF from validated facts.
- Batch directory input, duplicate detection by SHA-256, per-sample failure isolation, workspace locks, automatic resume, redacted logs, and batch summary files.

## Requirements

- Python 3.11 or newer.
- IDA Pro with a command-line executable (`ida64`, `idat64`, `ida`, or equivalent) for real extraction.
- Hex-Rays/decompiler support is needed for pseudocode. REAI records decompiler failures and still stores disassembly where extraction provides it.
- AI provider access for the provider you choose: OpenAI, Anthropic, or an OpenAI-compatible local endpoint such as LM Studio, Ollama, or Hermes.
- Live MCP investigation is optional. REAI ships its own read-only `reai-mcp` backend, which serves REAI's Phase 2 extraction artifacts through an MCP-compatible HTTP interface. No third-party MCP server is required for the default workflow.

REAI has been developed and tested in this repository on Windows. Other platforms may work if Python and IDA command-line execution are available, but they have not been verified here.

## Installation

To completely automate environment setup, package installation, and API configuration, run the setup script for your platform from a fresh checkout:

**Windows**:
```bat
.\setup.bat
```

**Linux / macOS**:
```bash
bash setup.sh
```

The setup script will:
1. Create and activate a Python virtual environment.
2. Install REAI and its dependencies.
3. Launch an interactive configuration tool to set your IDA path, AI provider, and API key (`reai.toml`) only when no existing config is found.
4. Perform a live connection test to verify your API key works when interactive configuration runs.

After setup, simply activate your environment to use REAI:
```bash
# Windows
.\.venv\Scripts\Activate.ps1

# Linux / macOS
source .venv/bin/activate

reai --help
```

## Configuration

REAI uses built-in defaults, then an optional TOML file, then CLI overrides. Everything in the analysis pipeline is enabled by default; users normally configure only IDA and AI.

```bash
python -m reai malware.exe --config reai.example.toml -o ./case
```

Minimal configuration:

```toml
[ida]
path = "C:/Path/To/IDA"

[ai]
provider = "openai"
model = "gpt-4o-mini"
api-key = ""
```

Supported providers are `openai`, `anthropic`, `openai-compatible`, `lmstudio`, `ollama`, and `hermes`. Keep real API keys out of source control. If `api-key` is empty or omitted, REAI uses the provider's normal environment variable.

For large IDBs, Phase 2 defaults to targeted Hex-Rays extraction for entry-point, `sub_*`, and callback-like functions instead of eagerly decompiling every function. Use `[ida].decompile_mode = "none"` for the fastest metadata/disassembly pass, or `"all"` with `decompile_max_functions = 0` for full pseudocode extraction.

See [docs/configuration.md](docs/configuration.md) for the full configuration reference.

## Quick Start

Single sample:

```bash
python -m reai malware.exe
```

Custom output directory:

```bash
python -m reai malware.exe -o ./cases/ghosthopper
```

Only enrich an IDB with function names, variable names, and comments:

```bash
python -m reai malware.exe --enrichidb
```

This mode skips MCP investigation, malware-understanding reports, and report generation. It runs inside one headless IDA session, analyzes unnamed functions in AI batches of 5 functions with 2 concurrent batch workers, applies function renames, variable renames, and comments directly to the live database, then saves the final 64-bit database beside the input sample as `malware.exe.i64`.

Function names only:

```bash
python -m reai malware.exe --enrichidb-rename-only
```

This implies `--enrichidb`, but skips variable renames and function comments/explanations.

Enrich-only output is intentionally just the sibling `.i64`; no REAI workspace, report folder, SQLite database, or extracted-code folder is created.

Directory batch:

```bash
python -m reai ./samples
python -m reai ./samples --recursive
```

## Output Structure

A sample workspace is named from the file stem and the first eight SHA-256 characters:

```text
reai-output/
`-- malware_6e921af7/
    |-- Analysis Data/
    |   |-- analysis.db
    |   |-- ai_narrative.md
    |   |-- ai_execution_flow.txt
    |   `-- ...
    |-- Analysis Findings/
    |   |-- analyst-notebook.md
    |   |-- phase-3-bottom-up-ai.md
    |   `-- ...
    |-- Extracted Codes/
    |   |-- pseudocode/
    |   `-- disassembly/
    |-- IDB Files/
    |   |-- original.i64
    |   `-- analyzed.i64
    |-- Raw Data/
    |   |-- imports.json
    |   `-- strings.json
    |-- REAI Logs/
    |-- Readable Code/
    |   `-- 0x401080.c
    `-- REPORT/
        |-- report.md
        |-- report.html
        `-- report.pdf
```

The SQLite database in `Analysis Data/analysis.db` is the canonical analysis state. The IDB is an analyst output, not REAI's reasoning memory.

See [docs/output-structure.md](docs/output-structure.md).

## How It Works

```text
Sample -> Phase 1 workspace setup -> Phase 2 IDA extraction
       -> Phase 3 bottom-up AI analysis -> Phase 4 MCP investigation
       -> Phase 5 validation -> Phase 6 IDB enrichment
       -> Phase 7 report generation
```

REAI targets unnamed `sub_*` functions and avoids overwriting meaningful names unless validated policy marks a change as eligible. Calibrated confidence controls whether a finding becomes an IDB change. Low-confidence or contradictory findings are preserved for review rather than forced into the IDB.

REAI performs a bottom-up first-pass analysis of IDA functions and uses targeted MCP queries to investigate important or unresolved behavior. It can inspect callers, callees, cross-references, pseudocode, disassembly, data and other IDA context to refine function findings before generating an enriched IDB and malware-analysis report.

Detailed phase reference:

- [docs/analysis-pipeline.md](docs/analysis-pipeline.md)
- [docs/examples/enrich-idb.md](docs/examples/enrich-idb.md)

## Analyzing Raw Shellcode

When you provide a standard executable (PE, ELF, etc.), REAI's automated IDA extraction perfectly detects the architecture. However, raw shellcode (`.bin`, `.raw`) lacks headers, and IDA's batch-mode usually defaults to 32-bit x86.

**Workaround for 64-bit Shellcode:**
If you want to analyze 64-bit raw shellcode using REAI, the best workflow is:
1. Open the `.bin` shellcode manually in the IDA GUI.
2. Select "64-bit" when prompted.
3. Save the resulting database (`.i64`).
4. Instead of pointing REAI at the `.bin` file, point REAI at the `.i64` file you just saved. REAI will happily extract from your pre-configured database!

## Resume & Recovery

Run the same command again. REAI detects existing workspaces by SHA-256, checks persisted artifacts, and resumes from the latest usable checkpoint. Interrupted in-progress states are mapped back to the previous stable phase.

Directory runs isolate non-global per-sample failures. A failed sample is recorded in `batch-summary.json` and `batch-report.md`; other samples continue.

## CLI Reference

The public CLI currently has one command:

```text
python -m reai [OPTIONS] INPUT
```

Common options:

- `-o, --output PATH`: output root directory.
- `--recursive`: recursively discover files for directory input.
- `--config PATH`: TOML configuration file.
- `--enrichidb`: only rename `sub_*` functions, rename variables, add function comments, and save `<input-folder>/<filename>.i64`.
- `--enrichidb-rename-only`: run enrich-IDB mode with function renames only; skip variable renames and comments.
- `--verbose`: show detailed tracebacks on terminal errors and enable debug logging.
- `--version`: print version.
- `-h, --help`: print help.

There are no separate `doctor`, `status`, `resume`, or `report` subcommands in version `0.1.0`.

Developer-only switches still exist for test and recovery workflows, but the intended user command is simply `reai sample.exe`.

## Reports

REAI generates reports from a blend of validated structured state and AI-synthesized narratives. The report engine synthesizes malware behavior from validated functions, artifacts, imports, and execution flows, and triggers an AI rewrite for readable code snippets, while using ReportLab to render a clean PDF. Outputs are:

- `report/report.md`: portable source report.
- `report/report.html`: standalone readable HTML.
- `report/report.pdf`: simple shareable text PDF.

Typical sections include Executive Assessment, Key Findings, Sample Profile, Malware Execution Chain, Technical Analysis, Reverse Engineering Findings, Threat Intelligence, Indicators, MITRE ATT&CK Mapping, Detection and Hunting, Analytical Gaps, and Appendix. Sections and claims with no supporting facts are omitted. ATT&CK, IOC roles, persistence, cleanup, and attribution language are evidence-gated; build artifacts such as PDB paths are reported as development context, not actor attribution.

## Security

Treat analyzed files as untrusted malware. REAI does not intentionally execute the sample, launch extracted payloads, or perform sandboxed dynamic analysis, but IDA loaders and parsers still process attacker-controlled input. Run REAI in an isolated research environment.

Function context derived from the binary may be sent to the configured AI provider. REAI does not implement its own usage telemetry.

See [SECURITY.md](SECURITY.md).

## Limitations

- Static analysis only. No sandbox, debugger automation, emulation, symbolic execution, or general-purpose unpacking.
- Packed, obfuscated, self-modifying, or runtime-decrypted code may remain unresolved.
- Decompiler failures reduce available context.
- Indirect calls and generated code can weaken call-graph ordering.
- AI-generated names and explanations can be wrong.
- Static-only analysis cannot observe runtime-only configuration, packed code that was not unpacked, or behavior that depends on dynamic execution.
- Indirect calls, obfuscation, and incomplete decompilation may leave investigation questions unresolved.
- MCP evidence depends on IDA analysis quality and available backend tools.
- REAI's owned `reai-mcp` backend depends on the quality of Phase 2 static extraction.
- PDF output is intentionally simple.
- A licensed IDA/Hex-Rays environment is required for real IDB extraction and enrichment verification.

## Troubleshooting

Start with [docs/troubleshooting.md](docs/troubleshooting.md). Useful checks:

```bash
python -m reai --version
python -m reai --help
python -m reai malware.exe --verbose
```

Logs are written to `<workspace>/logs/reai.log`.

## Development

```bash
python -m pip install -e .
pytest -q
```

IDA-dependent tests are skipped unless `REAI_IDA_PATH` or `IDA_PATH` is set.

## Release Status

Version `0.1.0` is a research preview. Documentation and tests are in place, but final verification in a licensed IDA environment is recommended.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
