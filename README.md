# REAI

REAI is an autonomous first-pass malware reverse-engineering pipeline built around IDA.

Give it a binary:

```bash
python -m reai malware.exe
```

REAI runs static analysis, exports IDA context, analyzes unnamed functions bottom-up, performs bounded MCP investigation when configured, validates findings, enriches a separate IDB copy, and writes a technical report.

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
- Structured OpenAI or deterministic mock AI provider.
- Confidence calibration, evidence storage, retry accounting, and token/timing metadata.
- Optional bounded read-only MCP investigation for ambiguous functions.
- Multi-pass context propagation, subsystem/capability grouping, IOC and configuration extraction, command-handler recovery, and contradiction tracking.
- Safe IDB enrichment into `ida/analyzed.i64`, preserving `ida/original.i64`.
- Markdown, HTML, and simple text-based PDF report generation from validated facts.
- Batch directory input, duplicate detection by SHA-256, per-sample failure isolation, workspace locks, automatic resume, redacted logs, and batch summary files.

## Requirements

- Python 3.11 or newer.
- IDA Pro with a command-line executable (`ida64`, `idat64`, `ida`, or equivalent) for real extraction.
- Hex-Rays/decompiler support is needed for pseudocode. REAI records decompiler failures and still stores disassembly where extraction provides it.
- OpenAI API access only if `[ai].provider = "openai"`.
- No concrete live IDA MCP adapter is included yet. The current MCP provider is `mock`, used for deterministic tests and local development.

REAI has been developed and tested in this repository on Windows. Other platforms may work if Python and IDA command-line execution are available, but they have not been verified here.

## Installation

From a checkout:

```bash
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -U pip
python -m pip install -e .
python -m reai --help
```

After editable installation, the package also exposes:

```bash
reai --help
```

## Configuration

REAI uses built-in defaults, then an optional TOML file, then CLI overrides.

```bash
python -m reai malware.exe --config reai.example.toml -o ./case
```

Minimal OpenAI configuration:

```toml
[ida]
path = "C:/Path/To/IDA"

[ai]
provider = "openai"
model = "gpt-4o-mini"
api-key = ""
```

Keep real API keys out of source control. If `api-key` is empty or omitted, the OpenAI SDK can use `OPENAI_API_KEY` from the environment.

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

Directory batch:

```bash
python -m reai ./samples
python -m reai ./samples --recursive
```

`--workers` is accepted and recorded, but execution is currently conservative and single-process. Keep `workers = 1` unless you are extending the batch runner.

## Output Structure

A sample workspace is named from the file stem and the first eight SHA-256 characters:

```text
reai-output/
`-- malware_6e921af7/
    |-- ida/
    |   |-- original.i64
    |   |-- analyzed.i64
    |   `-- analyzed.i64.reai.json
    |-- report/
    |   |-- report.md
    |   |-- report.html
    |   `-- report.pdf
    |-- analysis/
    |   |-- analysis.db
    |   |-- sample.json
    |   |-- functions.json
    |   |-- callgraph.json
    |   |-- function_analysis.json
    |   |-- findings.json
    |   |-- validated_analysis.json
    |   |-- changes.json
    |   `-- report_model.json
    |-- raw/
    |-- pseudocode/
    |-- disassembly/
    `-- logs/
```

The SQLite database in `analysis/analysis.db` is the canonical analysis state. The IDB is an analyst output, not REAI's reasoning memory.

See [docs/output-structure.md](docs/output-structure.md).

## How It Works

```text
Sample -> IDA extraction -> call graph -> bottom-up AI analysis
       -> optional MCP investigation -> validation -> IDB/report outputs
```

REAI targets unnamed `sub_*` functions and avoids overwriting meaningful names unless validated policy marks a change as eligible. Calibrated confidence controls whether a finding becomes an IDB change. Low-confidence or contradictory findings are preserved for review rather than forced into the IDB.

Details:

- [docs/analysis-pipeline.md](docs/analysis-pipeline.md)
- [docs/confidence-and-evidence.md](docs/confidence-and-evidence.md)
- [docs/state-machine.md](docs/state-machine.md)

## Resume & Recovery

Run the same command again. REAI detects existing workspaces by SHA-256, checks persisted artifacts, and resumes from the latest usable checkpoint. Interrupted in-progress states are mapped back to the previous stable phase.

Directory runs isolate non-global per-sample failures. A failed sample is recorded in `batch-summary.json` and `batch-report.md`; other samples continue.

## CLI Reference

The public CLI currently has one command:

```text
python -m reai [OPTIONS] INPUT
```

Options:

- `-o, --output PATH`: output root directory.
- `--recursive`: recursively discover files for directory input.
- `--workers INTEGER`: accepted for batch configuration; currently reserved for later parallel execution.
- `--config PATH`: TOML configuration file.
- `--max-functions INTEGER`: development limit for Phase 3 AI target count.
- `--verbose`: show detailed tracebacks on terminal errors and enable debug logging.
- `--version`: print version.
- `-h, --help`: print help.

There are no separate `doctor`, `status`, `resume`, or `report` subcommands in version `0.1.0`.

## Reports

REAI generates reports from validated structured state, not by asking the model to write a final narrative. Outputs are:

- `report/report.md`: portable source report.
- `report/report.html`: standalone readable HTML.
- `report/report.pdf`: simple shareable text PDF.

Typical sections include Executive Summary, Sample Information, Technical Overview, Execution Flow, Configuration, behavior subsystems, Command Dispatch, Indicators of Compromise, MITRE ATT&CK Mapping, Important Functions, Recovered Types / Structures, Evidence and Confidence, Unresolved Behavior / Limitations, and Appendix. Sections with no supporting facts are omitted.

## Security

Treat analyzed files as untrusted malware. REAI does not intentionally execute the sample, launch extracted payloads, or perform sandboxed dynamic analysis, but IDA loaders and parsers still process attacker-controlled input. Run REAI in an isolated research environment.

If OpenAI is enabled, function context derived from the binary may be sent to the configured model provider. REAI does not implement its own usage telemetry.

See [SECURITY.md](SECURITY.md).

## Limitations

- Static analysis only. No sandbox, debugger automation, emulation, symbolic execution, or general-purpose unpacking.
- Packed, obfuscated, self-modifying, or runtime-decrypted code may remain unresolved.
- Decompiler failures reduce available context.
- Indirect calls and generated code can weaken call-graph ordering.
- AI-generated names and explanations can be wrong.
- MCP currently has only the mock provider in this repository.
- `--workers` is reserved; process-level parallel batch execution is not implemented.
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

Contributor notes are in [docs/development.md](docs/development.md). The implementation plan remains in [docs/IMPLEMENTATION_PLAN.md](docs/IMPLEMENTATION_PLAN.md).

## Release Status

Version `0.1.0` is a research preview. Documentation and tests are in place, but release requires an explicit project license decision and final verification in a licensed IDA environment.

## License

No project license file is currently present. Treat this as a release blocker until the project owner adds one.
