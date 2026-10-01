# Output Structure

Default output root:

```text
reai-output/
```

Each sample gets a workspace:

```text
<sanitized-stem>_<sha256-prefix>/
```

## Primary Outputs

| Path | Purpose |
| --- | --- |
| `IDB Files/original.i64` | Baseline IDA database produced by extraction. |
| `IDB Files/analyzed.i64` | Analyst database after validated enrichment. |
| `REPORT/report.md` | Markdown source report. |
| `REPORT/report.html` | Standalone HTML report. |
| `REPORT/report.pdf` | Simple text-based PDF report. |
| `Analysis Data/analysis.db` | Canonical SQLite analysis state. |

## Supporting Analysis Artifacts

| Path | Purpose |
| --- | --- |
| `Analysis Data/sample.json` | Sample identity and current state. |
| `Analysis Data/binary_metadata.json` | IDA/binary metadata. |
| `Analysis Data/ai_narrative.md` | AI-generated technical narrative synthesizing all phases. |
| `Analysis Data/ai_execution_flow.txt` | AI-generated high-level behavioral execution tree. |
| `Analysis Data/functions.json` | Extracted function records and stats. |
| `Analysis Data/callgraph.json` | Call graph and SCC structure. |
| `Analysis Data/extraction_stats.json` | Bulk extraction counters. |
| `Analysis Data/function_analysis.json` | Phase 3 structured function analysis. |
| `Analysis Data/findings.json` | Condensed function findings. |
| `Analysis Data/artifact_candidates.json` | AI artifact candidates. |
| `Analysis Data/ai_usage.json` | AI request metadata and token/timing stats. |
| `Analysis Data/mcp_investigations.json` | Phase 4 investigation records. |
| `Analysis Data/mcp_evidence.json` | MCP-derived evidence. |
| `Analysis Data/mcp_usage.json` | MCP call records and stats. |
| `Analysis Data/validated_analysis.json` | Phase 5 validated semantic model. |
| `Analysis Data/semantic_relationships.json` | Function/entity relationships. |
| `Analysis Data/subsystems.json` | Subsystem groupings. |
| `Analysis Data/capabilities.json` | Validated capability labels. |
| `Analysis Data/validated_artifacts.json` | Validated artifacts. |
| `Analysis Data/iocs.json` | Reportable IOC subset. |
| `Analysis Data/recovered_structures.json` | Recovered structure candidates. |
| `Analysis Data/execution_flows.json` | Execution relationships. |
| `Analysis Data/contradictions.json` | Validation contradictions. |
| `Analysis Data/change_candidates.json` | Potential IDB modifications. |
| `Analysis Data/changes.json` | Enrichment run and application results. |
| `Analysis Data/report_model.json` | Structured source model for reports. |

## Analysis Findings

| Path | Purpose |
| --- | --- |
| `Analysis Findings/analyst-notebook.md` | Curated analyst bridge linking phase findings to the final report. |
| `Analysis Findings/phase-3-bottom-up-ai.md` | Human-readable summary of Phase 3 findings. |
| `Analysis Findings/phase-4-mcp-investigation.md` | Human-readable summary of Phase 4 findings. |
| `Analysis Findings/phase-5-semantic-validation.md` | Human-readable summary of Phase 5 findings. |
| `Analysis Findings/phase-6-idb-enrichment.md` | Human-readable summary of applied IDB changes. |

## Raw Context & Extracted Code

| Directory | Purpose |
| --- | --- |
| `Raw Data/` | Strings, imports, exports, globals, segments, types, xrefs, and decompile failures. |
| `Extracted Codes/pseudocode/` | Extracted pseudocode files. |
| `Extracted Codes/disassembly/` | Extracted disassembly files. |
| `Readable Code/` | AI-rewritten, clean C code snippets for critical functions. |
| `REAI Logs/` | Runtime log files, especially `reai.log`. |

## Batch Outputs

For directory input, the output root also contains:

- `batch-summary.json`
- `batch-report.md`
- `batch.db`

## `--enrichidb` Output

`--enrichidb` is intentionally different from a full analysis run. It does not create `reai-output/`, a sample workspace, SQLite state, extracted-code folders, findings, or reports.

For each input sample, the only persistent user-facing output is saved beside the sample:

```text
<input-folder>/<filename>.i64
```

The generated `.i64` contains the applied function renames, variable renames, and function comments. If `--enrichidb-rename-only` is used, the `.i64` contains function renames only; variable names and function comments are left untouched.

REAI may create transient control/status files in the system temp directory while headless IDA is running. Those files are deleted before the command exits. If IDA creates an accidental sibling `.idb` during the save process, REAI removes it so only the final `.i64` remains.
