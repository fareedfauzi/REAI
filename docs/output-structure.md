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

## Raw Context & Extracted Code

| Directory | Purpose |
| --- | --- |
| `Raw Data/` | Strings, imports, exports, globals, segments, types, xrefs, and decompile failures. |
| `Extracted Codes/pseudocode/` | Extracted pseudocode files. |
| `Extracted Codes/disassembly/` | Extracted disassembly files. |
| `REAI Logs/` | Runtime log files, especially `reai.log`. |

## Batch Outputs

For directory input, the output root also contains:

- `batch-summary.json`
- `batch-report.md`
- `batch.db`
