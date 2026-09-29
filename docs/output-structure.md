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
| `ida/original.i64` | Baseline IDA database produced by extraction. |
| `ida/analyzed.i64` | Analyst database after validated enrichment. |
| `report/report.md` | Markdown source report. |
| `report/report.html` | Standalone HTML report. |
| `report/report.pdf` | Simple text-based PDF report. |
| `analysis/analysis.db` | Canonical SQLite analysis state. |

## Supporting Analysis Artifacts

| Path | Purpose |
| --- | --- |
| `analysis/sample.json` | Sample identity and current state. |
| `analysis/binary_metadata.json` | IDA/binary metadata. |
| `analysis/functions.json` | Extracted function records and stats. |
| `analysis/callgraph.json` | Call graph and SCC structure. |
| `analysis/extraction_stats.json` | Bulk extraction counters. |
| `analysis/function_analysis.json` | Phase 3 structured function analysis. |
| `analysis/findings.json` | Condensed function findings. |
| `analysis/artifact_candidates.json` | AI artifact candidates. |
| `analysis/ai_usage.json` | AI request metadata and token/timing stats. |
| `analysis/mcp_investigations.json` | Phase 4 investigation records. |
| `analysis/mcp_evidence.json` | MCP-derived evidence. |
| `analysis/mcp_usage.json` | MCP call records and stats. |
| `analysis/validated_analysis.json` | Phase 5 validated semantic model. |
| `analysis/semantic_relationships.json` | Function/entity relationships. |
| `analysis/subsystems.json` | Subsystem groupings. |
| `analysis/capabilities.json` | Validated capability labels. |
| `analysis/validated_artifacts.json` | Validated artifacts. |
| `analysis/iocs.json` | Reportable IOC subset. |
| `analysis/recovered_structures.json` | Recovered structure candidates. |
| `analysis/execution_flows.json` | Execution relationships. |
| `analysis/contradictions.json` | Validation contradictions. |
| `analysis/change_candidates.json` | Potential IDB modifications. |
| `analysis/changes.json` | Enrichment run and application results. |
| `analysis/report_model.json` | Structured source model for reports. |

## Raw Context

| Directory | Purpose |
| --- | --- |
| `raw/` | Strings, imports, exports, globals, segments, types, xrefs, and decompile failures. |
| `pseudocode/` | Extracted pseudocode files. |
| `disassembly/` | Extracted disassembly files. |
| `logs/` | Runtime log files, especially `reai.log`. |

## Batch Outputs

For directory input, the output root also contains:

- `batch-summary.json`
- `batch-report.md`
- `batch.db`
