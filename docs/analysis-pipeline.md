# Analysis Pipeline

REAI separates bulk context collection from reasoning and IDB mutation.

```text
Sample
  |
  v
IDA auto-analysis
  |
  v
Bulk extraction -> SQLite + JSON artifacts
  |
  v
Call graph and SCC ordering
  |
  v
Bottom-up function analysis
  |
  +--> optional MCP investigation
  |
  v
Context propagation and validation
  |
  +--> IDB enrichment
  `--> report generation
```

## Phase 2: IDA Extraction

IDA runs headlessly with `extract_ida.py`. REAI stores:

- binary metadata
- functions and decompilation/disassembly status
- call edges and SCC metadata
- strings, imports, exports, globals, segments, types, and xrefs
- extraction failures

The exported context lets later phases avoid querying IDA for every basic fact.

## Phase 3: Bottom-Up AI Analysis

REAI targets unnamed `sub_*` functions. Leaf functions are analyzed before callers so child findings can become parent context.

Recursive groups are handled as strongly connected components. If `max_functions` is set, only the first selected targets are analyzed.

Supported providers:

- `disabled`: skip AI phases.
- `mock`: deterministic local provider for tests.
- `openai`: structured responses through the OpenAI Python SDK.

## Phase 4: MCP Investigation

MCP is optional and disabled by default. The current repository includes only a deterministic `mock` provider.

When enabled, REAI queues low-confidence or evidence-poor functions, executes allowed read-only tool capabilities, stores observed evidence, and records whether the interpretation improved. Budgets prevent runaway recursive investigation.

## Phase 5: Malware Understanding

Phase 5 loads current function findings, builds relationships, clusters subsystems and capabilities, propagates context, validates artifacts, recovers simple structures, builds execution/data flows, identifies command handlers/configuration items, and emits change candidates.

## Phase 6: IDB Enrichment

The original IDB is preserved as `ida/original.i64`. REAI copies it to a temporary database, applies validated changes, verifies results, and atomically publishes `ida/analyzed.i64`.

`mode = "ida"` uses IDA to apply changes. `mode = "manifest"` writes a sidecar state file. `mode = "auto"` uses IDA if available and falls back to manifest when allowed.

## Phase 7: Report Generation

Reports are rendered from validated structured facts. The report generator builds a model, creates deterministic narrative sections, validates references, and writes Markdown, HTML, and PDF outputs.

## Phase 8: Batch and Resume

Directory input discovers regular files, skips symlinks and common metadata files, detects duplicates by SHA-256, locks each workspace, isolates per-sample failures, and writes batch summaries.

Resume is automatic. Existing workspaces are found by SHA-256 and stale in-progress states are mapped back to the previous stable phase.
