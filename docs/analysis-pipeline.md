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
  v
Targeted MCP investigation
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

- `openai`: OpenAI API.
- `anthropic`: Anthropic Claude API.
- `openai-compatible`: custom OpenAI-format endpoint.
- `lmstudio`, `ollama`, `hermes`: local OpenAI-format endpoints with sensible default URLs.
- `mock` / `simulation`: deterministic providers for tests.

## Phase 4: MCP Investigation

MCP is a core read-only investigation stage. Bulk extraction provides broad static context, while MCP lets REAI return to IDA for targeted evidence such as xrefs, callers/callees, decompilation, disassembly, control-flow, strings, imports, globals, static data, types, and structures.

The production provider is REAI's owned `reai-mcp` backend. REAI starts the backend, discovers the available tool catalog, normalizes server tools into internal read-only capabilities, binds the current sample workspace, and records session/capability metadata in SQLite. The first implementation serves REAI's Phase 2 extraction artifacts through an MCP-compatible HTTP interface; direct owned IDA/idalib queries can be added behind the same provider later.

If the local MCP backend cannot start, REAI records `MCP_UNAVAILABLE` evidence gaps and continues without simulated evidence. The deterministic simulation provider exists only for tests and local development.

REAI queues low-confidence, evidence-poor, ambiguous, or high-value functions, executes allowed read-only tool capabilities, stores observed evidence, and records whether the interpretation improved. Budgets and action fingerprints prevent runaway or duplicate investigation. IDB mutation remains confined to Phase 6.

Investigation V2 separates confidence from analytical importance. A trivial helper can be high-confidence and low-importance, while an entry-point downloader can be high-confidence and still worth investigating because it answers report-critical questions. REAI scores practical signals such as entry-point relationship, call relationships, network/process/file APIs, persistence indicators, crypto/decoding context, artifacts, and unresolved unknowns. Runtime helpers are normally low importance.

Before using MCP, REAI generates concrete investigation questions and stores them in SQLite. Examples include who calls a function, where an artifact is referenced, what endpoint a network function uses, where response data goes, how a file path is used, and what command or path is executed. The planner maps obvious questions deterministically to read-only capabilities such as callers, callees, xrefs, decompile, disassemble, strings, imports, data, types, and structures.

Question state is persisted as `PENDING`, `INVESTIGATING`, `RESOLVED`, `PARTIALLY_RESOLVED`, `UNRESOLVED`, or `FAILED`. Unresolved or partially resolved questions feed the final report's Analytical Gaps section. This makes uncertainty visible instead of hiding it behind a confident function summary.

## Phase 5: Malware Understanding

Phase 5 loads current function findings, builds relationships, clusters subsystems and capabilities, propagates context, validates artifacts, recovers simple structures, builds execution/data flows, identifies command handlers/configuration items, and emits change candidates.

## Phase 6: IDB Enrichment

The original IDB is preserved as `ida/original.i64`. REAI copies it to a temporary database, applies validated changes, verifies results, and atomically publishes `ida/analyzed.i64`.

`mode = "ida"` uses IDA to apply changes. `mode = "manifest"` writes a sidecar state file. `mode = "auto"` uses IDA if available and falls back to manifest when allowed.

## Phase 7: Report Generation

Reports are rendered from a mix of validated structured facts and AI-generated narratives. The generator builds an evidence-backed `ReportModelV2`, writes a curated `analyst-notebook.md`, triggers LLM tasks to write a behavior-driven Technical Analysis narrative (`ai_narrative.md`), rewrites critical functions into `Readable Code/*.c`, and finally synthesizes Markdown, HTML, and PDF outputs.

The report engine explicitly requests the AI to generate a threat-intelligence-grade technical narrative backed by Phase 3 behaviors, Phase 4 MCP evidence, and Phase 5 validations. AI rewrite transforms raw pseudocode into clean C snippets, which are subsequently integrated into the report HTML and PDF using ReportLab.

IOC presentation is typed: network IOC, host IOC, build artifact, command-line artifact, and contextual artifact are distinct categories. PDB paths and similar build strings are treated as development context unless stronger evidence exists. ATT&CK mappings are emitted only when specific behavior has supporting functions, APIs, or artifacts.

Analytical gaps are generated for unresolved contradictions, low-confidence important functions, and missing relationships such as network response handling. These gaps are intended to guide analyst follow-up rather than hide uncertainty.

## Phase 8: Batch and Resume

Directory input discovers regular files, skips symlinks and common metadata files, detects duplicates by SHA-256, locks each workspace, isolates per-sample failures, and writes batch summaries.

Resume is automatic. Existing workspaces are found by SHA-256 and stale in-progress states are mapped back to the previous stable phase.
