# Analysis Pipeline

REAI is split into phases so expensive static extraction, AI reasoning, targeted investigation, validation, IDB mutation, and report generation stay separate. The terminal progress line shows the current action inside the active phase, for example:

```text
system.exe_:
[done]     Phase 1: initialization complete
[done]     Phase 2: deterministic extraction complete
[running]  Phase 3: analyzing function 58/1468: sub_140015500 (0x140015500)
[pending]  Phase 4: running REAI MCP investigation
[pending]  Phase 5: validating malware understanding
[pending]  Phase 6: renaming, commenting, and saving analyzed IDB
[pending]  Phase 7: generating analysis report
```

Pipeline overview:

```text
Sample
  |
  v
Phase 1: workspace and state initialization
  |
  v
Phase 2: IDA auto-analysis and deterministic extraction
  |
  v
Phase 3: bottom-up AI function analysis
  |
  v
Phase 4: targeted read-only MCP investigation
  |
  v
Phase 5: semantic validation and malware understanding
  |
  v
Phase 6: analyzed IDB enrichment
  |
  v
Phase 7: report generation
```

## Phase 1: Initialization

Purpose: create a reliable case workspace and persistent sample record before any expensive analysis starts.

Typical live status:

```text
Phase 1: discovering input samples
Phase 1: hashing sample identity
Phase 1: checking existing workspace
Phase 1: creating workspace and database
Phase 1: initialization complete
```

What it does:

- Resolves the input path and discovers samples for single-file or directory mode.
- Calculates sample hashes, including SHA-256 used for duplicate detection and workspace naming.
- Creates the per-sample workspace under the configured output directory.
- Initializes `Analysis Data/analysis.db`.
- Writes initial sample metadata and state.
- Detects existing workspaces so interrupted runs can resume instead of starting over.

Important outputs:

- `Analysis Data/sample.json`
- `Analysis Data/analysis.db`
- workspace directory named from the sample stem and SHA-256 prefix

Later phases depend on Phase 1 because the database and workspace paths are the canonical state for the whole run.

## Phase 2: Deterministic Extraction

Purpose: run IDA once to collect broad static context that every later phase can reuse.

Typical live status:

```text
Phase 2: waiting for IDA auto-analysis
Phase 2: preparing extraction workspace
Phase 2: extracting imports
Phase 2: extracting strings
Phase 2: extracting functions and call graph
Phase 2: enumerating 2043 functions and references
Phase 2: batch decompiling functions 1-25/812
Phase 2: writing disassembly for 812 target functions
Phase 2: extracting exports
Phase 2: extracting segments
Phase 2: extracting globals
Phase 2: extracting types
Phase 2: saving original IDB
Phase 2: writing extraction JSON
Phase 2: deterministic extraction complete
```

What it does:

- Starts IDA headlessly and waits for IDA auto-analysis.
- Saves the baseline database as `IDB Files/original.i64` or `original.idb`.
- Extracts binary metadata, functions, flags, prototypes, segments, imports, exports, strings, globals, types, xrefs, and call edges.
- Builds the call graph and strongly connected component metadata used by bottom-up analysis.
- Records decompilation status, disassembly status, and extraction failures.
- Persists extracted records into SQLite and JSON artifacts.

Pseudocode and disassembly behavior:

- `decompile_mode = "targeted"` batch-decompiles entry points, `sub_*`-style functions, and callback-like functions.
- `decompile_mode = "all"` requests Hex-Rays output for every eligible function.
- `decompile_mode = "none"` skips Hex-Rays and writes capped disassembly for target functions, allowing Phase 3 to continue without pseudocode.
- `decompile_batch_size` controls how many functions each Hex-Rays batch receives. It is not a coverage limit.
- `decompile_max_functions = 0` means unlimited within the chosen mode.

Important outputs:

- `IDB Files/original.i64`
- `Analysis Data/functions.json`
- `Analysis Data/callgraph.json`
- `Analysis Data/extraction_stats.json`
- `Raw Data/imports.json`
- `Raw Data/strings.json`
- `Raw Data/xrefs.json`
- `Extracted Codes/pseudocode/decompiled_*.c`
- `Extracted Codes/disassembly/*.asm`

Phase 3 cannot run without Phase 2's function list, call graph, and database state. Phase 3 can run without Hex-Rays pseudocode if Phase 2 completed metadata extraction and has disassembly or other static context.

## Phase 3: Bottom-Up AI Function Analysis

Purpose: produce first-pass semantic understanding for target functions.

Typical live status:

```text
Phase 3: creating AI client
Phase 3: selecting target functions
Phase 3: selected 1468 target functions
Phase 3: loading call graph order
Phase 3: using up to 4 concurrent AI requests per dependency group
Phase 3: queueing function 58/1468: sub_140015500 (0x140015500)
Phase 3: analyzing 4 functions concurrently
Phase 3: rate limited while analyzing 0x140015500; waiting 180s before retry 1/2
Phase 3: retrying 0x140015500 after provider error (1/2)
Phase 3: exporting AI findings
Phase 3: AI function analysis complete
```

What it does:

- Selects target functions, primarily unnamed `sub_*` functions, entry-point-related functions, callback-like functions, and functions with extracted code context.
- When `ai.max_functions` limits the seed list, REAI still adds target callee dependencies so selected callers can receive already-analyzed child context.
- Orders analysis bottom-up using the call graph, so callees are analyzed before callers where possible.
- Analyzes independent functions in the same dependency layer concurrently, bounded by `ai.max_concurrent_requests`.
- Treats recursive cycles as strongly connected components.
- Builds compact context for each function: pseudocode or disassembly, imports, strings, globals, callers, callees, child findings, types, and segment information.
- Sends each function context to the configured AI provider.
- Pauses and retries when the provider returns a rate-limit error, using `Retry-After` when available or `ai.rate_limit_cooldown_seconds` otherwise.
- Stores proposed names, summaries, behaviors, capabilities, artifacts, variables, types, confidence, evidence, and unknowns.
- Records request metadata, retries, failures, and token/timing usage where available.

Important outputs:

- `Analysis Data/function_analysis.json`
- `Analysis Data/findings.json`
- `Analysis Data/ai_usage.json`
- `Analysis Findings/phase-3-bottom-up-ai.md`

Supported providers include `openai`, `anthropic`, `openai-compatible`, `lmstudio`, `ollama`, `hermes`, and test-only mock/simulation providers.

## Phase 4: REAI MCP Investigation

Purpose: revisit uncertain or important functions with targeted read-only tools instead of blindly trusting the first AI pass.

Typical live status:

```text
Phase 4: creating MCP client
Phase 4: selecting investigation targets
Phase 4: selected 20 investigation targets
Phase 4: starting read-only MCP session
Phase 4: investigating target 3/20: sub_140045110 (0x140045110)
Phase 4: planning MCP round 1 for sub_140045110 (3 action(s))
Phase 4: calling MCP decompile for 0x140045110
Phase 4: calling MCP xrefs for 0x140045110
Phase 4: exporting MCP findings
Phase 4: MCP investigation complete
```

What it does:

- Starts REAI's read-only MCP backend for the current workspace.
- Discovers available capabilities such as decompile, disassemble, callers, callees, xrefs, strings, imports, data, CFG, types, and structures.
- Selects targets based on low confidence, unresolved unknowns, analytical importance, report value, entry-point relevance, suspicious APIs, artifacts, and relationship gaps.
- Creates concrete investigation questions.
- Executes bounded read-only tool calls.
- Normalizes MCP results into evidence.
- Reassesses the affected function finding when new evidence appears.
- Preserves unresolved questions for the final report's Analytical Gaps section.

Important outputs:

- `Analysis Data/mcp_investigations.json`
- `Analysis Data/mcp_evidence.json`
- `Analysis Data/mcp_usage.json`
- `Analysis Findings/phase-4-mcp-investigation.md`

If MCP cannot start and the failure policy allows degradation, REAI records the gap and continues. IDB mutation never happens in Phase 4.

## Phase 5: Malware Understanding And Validation

Purpose: turn per-function findings into a coherent malware understanding model and decide which facts are safe enough for enrichment/reporting.

Typical live status:

```text
Phase 5: loading current function findings
Phase 5: building semantic relationships
Phase 5: discovering subsystems and capabilities
Phase 5: propagating context across functions
Phase 5: reclustering subsystems after propagation
Phase 5: validating strings, artifacts, and IOCs
Phase 5: recovering structures and types
Phase 5: building execution and data flows
Phase 5: identifying command handlers and configuration items
Phase 5: validating semantic model and IDB change candidates
Phase 5: persisting validated malware understanding
Phase 5: semantic validation complete
```

What it does:

- Loads current Phase 3 and Phase 4 function findings.
- Builds semantic relationships between functions and artifacts.
- Groups functions into subsystems and capability clusters.
- Propagates context from callees to callers and across related findings.
- Validates artifacts and IOC candidates against extracted strings/xrefs.
- Recovers simple structure/type candidates from repeated usage patterns.
- Builds execution flows and data flows.
- Identifies command handlers and configuration items.
- Detects contradictions and unresolved gaps.
- Produces IDB change candidates for renames, comments, variables, and types.
- Marks which changes are eligible for safe IDB application.

Important outputs:

- `Analysis Data/validated_analysis.json`
- `Analysis Data/semantic_relationships.json`
- `Analysis Data/subsystems.json`
- `Analysis Data/capabilities.json`
- `Analysis Data/validated_artifacts.json`
- `Analysis Data/iocs.json`
- `Analysis Data/recovered_structures.json`
- `Analysis Data/execution_flows.json`
- `Analysis Data/contradictions.json`
- `Analysis Data/change_candidates.json`
- `Analysis Findings/phase-5-semantic-validation.md`

Phase 5 is the gate between "AI/MCP observed this" and "REAI is willing to put this into the analyzed IDB or final report."

## Phase 6: IDB Enrichment

Purpose: apply validated changes to a copy of the IDB while preserving the original database.

Typical live status:

```text
Phase 6: loading validated IDB change candidates
Phase 6: preparing 312 IDB change candidates
Phase 6: copying original IDB to analyzed workspace
Phase 6: applying changes with IDA backend
Phase 6: verifying original IDB remained unchanged
Phase 6: saving analyzed IDB
Phase 6: persisting enrichment results
Phase 6: IDB enrichment complete
```

What it does:

- Loads validated change candidates from Phase 5.
- Preserves `IDB Files/original.i64`.
- Copies the original IDB to a temporary analyzed database.
- Applies eligible function renames, comments, variable changes, and type-related changes.
- Verifies applied changes.
- Ensures the original IDB hash did not change.
- Atomically publishes `IDB Files/analyzed.i64`.
- Records skipped, failed, and applied changes.

Important outputs:

- `IDB Files/analyzed.i64`
- `Analysis Data/changes.json`
- `Analysis Findings/phase-6-idb-enrichment.md`

Modes:

- `mode = "ida"` applies changes through IDA.
- `mode = "manifest"` writes sidecar enrichment state without modifying an IDB.
- `mode = "auto"` uses IDA when available and falls back to manifest only when allowed.

## Phase 7: Report Generation

Purpose: produce analyst-facing Markdown, HTML, and PDF reports from validated state.

Typical live status:

```text
Phase 7: generating AI narrative
Phase 7: generating readable code appendix
Phase 7: synthesizing report model
Phase 7: writing report findings
Phase 7: building report sections
Phase 7: validating report model
Phase 7: writing report model JSON
Phase 7: rendering Markdown report
Phase 7: rendering HTML report
Phase 7: rendering PDF report
Phase 7: report generation complete
```

What it does:

- Generates a technical narrative from validated findings.
- Rewrites critical functions into cleaner readable C snippets.
- Synthesizes a structured report model.
- Builds report sections, IOC tables, ATT&CK mappings, evidence references, hunting leads, and analytical gaps.
- Validates the report model and Markdown references.
- Renders Markdown, HTML, and PDF formats according to configuration.

Important outputs:

- `REPORT/report.md`
- `REPORT/report.html`
- `REPORT/report.pdf`
- `Analysis Data/report_model.json`
- `Analysis Data/ai_narrative.md`
- `Readable Code/*.c`
- `Analysis Findings/analyst-notebook.md`

Analytical gaps are intentional. They capture unresolved contradictions, low-confidence important functions, missing data-flow relationships, or evidence that requires manual follow-up.

## Batch And Resume Behavior

Directory input adds orchestration around the same seven per-sample phases:

- discovers regular files
- skips symlinks and common metadata files
- detects duplicates by SHA-256
- locks each workspace
- isolates per-sample failures
- writes `batch-summary.json` and `batch-report.md`

Resume is automatic. Existing workspaces are found by SHA-256 and stale in-progress states are mapped back to the previous stable phase. For example, an interrupted Phase 3 run can resume from Phase 2's completed extraction rather than rerunning IDA.
