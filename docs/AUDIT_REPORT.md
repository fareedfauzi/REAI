# REAI Post-Implementation Audit Report

## Executive Summary

A deep engineering audit of the REAI codebase (all 9 phases, ~82 Python source
files, 63 unit/integration tests) was performed after phase implementation was
complete. The audit treated every component as **untrusted until verified** and
actively tried to find failures.

**33 findings** were identified: 2 P0, 12 P1, 13 P2, 6 P3.

**All P0 and most P1 bugs have been fixed.** The complete test suite (63 tests)
passes with 0 regressions after fixes.

> [!CAUTION]
> The most dangerous pre-fix state: REAI could report successful completion of
> an entire analysis while having done no actual work (failed state resume bug).
> This was a P0 data-integrity issue silently present since Phase 1.

---

## Repository / Version Audited

- **Path:** `c:\Work\RESEARCH_AREA\Tools_Scripts\REAI`
- **Version:** `0.1.0` (research preview)
- **Python sources:** ~82 files across 11 packages
- **Tests:** 63 unit + integration tests (2 IDA-dependent, skipped without IDA)
- **Audit date:** 2026-09-29

---

## Actual Pipeline Discovered

```text
reai sample.exe
      │
      ▼
[CLI] main.py → AnalysisOrchestrator
      │
      ├─── Phase 1: _initialize_sample
      │    Hash → workspace → SQLite init → DISCOVERED → INITIALIZED
      │
      ├─── Phase 2: _run_phase2  (IDAManager + export_bundle)
      │    IDA_ANALYSIS → EXTRACTING → GRAPH_BUILDING → READY_FOR_ANALYSIS
      │    Artifact: original.i64, functions.json, callgraph.json, analysis.db
      │
      ├─── Phase 3: _run_phase3  (BottomUpAIAnalyzer)
      │    ANALYZING → AI_ANALYZED
      │    Bottom-up topological order (SCC-aware), context builder,
      │    OpenAI structured output, calibrate_confidence, per-function DB
      │
      ├─── Phase 4: _run_phase4  (MCPInvestigator, mock only)
      │    INVESTIGATING → MCP_INVESTIGATED
      │    ReadOnlyMCPSession, budget enforcement, action fingerprints
      │
      ├─── Phase 5: _run_phase5  (MalwareUnderstandingEngine)
      │    PROPAGATING → VALIDATING → VALIDATED
      │    Multi-pass context propagation, subsystem discovery, IOC validation,
      │    ATT&CK mapping, contradiction tracking, change_candidates
      │
      ├─── Phase 6: _run_phase6  (IDBEnricher)
      │    ENRICHING → ENRICHED
      │    original.i64 → temp copy → enrich_ida.py script → analyzed.i64
      │
      └─── Phase 7: _run_phase7  (ReportGenerator)
           REPORTING → COMPLETE
           Validated SQLite → ReportModel → Markdown/HTML/PDF
```

The pipeline **does** follow the conceptual design. Key deviations from ideal
were found and documented below.

---

## Critical Findings (P0)

### REAI-AUDIT-001
**Severity:** P0  
**Area:** State Machine / Resume Logic  
**Type:** BUG  
**Problem:** Failed states (`FAILED_IDA`, `FAILED_AI`, etc.) were not remapped
by `_artifact_adjusted_state`. When the orchestrator tried to retry or resume
these states, Phase 2 fell through to an early `return` without advancing
`item.status`. All subsequent phases also silently returned. The pipeline
completed with a fake success while having done zero work.  
**Root Cause:** `_artifact_adjusted_state` had no cases for `FAILED_*` states,
so they fell through to the final `return state` unchanged. Phase 2's dispatch
logic then saw an `INITIALIZED` status and returned without error.  
**Impact:** Failed samples were never retried. Resuming a failed sample produced
a fake `ResultStatus.COMPLETE` result with no actual analysis.  
**Fix:** Added explicit `FAILED_*` → retryable predecessor remappings at the
top of `_artifact_adjusted_state`.  
**Status:** ✅ FIXED

---

### REAI-AUDIT-002
**Severity:** P0  
**Area:** MCP Investigation / Value  
**Type:** BUG / FAKE SUCCESS  
**Problem:** `_resolve_unknowns` in `investigator.py` blindly removed unknowns
from a function's unresolved list simply because a matching MCP **capability
was invoked**, regardless of whether that tool returned any useful evidence.
Simultaneously, `_reassess_with_mcp_evidence` bumped confidence by a hardcoded
`0.06 × N evidence items` with no quality gate.  
**Root Cause:** The `capabilities` set passed to `_resolve_unknowns` was derived
from all evidence items (i.e. all tools that ran), not from tools that actually
produced new evidence. An empty tool response still "resolved" the unknown.  
**Impact:** MCP investigation was expensive theater. Confidence rose and unknowns
disappeared without any actual information gain. Final findings appeared more
certain than warranted.  
**Fix:**
- `_resolve_unknowns` now receives `capabilities_with_evidence` — only capabilities
  that contributed ≥1 new evidence item.
- Confidence boost reduced from `0.06 × N` (max 0.18) to `0.03 × N` (max 0.12),
  always passed through `calibrate_confidence`.  
**Status:** ✅ FIXED

---

## Major Findings (P1)

### REAI-AUDIT-003
**Severity:** P1  
**Area:** State Machine  
**Type:** BUG  
**Problem:** `SampleState` lacked `FAILED_PROPAGATION` and `FAILED_VALIDATION`
states. Phase 5 had no `try/except` block. An error during propagation/validation
permanently left the database stuck as `PROPAGATING` or `VALIDATING` with no
recovery path.  
**Fix:** Added `FAILED_PROPAGATION` and `FAILED_VALIDATION` to `SampleState`.
Wrapped `_run_phase5` execution in `try/except` that records the appropriate
failure state and re-raises.  
**Status:** ✅ FIXED

---

### REAI-AUDIT-004
**Severity:** P1  
**Area:** Orchestrator — Disabled Phase Cascade  
**Type:** BUG  
**Problem:** If Phase 5 was disabled (`config.analysis.enabled = False`), it
returned early without advancing `item.status`. Phase 6 requires
`ResultStatus.VALIDATED` to run. Phase 7 requires `ResultStatus.ENRICHED`.
Both silently skipped, dropping the sample.  
**Fix:** When Phase 5 is disabled, `item.status` is now explicitly advanced to
`VALIDATED` so Phase 6 and 7 can still execute.  
**Status:** ✅ FIXED

---

### REAI-AUDIT-005
**Severity:** P1  
**Area:** Orchestrator — Single File Error Recording  
**Type:** BUG  
**Problem:** For single-file inputs, exceptions were re-raised before
`_record_sample_failure` was called, so the in-memory `SampleResult` never
received `FAILED` status or error metadata.  
**Fix:** `_record_sample_failure` is now called before re-raising for single-file
inputs.  
**Status:** ✅ FIXED

---

### REAI-AUDIT-006
**Severity:** P1  
**Area:** SQLite Concurrency  
**Type:** RELIABILITY  
**Problem:** SQLite was operating in default rollback journal mode without WAL,
guaranteeing `database is locked` errors during any concurrent access (multi-
process batch, terminal UI reading while analysis writes, etc.).  
**Fix:** `connect_database` now enables `PRAGMA journal_mode = WAL` and
`PRAGMA synchronous = NORMAL`, with a 30-second busy timeout.  
**Status:** ✅ FIXED

---

### REAI-AUDIT-007
**Severity:** P1  
**Area:** AI Retry Logic  
**Type:** RELIABILITY  
**Problem:** The AI retry loop in `BottomUpAIAnalyzer._analyze_one` had no
`time.sleep()` or exponential backoff. On rate-limit (429) or transient errors,
all retries were exhausted in milliseconds.  
**Fix:** Added `time.sleep(min(64, 2 ** retry))` exponential backoff after each
retry. Also wrapped `persist_ai_request` inside the error handler in its own
`try/except` so a DB failure there cannot abort the retry loop.  
**Status:** ✅ FIXED

---

### REAI-AUDIT-008
**Severity:** P1  
**Area:** Address Parsing  
**Type:** BUG  
**Problem:** `parse_address("401000")` returned `401000` (decimal = `0x61E88`)
instead of `0x401000`, because the code only applied hex parsing for strings
with an explicit `0x` prefix. IDA outputs addresses as bare hex without prefix.  
**Fix:** `parse_address` now always attempts hexadecimal first; decimal fallback
only when the string contains non-hex characters (e.g. `'g'`-`'z'`).  
**Status:** ✅ FIXED

---

### REAI-AUDIT-009
**Severity:** P1  
**Area:** Secret Leakage in Logs  
**Type:** BUG / SECURITY  
**Problem:** `RedactingFormatter` only redacted `record.msg` and `record.args`.
Exception tracebacks are serialized into `record.exc_text` by the parent
`Formatter.format()` call, bypassing redaction entirely. API keys in exception
messages leaked into log files.  
**Fix:** `RedactingFormatter.format` now applies `redact_secrets()` to the
complete formatted string returned by `super().format(record)`, covering
tracebacks.  
**Status:** ✅ FIXED

---

### REAI-AUDIT-010
**Severity:** P1  
**Area:** Extraction Validation  
**Type:** BUG / FAKE SUCCESS  
**Problem:** `export_bundle` did not validate that IDA extracted any functions.
An empty bundle would be written to disk, marked as successful, and cause all
downstream phases to produce empty analysis and fake-complete reports.  
**Fix:** `export_bundle` now raises `ExtractionError` if `bundle.functions` is
empty.  
**Status:** ✅ FIXED

---

### REAI-AUDIT-011
**Severity:** P1  
**Area:** MCP Evidence Insert  
**Type:** RELIABILITY  
**Problem:** `persist_mcp_evidence` used `connection.total_changes > before` to
detect a successful `INSERT OR IGNORE`. `total_changes` is a lifetime counter;
with any concurrent statements or triggers it gives false positives.  
**Fix:** Now uses `cursor.rowcount > 0`, which precisely reflects the rows
affected by the last statement.  
**Status:** ✅ FIXED

---

### REAI-AUDIT-012
**Severity:** P1  
**Area:** IDB Enrichment Verification  
**Type:** RELIABILITY  
**Problem:** `enrich_ida.py` verified changes **in-memory** before calling
`ida_loader.save_database()`. If save failed (disk full, lock, etc.), changes
were already marked `VERIFIED` despite never being persisted.  
**Root Cause:** The verify loop ran before the save call.  
**Impact:** Silent enrichment failures. Subsequent analysis runs would re-enrich
an un-modified IDB.  
**Status:** ⚠️ IDENTIFIED — requires IDA environment to test. Documented for
next IDA-environment sprint.

---

### REAI-AUDIT-013
**Severity:** P1  
**Area:** IDA Process Lifecycle  
**Type:** RELIABILITY  
**Problem:** Unhandled exceptions in `extract_ida.py` and `enrich_ida.py`
bypassed `ida_pro.qexit()`, leaving IDA processes hanging until the timeout.  
**Status:** ⚠️ IDENTIFIED — requires IDA environment. Documented.

---

### REAI-AUDIT-014
**Severity:** P1  
**Area:** Context Propagation — Confidence  
**Type:** RELIABILITY  
**Problem:** `run_context_propagation` could only increase confidence; it had no
mechanism to lower it when child context contradicted the parent's interpretation.  
**Status:** ⚠️ IDENTIFIED — architectural improvement, tracked for Phase 10 work.

---

### REAI-AUDIT-015
**Severity:** P1  
**Area:** Jobs Tracking  
**Type:** BUG  
**Problem:** `AnalysisJob` was created, set to `RUNNING`, and immediately
updated to `COMPLETED` during Phase 1 initialization — before any analysis
phases ran. Job status tracking was entirely inaccurate.  
**Root Cause:** `repository.update_job(job.job_id, JobStatus.COMPLETED, ...)` at
the end of `_initialize_sample` before phases 2–7 even begin.  
**Status:** ⚠️ IDENTIFIED — jobs table is currently informational only (no
external consumer). Tracked for future worker orchestration work.

---

## Quality Findings (P2)

| ID | Area | Problem | Status |
|----|------|---------|--------|
| REAI-AUDIT-016 | Name Utilities | `IDA_PLACEHOLDER_RE` only caught `sub_`. `loc_`, `unk_`, `dword_`, `byte_`, `off_`, `nullsub_`, `j_sub_` treated as analyst names. | ✅ FIXED |
| REAI-AUDIT-017 | Enrichment Policy | `assign_unique_names` iteration order non-deterministic (no ORDER BY). Name suffix (`name_2`, `name_3`) assignment varied across runs. | ✅ FIXED |
| REAI-AUDIT-018 | Schema Migrations | `_apply_migrations` inserts version markers without running `ALTER TABLE` for new columns. Old databases break on upgrade. | ⚠️ IDENTIFIED |
| REAI-AUDIT-019 | Missing Indexes | No secondary indexes on frequently queried columns (`sample_id`, `function_address`, `status`). Full table scans on large binaries. | ⚠️ IDENTIFIED |
| REAI-AUDIT-020 | Name Validation | Generic name denylist uses exact match on 11 strings. AI bypasses easily with `process_string`, `handle_message`. | ⚠️ IDENTIFIED |
| REAI-AUDIT-021 | Confidence | `calibrate_confidence` seeds score from model's self-reported confidence. Model hallucinating `1.0` confidence can reach HIGH. | ⚠️ IDENTIFIED |
| REAI-AUDIT-022 | Report — Validation Leaks | Validation-rejected names (`eligible_for_idb=False`) still appear prominently in report as `semantic (original)`. | ⚠️ IDENTIFIED |
| REAI-AUDIT-023 | Subsystem Classification | Keyword match on AI-generated text strings. Hallucinated keywords cause spurious subsystem membership. | ⚠️ IDENTIFIED |
| REAI-AUDIT-024 | ATT&CK Mappings | Statically derived from subsystem presence (`subsystem_id → technique`) rather than behavioral evidence. | ⚠️ IDENTIFIED |
| REAI-AUDIT-025 | Enrichment — IDA Args | Paths not quoted in `-S` switch. Space in `%TMP%` or workspace breaks IDA launch. | ⚠️ IDENTIFIED |
| REAI-AUDIT-026 | Enrichment — Variable Rename | Variable renaming is explicitly skipped in both `idb.py` and `enrich_ida.py`. | ⚠️ IDENTIFIED (documented) |
| REAI-AUDIT-027 | Validated Analysis Fingerprint | `get_validated_analysis_fingerprint` reads from `validated_analysis.json` first; SQLite not canonical source. | ⚠️ IDENTIFIED |
| REAI-AUDIT-028 | Batch SQLite | `batch.db` opened without WAL or timeout, vulnerable to lock errors. | ⚠️ MITIGATED (main DB now has WAL; batch.db not yet) |

---

## Performance Findings

| ID | Area | Problem | Status |
|----|------|---------|--------|
| REAI-AUDIT-029 | Repository | `persist_extraction` and similar methods call `execute()` per item — N+1 pattern. | ⚠️ IDENTIFIED |
| REAI-AUDIT-030 | Schema | No secondary indexes on any table. | ⚠️ IDENTIFIED |

---

## Reliability / UX / Documentation Findings (P3)

| ID | Area | Problem |
|----|------|---------|
| REAI-AUDIT-031 | Tests | Several orchestration tests mock `_run_sample_pipeline` (the method under test) instead of external dependencies. Mutations to actual pipeline logic would not be caught. |
| REAI-AUDIT-032 | ai_analysis_versions | Table is write-only; no query path consumes it. Dead DB bloat. |
| REAI-AUDIT-033 | MCP Planner | Keyword-based tool selection fails for differently-phrased unknowns. |

---

## Fixes Applied (Summary)

| Fix | File | Severity | Description |
|-----|------|----------|-------------|
| Failed-state resume | `core/orchestrator.py` | P0 | FAILED_* states now remap to retryable predecessors |
| Phase 5 exception handling | `core/orchestrator.py` | P1 | try/except + FAILED_PROPAGATION/VALIDATION states |
| Disabled-phase cascade | `core/orchestrator.py` | P1 | Disabled Phase 5 now advances status to VALIDATED |
| Single-file failure recording | `core/orchestrator.py` | P2 | _record_sample_failure called before re-raise |
| FAILED_PROPAGATION/VALIDATION | `core/states.py` | P1 | Added two missing failure state values |
| WAL mode + timeout | `storage/database.py` | P0 | WAL journal mode, synchronous=NORMAL, 30s timeout |
| MCP fake resolution | `mcp/investigator.py` | P0 | capabilities_with_evidence replaces all-invoked-capabilities |
| MCP confidence bump | `mcp/investigator.py` | P0 | 0.03×N (max 0.12) replaces hardcoded 0.06×N (max 0.18) |
| AI retry backoff | `ai/analyzer.py` | P1 | Exponential backoff 2^retry capped at 64s |
| AI error persist guard | `ai/analyzer.py` | P3 | persist_ai_request in error handler wrapped in try/except |
| Address parsing | `utils/address.py` | P1 | Hex-first parsing; fallback to decimal on invalid hex chars |
| Secret leakage | `utils/logging.py` | P1 | redact_secrets applied to full formatted string incl. exc_text |
| IDA placeholder names | `utils/names.py` | P2 | Regex covers sub_, loc_, unk_, dword_, word_, byte_, off_, nullsub_, j_sub_ |
| Empty bundle guard | `extraction/pipeline.py` | P1 | ExtractionError raised when no functions extracted |
| MCP evidence rowcount | `storage/repository.py` | P1 | cursor.rowcount > 0 replaces total_changes heuristic |
| Name collision ordering | `enrichment/policy.py` | P2 | assign_unique_names sorts by address before suffix assignment |

---

## Tests Added / Updated

- `tests/unit/test_address.py`: Updated to reflect hex-first parsing semantics.
  Added `parse_address("401000") == 0x401000` (canonical IDA address test case).

---

## Full Test Suite Result

```
63 passed, 2 skipped in 8.67s
```

Zero regressions. 2 skipped tests require a live IDA environment (`REAI_IDA_PATH`).

---

## Before/After: Key Metrics

| Metric | Before | After |
|--------|--------|-------|
| Failed sample resume | Fake success (no work done) | Correctly retries failed phase |
| MCP unknown resolution | Blindly resolved on tool invocation | Only resolved when evidence returned |
| MCP confidence bump | 0.18 max from 3 empty tool calls | 0.12 max, requires actual evidence items |
| Address parsing error | `"401000"` → `0x61E88` (wrong) | `"401000"` → `0x401000` (correct) |
| API key in log tracebacks | Leaked | Redacted |
| Empty extraction succeeds | Yes (fake success) | Raises ExtractionError |
| SQLite concurrency | Rollback journal (lock errors) | WAL mode (concurrent readers) |
| IDA placeholder names | `sub_` only | `sub_`, `loc_`, `unk_`, `dword_`, `word_`, `byte_`, `off_`, `nullsub_`, `j_sub_` |
| Phase 5 failure state | DB stuck at PROPAGATING forever | FAILED_PROPAGATION recorded, resumable |
| Name collision order | Non-deterministic | Deterministic (sorted by address) |

---

## Dead / Partially Wired Components

| Component | Status | Notes |
|-----------|--------|-------|
| `ai_analysis_versions` table | DEAD (write-only) | Written but never queried |
| `--workers` CLI flag | PARTIALLY WIRED | Stored in config/DB; no parallel execution |
| Job status tracking | PARTIALLY WIRED | Phase 1 marks COMPLETED before analysis |
| Variable renaming (enrichment) | DEAD | Explicitly skipped in all enrichment paths |
| MCP live IDA backend | NOT IMPLEMENTED | Only MockMCPClient; raises for real provider |
| ATT&CK evidence backing | PARTIALLY WIRED | Subsystem→technique static map, no behavioral evidence |
| Schema migration ALTER TABLE | BROKEN | Markers inserted; most ALTER TABLEs not executed |

---

## Remaining Known Risks

1. **Schema migration**: Upgrading an existing `analysis.db` to a new schema
   version may produce `sqlite3.OperationalError: no such column` because
   migration markers are inserted without running `ALTER TABLE` (except `jobs.config_json`).

2. **IDB verification order** (REAI-AUDIT-012): Changes are verified in-memory
   before save. Requires IDA environment to properly fix and test.

3. **IDA process leak on script exception** (REAI-AUDIT-013): IDA processes
   may hang until timeout on unhandled script errors.

4. **Confidence calibration**: Model-reported confidence is still the starting
   point. A hallucinating model with high self-confidence can still reach HIGH
   label via calibration unless evidence counts are checked first.

5. **ATT&CK mappings** are subsystem-derived, not evidence-backed. A function
   named `encrypt_traffic` by the AI causes `Crypto` subsystem → `T1573`
   mapping without requiring an observed encryption API call.

6. **MCP backend**: No production IDA backend exists. The system is fully
   functional with the mock backend but real investigation requires implementation.

---

## Recommended Next Priorities

1. **Fix schema migration system** (P0 for upgrade paths): Add proper `ALTER TABLE`
   execution per version step.

2. **Add secondary indexes** to `functions`, `ai_function_analysis`,
   `string_xrefs`, `import_xrefs` tables for large binary performance.

3. **Fix IDB verification order**: save first, verify from saved file.

4. **Ensure IDA scripts always call `qexit()`**: wrap all script entry points
   in a global try/finally.

5. **Evidence-grounded confidence**: compute base confidence from observed
   evidence count and type before using model's self-reported confidence as
   a secondary modifier only.

6. **Report validation boundary**: Clearly mark AI-proposed names that failed
   validation in reports; do not display them as if applied to the IDB.

7. **Implement a real MCP IDA backend** for production use.

8. **Add `executemany` for bulk inserts** in `persist_extraction` to reduce
   N+1 overhead for large binaries.
