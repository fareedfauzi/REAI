# Configuration

REAI configuration precedence:

```text
built-in defaults -> TOML config file -> CLI options
```

Load a config file with:

```bash
python -m reai malware.exe --config reai.example.toml
```

## Top-Level Settings

| Key | Type | Default | Purpose |
| --- | --- | --- | --- |
| `output_dir` | path | `./reai-output` | Root for all sample workspaces. |
| `workers` | integer | `1` | Recorded batch worker count. Process-level parallel execution is not implemented. |
| `recursive` | boolean | `false` | Recursively discover samples for directory input. |
| `verbose` | boolean | `false` | Enable more terminal/debug detail. |

`[batch]` may also contain `workers` and `recursive` for compatibility with the config loader.

## IDA

| Key | Type | Default | Purpose |
| --- | --- | --- | --- |
| `path` | path/null | unset | IDA executable or installation directory. |
| `timeout_seconds` | integer | `3600` | IDA subprocess timeout. |
| `max_concurrent_instances` | integer | `1` | Reserved guard for IDA concurrency policy. |
| `database_extension` | string | `.i64` | IDB extension used for `original` and `analyzed` files. |

## AI

| Key | Type | Default | Purpose |
| --- | --- | --- | --- |
| `provider` | string | `disabled` | `disabled`, `mock`, or `openai`. |
| `model` | string/null | unset | Required for OpenAI. |
| `api-key` / `api_key` | string/null | unset | Optional OpenAI API key. |
| `max_functions` | integer/null | unset | Development limit for function analysis count. |
| `max_concurrent_requests` | integer | `1` | Reserved request concurrency setting. |
| `max_retries` | integer | `2` | Retry count for AI requests. |
| `timeout_seconds` | integer | `120` | AI request timeout setting. |
| `prompt_version` | string | `phase3-function-analysis-v1` | Stored with AI results. |
| `schema_version` | string | `phase3-function-analysis-v1` | Stored with AI results. |
| `confidence_policy_version` | string | `phase3-confidence-v1` | Stored with AI results. |
| `context_builder_version` | string | `phase3-context-v1` | Stored with AI results. |

## MCP

| Key | Type | Default | Purpose |
| --- | --- | --- | --- |
| `enabled` | boolean | `false` | Enable Phase 4 investigation. |
| `provider` | string | `disabled` | `disabled` or `mock` in this repository. |
| `max_functions` | integer/null | unset | Limit investigation candidates. |
| `max_rounds_per_function` | integer | `5` | Bound iterative investigation. |
| `max_tool_calls_per_function` | integer | `20` | Bound tool calls per function. |
| `max_total_tool_calls` | integer/null | unset | Optional global tool-call budget. |
| `max_related_functions` | integer | `20` | Bound relationship expansion. |
| `max_depth` | integer | `4` | Bound recursive planning depth. |
| `timeout_seconds` | integer | `60` | MCP operation timeout setting. |
| `allowlist` | list[string] | read-only IDA capabilities | Restricts tool capabilities. |

No live MCP adapter is included yet. `mock` is deterministic and useful for tests.

## Analysis

| Key | Type | Default | Purpose |
| --- | --- | --- | --- |
| `enabled` | boolean | `true` | Enable Phase 5 semantic validation. |
| `taxonomy_version` | string | `phase5-subsystem-taxonomy-v1` | Stored with semantic output. |
| `schema_version` | string | `phase5-validated-analysis-v1` | Stored with semantic output. |
| `analysis.propagation.max_passes` | integer | `3` | Multi-pass context propagation cap. |
| `analysis.propagation.minimum_context_change` | integer | `1` | Minimum useful context change. |
| `analysis.propagation.minimum_confidence_delta` | float | `0.05` | Minimum confidence improvement. |
| `analysis.validation.rename_confidence_threshold` | float | `0.85` | Minimum function rename confidence. |
| `analysis.validation.comment_confidence_threshold` | float | `0.55` | Minimum comment confidence. |
| `analysis.validation.variable_confidence_threshold` | float | `0.85` | Minimum variable rename confidence. |
| `analysis.validation.type_confidence_threshold` | float | `0.90` | Minimum type/structure confidence. |

## Enrichment

| Key | Type | Default | Purpose |
| --- | --- | --- | --- |
| `enabled` | boolean | `true` | Enable Phase 6 IDB enrichment. |
| `mode` | string | `auto` | `auto`, `ida`, or `manifest`. |
| `schema_version` | string | `phase6-idb-enrichment-v1` | Stored with enrichment runs. |
| `comment_marker_begin` | string | `[REAI ANALYSIS BEGIN]` | Managed comment block start marker. |
| `comment_marker_end` | string | `[REAI ANALYSIS END]` | Managed comment block end marker. |
| `allow_manifest_fallback` | boolean | `true` | Allow sidecar manifest fallback when IDA enrichment is unavailable. |

## Report

| Key | Type | Default | Purpose |
| --- | --- | --- | --- |
| `enabled` | boolean | `true` | Enable Phase 7 report generation. |
| `schema_version` | string | `phase7-report-v1` | Stored with report runs. |
| `prompt_version` | string | `phase7-deterministic-narrative-v1` | Narrative strategy identifier. |
| `defang_iocs` | boolean | `true` | Defang rendered IOCs. |
| `formats` | list[string] | `["markdown", "html", "pdf"]` | Report formats. |
| `max_important_functions` | integer | `25` | Limit important function table. |
| `max_evidence_items` | integer | `4` | Limit rendered evidence per item. |
| `attack_version` | string | `reai-built-in-phase7-v1` | ATT&CK mapping source label. |

## Reliability

| Key | Type | Default | Purpose |
| --- | --- | --- | --- |
| `sample_retry_limit` | integer | `0` | Per-sample retry attempts after first failure. |
| `worker_restart_limit` | integer | `0` | Reserved for future worker supervision. |
| `lock_stale_seconds` | integer | `3600` | Workspace lock stale threshold. |
| `retry_initial_delay_seconds` | float | `1.0` | Retry backoff start. |
| `retry_max_delay_seconds` | float | `8.0` | Retry backoff cap. |
