# Database

`analysis/analysis.db` is the canonical analysis state. The IDB is generated output for analyst review.

Schema version: `8`.

Major logical groups:

| Group | Tables |
| --- | --- |
| Workspace state | `samples`, `jobs`, `state_transitions`, `schema_migrations` |
| IDA extraction | `binary_metadata`, `functions`, `function_calls`, `strings`, `string_xrefs`, `imports`, `import_xrefs`, `exports`, `segments`, `globals`, `global_xrefs`, `types`, `xrefs`, `callgraph_nodes`, `callgraph_components`, `extraction_failures` |
| AI analysis | `ai_function_analysis`, `ai_evidence`, `ai_variable_proposals`, `ai_type_suggestions`, `ai_artifact_candidates`, `ai_requests`, `ai_analysis_versions` |
| MCP investigation | `mcp_sessions`, `mcp_capabilities`, `mcp_questions`, `mcp_investigations`, `mcp_rounds`, `mcp_calls`, `mcp_evidence` |
| Validated semantics | `semantic_relationships`, `validated_function_findings`, `subsystems`, `subsystem_functions`, `execution_flows`, `data_flows`, `recovered_structures`, `recovered_structure_fields`, `validated_artifacts`, `capabilities`, `capability_functions`, `command_handlers`, `configuration_items`, `contradictions`, `validation_results`, `change_candidates`, `propagation_passes` |
| IDB enrichment | `enrichment_runs`, `idb_changes`, `idb_verification` |
| Reporting | `report_runs`, `report_sections` |

Directory batch summaries use a separate `batch.db` at the output root.

## Why SQLite?

Function results and phase outputs are committed as analysis progresses. This supports resume, auditing, report generation, and IDB enrichment without using IDA comments as REAI memory.
