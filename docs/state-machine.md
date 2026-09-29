# State Machine

Sample states are persisted in `analysis/analysis.db` and mirrored in `analysis/sample.json`.

Normal path:

```text
DISCOVERED
-> INITIALIZING
-> INITIALIZED
-> IDA_ANALYSIS
-> EXTRACTING
-> GRAPH_BUILDING
-> READY_FOR_ANALYSIS
-> ANALYZING
-> AI_ANALYZED
-> INVESTIGATING
-> MCP_INVESTIGATED
-> PROPAGATING
-> VALIDATING
-> VALIDATED
-> ENRICHING
-> ENRICHED
-> REPORTING
-> COMPLETE
```

Some phases are skipped by configuration:

- AI disabled stops after Phase 2.
- MCP disabled skips investigation.
- Analysis, enrichment, or reporting disabled stops before that layer's output.

Failure states:

```text
FAILED_IDA
FAILED_EXTRACTION
FAILED_AI
FAILED_MCP
FAILED_ENRICHMENT
FAILED_REPORT
```

## Resume Behavior

Run the same command again. REAI locates existing workspaces by SHA-256.

In-progress states are mapped back:

| Stored State | Resume From |
| --- | --- |
| `ANALYZING` | `READY_FOR_ANALYSIS` |
| `INVESTIGATING` | `AI_ANALYZED` |
| `PROPAGATING` / `VALIDATING` | `MCP_INVESTIGATED` |
| `ENRICHING` | `VALIDATED` |
| `REPORTING` | `ENRICHED` |

Artifact checks can move a state farther back when required files or rows are missing.
