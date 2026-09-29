# Confidence and Evidence

REAI stores names, summaries, and report statements with supporting evidence. Confidence is an analysis score, not a calibrated probability.

## Labels

The current confidence calibration uses:

| Label | Meaning |
| --- | --- |
| `HIGH` | Score is at least `0.85`, with at least three observed evidence items and at least two observed evidence types. |
| `MEDIUM` | Score is at least `0.55`, but support is incomplete. |
| `LOW` | Evidence is insufficient for semantic modification. |

Calibration may cap scores when evidence is sparse, evidence types are narrow, unknowns remain, decompilation failed, or the proposed name is invalid/generic.

## Validation Thresholds

Default Phase 5 IDB eligibility:

| Candidate | Threshold |
| --- | --- |
| Function rename | `0.85` |
| Function comment | `0.55` |
| Variable rename | `0.85` |
| Type/structure change | `0.90` |

Low-confidence findings remain in analysis state and reports where relevant, but they are not forced into the IDB.

## Evidence Sources

Evidence items identify a type, value, description, optional address, and source:

- `IDA_OBSERVED`: exported static context from IDA.
- `MCP_OBSERVED`: targeted MCP observation.
- `AI_DERIVED`: model-derived or validation-derived context.

Example public shape:

```json
{
  "address": "0x140003210",
  "proposed_name": "decrypt_c2_configuration",
  "summary": "Decrypts the embedded C2 configuration.",
  "confidence": 0.94,
  "confidence_label": "HIGH",
  "evidence": [
    {
      "type": "api_call",
      "value": "BCryptDecrypt",
      "source": "IDA_OBSERVED"
    }
  ]
}
```

## Unknowns

Unknowns are expected. If REAI cannot support a specific conclusion, it may preserve the original function name, record unresolved behavior, and include limitations in the report.

## What To Trust

Trust the evidence trail more than the proposed name. Start review from:

1. `report/report.pdf`
2. Important Functions
3. Evidence and Confidence
4. Unresolved Behavior / Limitations
5. `ida/analyzed.i64`
