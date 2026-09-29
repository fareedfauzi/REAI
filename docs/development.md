# Development

## Setup

```bash
python -m pip install -e .
pytest -q
```

IDA integration tests are skipped unless `REAI_IDA_PATH` or `IDA_PATH` is configured.

## Repository Structure

```text
src/reai/
|-- ai/
|-- analysis/
|-- batch/
|-- cli/
|-- core/
|-- enrichment/
|-- extraction/
|-- graph/
|-- ida/
|-- mcp/
|-- reporting/
|-- storage/
`-- utils/
```

## Architecture Boundaries

- IDA extraction is deterministic context collection.
- AI reasoning consumes structured context and emits structured findings.
- MCP is a targeted investigation layer, not the default transport for all context.
- Validated analysis decides what is eligible for mutation.
- IDB enrichment applies validated changes to a copy.
- Reporting renders from validated facts and stored evidence.

## Adding an AI Provider

Implement the `AIClient` protocol in `src/reai/ai/client.py`:

- `analyze_function(...) -> AIProviderResponse`
- `model_info() -> dict`

The provider must return `FunctionAnalysisResult` and populate request metadata. Add unit tests with deterministic responses and avoid real credentials in fixtures.

## Adding MCP Capabilities

Preserve the read-only safety model. New providers should implement `IDAInvestigationClient`, advertise capabilities, honor the allowlist, store call metadata, and include tests for budget behavior and failure handling.

## Adding an Extractor

Keep extraction structured:

- add schema fields in `src/reai/extraction/models.py`
- persist in SQLite
- export JSON artifacts
- preserve partial failure records
- add tests for malformed or missing data

## Adding a Report Section

Report sections should come from `ReportModel` facts, deterministic narrative, validation, and renderers. Do not add free-form report-only LLM output that lacks stored evidence.

## Fixture Policy

Do not commit live malware, shellcode, credential dumps, customer samples, or private IOCs. Use benign synthetic fixtures or sanitized generated data.
