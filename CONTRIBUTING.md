# Contributing

## Setup

```bash
python -m pip install -e .
pytest -q
```

IDA-dependent tests require `REAI_IDA_PATH` or `IDA_PATH`.

## Expectations

- Keep extraction, reasoning, MCP, enrichment, and reporting boundaries separate.
- Add focused tests for behavior changes.
- Do not commit credentials, live malware, shellcode, customer samples, or private incident data.
- Use deterministic fixtures where possible.
- Keep documentation accurate when CLI, config, outputs, or state behavior changes.

## Pull Request Checklist

- [ ] Tests pass.
- [ ] New config keys are documented.
- [ ] New output artifacts are documented.
- [ ] Security-sensitive fixtures are benign or sanitized.
- [ ] No secrets are present.
