# Troubleshooting

Use `--verbose` for terminal tracebacks and inspect `<workspace>/logs/reai.log`.

## IDA Environment Not Available

Symptom:

```text
IDA environment not available.
```

Likely cause: REAI cannot find an IDA executable.

Check:

```bash
python -m reai --help
```

Fix:

- Set `[ida].path` in a private config file.
- Or set `REAI_IDA_PATH`.
- Or add an IDA executable directory to `PATH`.

## IDA Analysis Failed

Symptom: the run exits during Phase 2 with an IDA exit code.

Likely cause: unsupported input, IDA loader/decompiler problem, timeout, or insufficient license/environment setup.

Fix:

- Open the sample manually in IDA in an isolated environment.
- Increase `[ida].timeout_seconds` for large binaries.
- Check `logs/reai.log`.

## AI Credentials Missing

Symptom: AI provider fails before or during function analysis.

Likely cause: the selected provider needs an API key or base URL that is not configured.

Fix:

- Put a key in a private config as `[ai] api-key = "..."`.
- Or leave `api-key` empty and set `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, or `REAI_AI_API_KEY`.
- For `openai-compatible`, set `[ai] base-url = "http://host:port/v1"` unless using `lmstudio`, `ollama`, or `hermes`.
- Never commit real keys.

## MCP Provider Unsupported

Symptom:

```text
Unsupported MCP provider
```

Likely cause: config requested a provider other than `reai`, `simulation`, or `disabled`.

Fix: remove non-IDA/non-AI settings from `reai.toml`. REAI's own MCP engine is enabled by default.

## REAI MCP Backend Missing

Symptom:

```text
Core MCP session could not be started.
```

Likely cause: Phase 4 MCP is enabled, but `reai-mcp` is not installed on `PATH` or cannot bind the configured host/port.

Fix:

- Reinstall REAI in editable mode with `python -m pip install -e .` so the `reai-mcp` console script is available.
- Re-run the same command; REAI records MCP as unavailable and continues without simulated evidence when the local backend cannot start.

## Workspace Locked

Symptom: REAI refuses to enter a workspace because `.reai.lock` exists.

Likely cause: another run is active or a previous process was interrupted.

Fix:

- Confirm no REAI process is using the workspace.
- Wait for `[reliability].lock_stale_seconds` to expire, or remove the stale lock only after manual verification.

## Interrupted Run

Symptom: analysis stopped mid-phase.

Fix: run the same command again. REAI resumes from persisted SQLite state and valid artifacts.

## Report Missing

Symptom: `report/report.pdf` is absent.

Likely cause: analysis did not reach Phase 7, reporting was disabled, or report validation/generation failed.

Fix:

- Check `analysis/sample.json` for state.
- Check `analysis/report_model.json` and `logs/reai.log`.
- Verify `[report].enabled = true`.

## Batch Sample Failed

Symptom: directory run exits with code 3 and some samples failed.

Fix:

- Read `batch-summary.json` and `batch-report.md`.
- Inspect each failed sample workspace.
- Re-run the same directory command after fixing environment or config issues.
