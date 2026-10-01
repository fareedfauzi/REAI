# Enrich-IDB Example

Use enrich-IDB mode when you want REAI to modify an IDA database quickly without generating a report workspace.

## Rename Functions, Variables, And Comments

```bash
reai sample.exe_ --enrichidb
```

Expected output:

```text
sample.exe_.i64
```

This mode runs headless IDA, waits for auto-analysis, analyzes unnamed functions in bottom-up AI batches, applies function renames, local variable renames, and function comments directly in the live database, then saves the final `.i64` beside the input sample.

It does not create `reai-output/`, reports, SQLite state, or extracted-code folders.

## Function Renames Only

```bash
reai sample.exe_ --enrichidb-rename-only
```

This implies `--enrichidb`, but only asks the AI for function names. It skips local variable renames, function comments, and explanations.

Expected output:

```text
sample.exe_.i64
```
