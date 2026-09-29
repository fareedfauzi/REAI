# Batch Analysis Example

Directory input:

```bash
python -m reai ./samples -o ./campaign
```

Recursive discovery:

```bash
python -m reai ./samples --recursive -o ./campaign
```

Batch behavior:

- regular files are discovered and hashed
- symlinks, empty files, and common metadata/temp files are skipped
- duplicate SHA-256 values are analyzed once
- each unique sample gets its own workspace
- non-global per-sample failures are recorded while other samples continue

Batch outputs:

```text
campaign/
|-- batch-summary.json
|-- batch-report.md
|-- batch.db
`-- <sample>_<sha256>/
```

Read `batch-report.md` first, then open each interesting sample's `report/report.pdf` and `ida/analyzed.i64`.

`--workers` is accepted and stored in batch output, but process-level parallel execution is not implemented in this version.
