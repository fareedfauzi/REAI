# Release Checklist

Use this before publishing a release.

## Documentation

- [ ] README describes the current implementation.
- [ ] Configuration docs match `src/reai/core/config.py`.
- [ ] CLI docs match `python -m reai --help`.
- [ ] Output docs match generated artifact paths.
- [ ] Limitations are candid.
- [ ] License state is clear.
- [ ] No screenshots or recordings are stale.

## Verification

- [ ] `pytest -q` passes.
- [ ] `python -m reai --version` works.
- [ ] `python -m reai --help` works.
- [ ] Package build succeeds.
- [ ] Clean install succeeds.
- [ ] IDA detection works in the release environment.
- [ ] Controlled single-sample analysis completes.
- [ ] Controlled batch analysis completes.
- [ ] Interrupted run resumes.
- [ ] `ida/analyzed.i64` opens in IDA.
- [ ] `report/report.pdf` renders and is technically useful.

## Safety

- [ ] No API keys, tokens, passwords, private URLs, customer names, or internal hostnames.
- [ ] No live malware, shellcode, payloads, credential dumps, or customer samples.
- [ ] Example data is benign or sanitized.
- [ ] Real API keys are kept in private local config files or environment variables.

## Known Release Blockers in This Checkout

- [ ] No `LICENSE` file is present.
- [ ] Full IDA-backed E2E verification requires a licensed local IDA/Hex-Rays environment.
