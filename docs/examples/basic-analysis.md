# Basic Analysis Example

This is a sanitized workflow example. Do not commit active malware samples to the repository.

```bash
python -m reai fixture.exe -o ./case
```

Expected primary artifacts after a complete IDA-backed run:

```text
case/
`-- fixture_<sha256>/
    |-- ida/
    |   |-- original.i64
    |   `-- analyzed.i64
    |-- report/
    |   |-- report.md
    |   |-- report.html
    |   `-- report.pdf
    `-- analysis/
        |-- analysis.db
        |-- findings.json
        |-- validated_analysis.json
        `-- changes.json
```

Analyst review order:

1. Read `report/report.pdf`.
2. Review Important Functions and Evidence and Confidence.
3. Open `ida/analyzed.i64` in IDA.
4. Compare proposed names and comments against the evidence.
5. Review unresolved behavior before drawing conclusions.

Example function evolution:

```text
Original:
sub_140003210

Proposed:
decrypt_c2_configuration

Evidence:
- cryptographic API use
- references to encoded data
- output consumed by configuration-handling callers

Result:
Applied only if validation confidence meets the rename threshold.
```

Example uncertainty:

```text
Original:
sub_140004820

Confidence:
0.61

Result:
Original name preserved.

Reason:
Evidence was insufficient to distinguish decompression from custom decoding.
```
