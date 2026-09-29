# Installation

REAI is packaged as a Python project and currently targets Python 3.11 or newer.

## Windows From Source

```bash
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -U pip
python -m pip install -e .
python -m reai --help
```

The editable install exposes the `reai` console script:

```bash
reai --version
reai --help
```

## IDA Setup

Real analysis requires IDA. REAI discovers IDA in this order:

1. `[ida].path` in the config file.
2. `REAI_IDA_PATH`.
3. `IDA_PATH`.
4. Executables on `PATH`: `ida64.exe`, `ida.exe`, `idat64.exe`, `idat.exe`, `ida64`, `ida`, `idat64`, `idat`.

`[ida].path` may point to either an executable or an IDA installation directory.

## AI Setup

The default provider is disabled. For OpenAI:

```toml
[ai]
provider = "openai"
model = "gpt-4o-mini"
api-key = ""
```

Use a real key only in a private local config file, or leave `api-key` empty and set `OPENAI_API_KEY` for the OpenAI SDK.

## Verification

```bash
python -m reai --version
python -m reai --help
pytest -q
```

IDA-dependent tests are skipped unless `REAI_IDA_PATH` or `IDA_PATH` is set.
