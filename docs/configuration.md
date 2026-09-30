# Configuration

REAI should be easy to run:

```bash
reai sample.exe
```

Everything in the pipeline is enabled by default:

- REAI MCP investigation
- function renaming
- variable renaming
- function comments
- analyzed IDB saving
- intelligence report generation

The user-facing config only needs IDA and AI settings.

## Minimal Config

```toml
[ida]
path = "C:/Program Files/IDA Professional 9.3"

[ai]
provider = "openai"
model = "gpt-4o-mini"
api-key = ""
```

You can also write the same config as simple top-level keys:

```toml
ida_path = "C:/Program Files/IDA Professional 9.3"
provider = "openai"
model = "gpt-4o-mini"
api_key = ""
```

If `api-key` / `api_key` is empty or omitted, REAI uses the provider's normal environment variable, such as `OPENAI_API_KEY` or `ANTHROPIC_API_KEY`.

## Phase 2 Performance

Phase 2 always extracts function metadata, strings, imports, xrefs, and call graph context. Hex-Rays pseudocode is the expensive part on large IDBs, so REAI defaults to targeted decompilation instead of decompiling every function up front. Targeted mode batch-decompiles IDA entry-point functions, unnamed `sub_*`-style functions, and callback-like functions referenced as function pointers or named like callbacks/procs into chunked `Extracted Codes/pseudocode/decompiled_*.c` files.

```toml
[ida]
decompile_mode = "targeted"   # all, targeted, or none
decompile_max_functions = 0   # 0 means unlimited
decompile_batch_size = 25     # functions per Hex-Rays batch, not a coverage limit
disassembly_max_lines_per_function = 1500 # 0 means unlimited
```

For very large samples where Hex-Rays is still too slow, use `decompile_mode = "none"`. Phase 2 still extracts metadata, call graph, imports, strings, and xrefs, then writes capped disassembly for target functions so Phase 3 can continue without pseudocode. Use `decompile_mode = "all"` only when you explicitly want Hex-Rays output for every function.

Phase 3 targets functions with recovered pseudocode or disassembly, plus normal entry-point and `sub_*` targets. If `ai.max_functions` is set, recovered pseudocode is preferred before non-decompiled targets. When Phase 2 uses chunked batch output, Phase 3 reads only the matching function body from the relevant `decompiled_*.c` file instead of sending the whole file as context.

## AI Providers

| Provider | Notes |
| --- | --- |
| `openai` | Uses the OpenAI API. |
| `anthropic` | Uses the Anthropic Claude API. |
| `openai-compatible` | Any OpenAI-format endpoint; set `base-url`. |
| `lmstudio` | OpenAI-format local endpoint, defaults to `http://localhost:1234/v1`. |
| `ollama` | OpenAI-format local endpoint, defaults to `http://localhost:11434/v1`. |
| `hermes` | OpenAI-format local endpoint, defaults to `http://localhost:8080/v1`. |

For custom OpenAI-format servers:

```toml
[ida]
path = "C:/Program Files/IDA Professional 9.3"

[ai]
provider = "openai-compatible"
model = "my-local-model"
base-url = "http://localhost:1234/v1"
api-key = "not-needed"
```

## Discovery

If `--config` is not passed, REAI looks for `reai.toml` in:

1. `REAI_CONFIG`
2. Current directory and parents
3. `~/.reai/reai.toml`, `~/.config/reai/reai.toml`, or `%APPDATA%/reai/reai.toml`
4. The repository root during editable development

Environment overrides:

```text
REAI_IDA_PATH
REAI_AI_PROVIDER
REAI_AI_MODEL
REAI_AI_API_KEY
REAI_AI_BASE_URL
```

Advanced internal defaults exist for development, but normal users should not need them.
