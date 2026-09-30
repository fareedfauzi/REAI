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
