# Security

REAI is intended for malware research and authorized security analysis.

Analyze untrusted binaries in an appropriately isolated environment. REAI does not intentionally execute samples, extracted payloads, or malware-provided scripts, but IDA loaders and parsers still process attacker-controlled input.

## Data Sent To Providers

When `[ai].provider = "openai"`, REAI may send extracted function context, pseudocode/disassembly snippets, strings, imports, and related evidence to the configured OpenAI model. Follow your organization's rules before using remote models on proprietary binaries, customer artifacts, or incident data.

MCP is disabled by default. The current repository includes a mock MCP provider; any future live provider should be reviewed for what data it sends and where.

REAI does not implement its own usage telemetry.

## Reporting Vulnerabilities

No public vulnerability reporting channel is configured in this checkout. Add one before a public release.
