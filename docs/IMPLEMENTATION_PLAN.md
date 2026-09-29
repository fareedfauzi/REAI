# Autonomous AI Malware Reverse Engineering Platform — Implementation Plan

## 1. Project Overview

This project is a fully autonomous malware reverse-engineering pipeline built around IDA Pro, idalib, AI reasoning, bulk static-analysis context, and targeted IDA MCP investigation.

The system accepts either:

- A single malware sample
- A directory containing multiple malware samples

The analyst starts the analysis from the command line and does not need to manually approve individual AI decisions.

Example:

```bash
reai malware.exe
```

Batch analysis:

```bash
reai ./samples/
```

Custom output directory:

```bash
reai malware.exe -o ./case/
```

```bash
reai ./samples/ -o ./campaign/
```

The system performs:

1. IDA auto-analysis
2. Bulk static-analysis extraction
3. Call-graph construction
4. Bottom-up function analysis
5. AI function classification
6. Autonomous MCP investigation when additional evidence is required
7. Multi-pass context propagation
8. Function and variable naming
9. Type and structure recovery
10. IOC extraction
11. Capability and subsystem classification
12. Validation
13. IDB enrichment
14. Malware report generation

The primary outputs are:

```text
Malware Sample
      │
      ▼
Autonomous Analysis
      │
      ├──► Enriched IDB / I64
      │
      └──► Evidence-backed Malware Report
```

The analyst verifies the result after the autonomous analysis is complete.

---

# 2. Project Goals

The primary goal is not to create an AI chatbot inside IDA.

The goal is to automate the tedious first-pass reverse-engineering process while producing artifacts that remain useful to a human malware analyst.

The system should:

- Understand unknown `sub_*` functions
- Analyze functions bottom-up
- Use child-function knowledge when analyzing parent functions
- Rename functions when evidence supports the conclusion
- Rename local variables when their roles can be determined
- Recover useful types and structures
- Add useful function summaries as IDA comments
- Extract malware artifacts and IOCs with context
- Group functions into malware capabilities/subsystems
- Investigate uncertain behavior using IDA MCP
- Generate a complete malware analysis report
- Produce an enriched IDB/I64 for manual verification
- Preserve evidence and provenance for AI-generated conclusions
- Operate autonomously without analyst approval during analysis
- Support both individual and batch malware analysis
- Resume interrupted analysis without restarting from the beginning

---

# 3. Non-Goals

The initial implementation should NOT attempt to become a complete malware-analysis platform.

The following are outside the initial scope:

- Automated debugger execution
- Full dynamic malware execution
- Sandbox orchestration
- Symbolic execution
- Binary patching
- Exploit development
- Memory forensics
- Automated unpacking framework
- YARA generation
- Threat-intelligence platform integration
- VirusTotal enrichment
- MISP integration
- Interactive graphical desktop UI

These can be considered later.

The first objective is to make static AI-assisted reverse engineering reliable.

---

# 4. Design Principles

## 4.1 CLI First

The application is primarily a command-line tool.

No desktop GUI is required.

The terminal should provide a polished application-like experience using:

- Colors
- Progress bars
- Status panels
- Tables
- Live analysis statistics
- Current function information
- Investigation activity
- Error reporting

The CLI should remain usable in:

- Local terminals
- SSH sessions
- CI/CD
- Automated pipelines
- Headless environments

---

## 4.2 Fully Autonomous

Once analysis begins, the engine should not stop to ask:

```text
Accept rename?
Continue?
Apply changes?
Approve finding?
```

There should be no analyst approval loop during normal execution.

The engine makes decisions according to:

- Evidence
- Confidence
- Validation
- Investigation budget
- Modification policy

Human verification occurs after analysis by reviewing:

```text
analyzed.i64
report.pdf
report.md
changes.json
findings.json
```

---

## 4.3 IDB Is an Output, Not AI Memory

The IDA database must not become the primary memory mechanism for the AI.

The canonical analysis state belongs in the Analysis/Evidence Database.

Architecture:

```text
                   Analysis DB
                        │
             ┌──────────┴──────────┐
             ▼                     ▼
       IDB Enricher          Report Generator
             │                     │
             ▼                     ▼
       analyzed.i64           report.pdf
```

Both deliverables therefore originate from the same findings.

---

## 4.4 Evidence Before Modification

The AI must not immediately rename objects simply because it generated a plausible interpretation.

The sequence should be:

```text
Analyze
   │
   ▼
Collect Evidence
   │
   ▼
Assess Confidence
   │
   ▼
Validate
   │
   ▼
Store Finding
   │
   ▼
Apply IDB Changes
```

---

## 4.5 Preserve Original Analysis

The original IDB must never be destructively modified.

The system should maintain:

```text
original.i64
analyzed.i64
```

All AI modifications are applied only to the working copy.

---

# 5. High-Level Architecture

```text
                           SAMPLE
                              │
                              ▼
                       IDA / idalib
                              │
                              ▼
                       AUTO ANALYSIS
                              │
                ┌─────────────┴─────────────┐
                │                           │
                ▼                           ▼
         ORIGINAL IDB                BULK EXTRACTION
                                            │
                                            ▼
                                     ANALYSIS CONTEXT
                                            │
                                            ▼
                                      CALL GRAPH
                                            │
                                            ▼
                                    sub_* SELECTION
                                            │
                                            ▼
                                   BOTTOM-UP ORDERING
                                            │
                                            ▼
                                      AI ANALYSIS
                                            │
                              ┌─────────────┴─────────────┐
                              │                           │
                        CONFIDENT                     UNCERTAIN
                              │                           │
                              │                           ▼
                              │                    MCP INVESTIGATION
                              │                           │
                              └─────────────┬─────────────┘
                                            ▼
                                      EVIDENCE DB
                                            │
                                            ▼
                                  CONTEXT PROPAGATION
                                            │
                                            ▼
                                     MULTI-PASS RE
                                            │
                                            ▼
                                        VALIDATION
                                            │
                              ┌─────────────┴─────────────┐
                              ▼                           ▼
                       IDB ENRICHER                REPORT ENGINE
                              │                           │
                              ▼                           ▼
                       analyzed.i64                  report.pdf
```

---

# 6. Major Components

The system should be divided into independent components.

```text
CLI / TUI
    │
    ▼
Analysis Orchestrator
    │
    ├── Sample Manager
    ├── IDA Manager
    ├── Bulk Extractor
    ├── Call Graph Engine
    ├── AI Function Analyzer
    ├── Investigation Manager
    ├── MCP Client
    ├── Context Propagation Engine
    ├── Type Recovery Engine
    ├── IOC Extractor
    ├── Capability Classifier
    ├── Validation Engine
    ├── Evidence Store
    ├── IDB Enricher
    ├── Report Generator
    └── Output Manager
```

Components must communicate using defined data models rather than arbitrary dictionaries or prompt text.

---

# 7. Proposed Project Structure

```text
reai/
├── src/
│   └── reai/
│
│       ├── cli/
│       │   ├── main.py
│       │   ├── commands.py
│       │   ├── console.py
│       │   └── progress.py
│
│       ├── core/
│       │   ├── orchestrator.py
│       │   ├── sample.py
│       │   ├── jobs.py
│       │   ├── states.py
│       │   └── config.py
│
│       ├── ida/
│       │   ├── manager.py
│       │   ├── idalib.py
│       │   ├── database.py
│       │   └── helpers.py
│
│       ├── extraction/
│       │   ├── functions.py
│       │   ├── pseudocode.py
│       │   ├── disassembly.py
│       │   ├── strings.py
│       │   ├── imports.py
│       │   ├── exports.py
│       │   ├── globals.py
│       │   ├── segments.py
│       │   ├── xrefs.py
│       │   └── types.py
│
│       ├── graph/
│       │   ├── callgraph.py
│       │   ├── ordering.py
│       │   └── clustering.py
│
│       ├── ai/
│       │   ├── client.py
│       │   ├── prompts.py
│       │   ├── schemas.py
│       │   ├── function_analyzer.py
│       │   ├── confidence.py
│       │   └── context.py
│
│       ├── mcp/
│       │   ├── client.py
│       │   ├── investigator.py
│       │   ├── budget.py
│       │   └── tools.py
│
│       ├── analysis/
│       │   ├── propagation.py
│       │   ├── validation.py
│       │   ├── capabilities.py
│       │   ├── iocs.py
│       │   ├── types.py
│       │   └── findings.py
│
│       ├── enrichment/
│       │   ├── idb.py
│       │   ├── functions.py
│       │   ├── variables.py
│       │   ├── comments.py
│       │   ├── types.py
│       │   └── changelog.py
│
│       ├── reporting/
│       │   ├── generator.py
│       │   ├── markdown.py
│       │   ├── html.py
│       │   └── pdf.py
│
│       ├── storage/
│       │   ├── database.py
│       │   ├── models.py
│       │   ├── repository.py
│       │   └── migrations/
│
│       └── utils/
│           ├── hashing.py
│           ├── paths.py
│           ├── logging.py
│           └── retry.py
│
├── tests/
│   ├── unit/
│   ├── integration/
│   └── samples/
│
├── docs/
│   └── IMPLEMENTATION_PLAN.md
│
├── pyproject.toml
└── LICENSE
```

The exact structure may evolve, but component boundaries should remain clear.

---

# 8. Input Model

The application accepts either a file or directory.

## Single Sample

```bash
reai malware.exe
```

## Custom Output

```bash
reai malware.exe -o ./case/
```

## Directory

```bash
reai ./samples/
```

## Directory with Custom Output

```bash
reai ./samples/ -o ./campaign/
```

## Recursive

```bash
reai ./samples/ --recursive
```

## Parallel Workers

```bash
reai ./samples/ --workers 2
```

Input type should be automatically detected.

---

# 9. Sample Identity

Each sample must have a stable identity.

At minimum calculate:

- SHA256
- SHA1
- MD5
- Filename
- File size

Primary identity:

```text
SHA256
```

Default output directory:

```text
reai-output/<filename>_<sha256-first-8>/
```

Example:

```text
reai-output/
└── GhostHopper_6e921af7/
```

This prevents collisions between samples with identical filenames.

---

# 10. Output Structure

Each sample should produce:

```text
sample_<hash>/
├── ida/
│   ├── original.i64
│   └── analyzed.i64
│
├── report/
│   ├── report.md
│   ├── report.html
│   └── report.pdf
│
├── analysis/
│   ├── analysis.db
│   ├── functions.json
│   ├── findings.json
│   ├── iocs.json
│   ├── capabilities.json
│   ├── callgraph.json
│   └── changes.json
│
├── raw/
│   ├── strings.json
│   ├── imports.json
│   ├── exports.json
│   ├── globals.json
│   ├── segments.json
│   └── types.json
│
├── pseudocode/
│
├── disassembly/
│
└── logs/
```

For batch mode:

```text
campaign/
├── batch-summary.json
├── batch-report.md
│
├── sample1_<hash>/
├── sample2_<hash>/
└── sample3_<hash>/
```

Cross-sample clustering is optional for the first implementation.

Initially batch mode may treat each sample independently.

---

# 11. Analysis State Machine

Sample-level states:

```text
DISCOVERED
    │
    ▼
INITIALIZING
    │
    ▼
IDA_ANALYSIS
    │
    ▼
EXTRACTING
    │
    ▼
GRAPH_BUILDING
    │
    ▼
ANALYZING
    │
    ▼
INVESTIGATING
    │
    ▼
PROPAGATING
    │
    ▼
VALIDATING
    │
    ▼
ENRICHING
    |
    v
ENRICHED
    │
    ▼
REPORTING
    │
    ▼
COMPLETE
```

Failure states:

```text
FAILED_IDA
FAILED_EXTRACTION
FAILED_AI
FAILED_MCP
FAILED_ENRICHMENT
FAILED_REPORT
```

Recoverable failures should not invalidate already completed work.

---

# 12. Function-Level States

Each target function should independently maintain state.

```text
PENDING
QUEUED
ANALYZING
INVESTIGATING
ANALYZED
VALIDATING
VALIDATED
APPLIED
FAILED
```

Every completed function analysis must be committed immediately to storage.

Do not wait until the entire binary finishes.

This enables reliable resume behavior.

---

# 13. Bulk Extraction

The extraction system follows the useful concept from IDA-NO-MCP:

> Give the AI large amounts of static-analysis context without requiring an MCP call for every piece of information.

Extract:

## Functions

For every function:

```text
address
name
size
flags
segment
prototype
callers
callees
```

## Decompiled Pseudocode

Prefer Hex-Rays pseudocode.

If decompilation fails, record the failure and preserve disassembly.

## Disassembly

Store disassembly when:

- Decompilation fails
- Function is explicitly requested
- Additional low-level context is useful

## Strings

Store:

```text
value
address
encoding
xrefs
referencing functions
```

## Imports

Store:

```text
module
function
address
xrefs
```

## Exports

Store export names and addresses.

## Globals

Store relevant global variables and references.

## Segments

Store:

```text
name
start
end
permissions
size
```

## Existing Types

Preserve existing IDA/Hex-Rays type information.

---

# 14. Function Targeting

Initial analysis targets functions whose names match:

```text
sub_*
```

Do not automatically rename functions already carrying meaningful names.

Examples to preserve:

```text
main
WinMain
decrypt_config
malware_init
analyst_named_function
```

Runtime/library/thunk functions should be detected where possible and deprioritized or excluded.

Future versions may optionally support:

```text
loc_*
byte_*
word_*
dword_*
qword_*
unk_*
off_*
```

but these are not initial targets.

---

# 15. Call Graph

Build a directed call graph.

Example:

```text
sub_A
├── sub_B
│   └── sub_D
└── sub_C
    └── sub_E
```

Analysis should begin with:

```text
sub_D
sub_E
```

then:

```text
sub_B
sub_C
```

and finally:

```text
sub_A
```

The system must handle:

- Recursive functions
- Strongly connected components
- Indirect calls
- Unknown callees
- Imported API calls

Recursive clusters should be analyzed as strongly connected components rather than creating infinite dependency loops.

---

# 16. Bottom-Up Analysis

Bottom-up analysis is the primary reverse-engineering strategy.

For each target function, provide the AI with:

- Address
- Original name
- Pseudocode
- Relevant disassembly
- Strings
- Imported APIs
- Callers
- Callees
- Already analyzed child-function summaries
- Known types
- Relevant global references
- Previous analysis-pass information

The AI should determine:

```text
Purpose
Behavior
Proposed function name
Variable roles
Potential types
Artifacts
Capabilities
Evidence
Confidence
Unknowns
```

---

# 17. Canonical Function Analysis Schema

Example:

```json
{
  "address": "0x140003210",
  "original_name": "sub_140003210",
  "proposed_name": "decrypt_c2_configuration",
  "summary": "Decrypts the embedded C2 configuration using AES and passes the resulting structure to the network initialization routine.",
  "confidence": 0.94,
  "confidence_label": "HIGH",
  "evidence": [
    {
      "type": "api_call",
      "value": "BCryptDecrypt"
    },
    {
      "type": "data_reference",
      "value": ".rdata encrypted blob"
    },
    {
      "type": "call_relationship",
      "value": "output consumed by initialize_c2"
    }
  ],
  "variables": [
    {
      "original": "v7",
      "proposed": "encrypted_config",
      "confidence": 0.92
    },
    {
      "original": "v12",
      "proposed": "decrypted_config",
      "confidence": 0.91
    }
  ],
  "types": [],
  "capabilities": [
    "configuration",
    "cryptography"
  ],
  "unknowns": [],
  "analysis_pass": 2
}
```

AI output must be schema validated.

Malformed responses must not be directly applied.

---

# 18. Confidence Model

Confidence should be evidence-driven rather than based only on the model's self-reported confidence.

Initial policy:

## HIGH

Strong evidence from multiple sources.

Actions:

```text
Rename function
Rename high-confidence variables
Apply validated types
Add summary comment
```

## MEDIUM

Likely interpretation but incomplete evidence.

Actions:

```text
Preserve original function name
Add summary comment
Record proposed name internally
```

## LOW

Insufficient evidence.

Actions:

```text
Preserve function
Do not rename variables
Do not apply speculative types
Record finding
Attempt MCP investigation if budget allows
```

Exact numeric thresholds should remain configurable.

Suggested defaults:

```text
HIGH   >= 0.90
MEDIUM >= 0.70
LOW    < 0.70
```

These thresholds should be tuned using real malware samples.

---

# 19. MCP Investigation

MCP is an escalation mechanism.

It should NOT be the default mechanism for retrieving every piece of information.

Normal analysis should first use bulk-exported context.

MCP should be invoked when the AI requires additional evidence.

Examples:

- Unknown indirect call
- Unclear data origin
- Missing XREF context
- Ambiguous function purpose
- Need to inspect callers
- Need to inspect callees
- Need CFG information
- Need memory/data inspection
- Need additional decompilation
- Need type information

MCP capabilities should include:

```text
decompile
disassemble
xrefs
callers
callees
CFG
memory
data
strings
types
```

---

# 20. Investigation Queue

Uncertain functions enter an autonomous investigation queue.

Example:

```text
Function:
sub_140047210

Initial confidence:
0.48

Reason:
Indirect call target unresolved.

Requested investigation:
- Resolve call target
- Inspect callers
- Inspect referenced global
```

MCP gathers additional evidence.

The function is then re-analyzed.

---

# 21. Investigation Budget

Autonomous analysis must have limits.

Example defaults:

```text
max_mcp_rounds_per_function = 5
max_related_functions = 20
max_analysis_depth = 4
```

When the budget is exhausted:

```text
Store best available assessment
Preserve uncertain function name
Record unresolved questions
Continue analysis
```

The system must never loop indefinitely.

---

# 22. Multi-Pass Analysis

Function analysis should not be considered final after the first pass.

## Pass 1 — Discovery

Understand basic function behavior.

Collect:

```text
APIs
strings
data references
basic purpose
```

## Pass 2 — Bottom-Up Analysis

Analyze leaf functions and propagate knowledge upward.

## Pass 3 — Context Propagation

Use newly discovered subsystem and parent/child relationships to revisit ambiguous functions.

## Pass 4 — Validation

Check:

```text
Function names
Variable names
Types
Call relationships
Artifacts
Contradictions
Confidence
```

Additional passes may be triggered only when useful and within configured limits.

---

# 23. Context Propagation

Example:

Initial analysis:

```text
sub_3090
→ decrypt_buffer
```

Parent:

```text
sub_2040
→ unknown
```

Later evidence determines:

```text
sub_3090
→ decrypt_aes_configuration_buffer
```

and another child becomes:

```text
sub_3100
→ parse_configuration_fields
```

The parent can now be revisited and classified as:

```text
sub_2040
→ load_encrypted_configuration
```

That knowledge can then propagate to its caller.

---

# 24. Variable Renaming

Variable renaming should occur after function purpose and data flow are sufficiently understood.

Avoid generic AI-generated names such as:

```text
data
buffer
result
temp
value
```

unless that is genuinely the strongest available interpretation.

Prefer role-based names:

```text
encrypted_config
decrypted_config
c2_domain
request_buffer
aes_key
command_id
sleep_interval
```

Variable changes require independent confidence.

A high-confidence function classification does not automatically mean every local variable is understood.

---

# 25. Type and Structure Recovery

Type recovery should follow behavioral understanding.

The goal is to improve pseudocode from:

```c
*(v7 + 8)
*(v7 + 16)
*(v7 + 24)
```

toward:

```c
config->c2_domain
config->c2_port
config->sleep_interval
```

Potential recovered types should be stored in the evidence database before application.

Type application should require strong evidence.

Never aggressively apply speculative structures across the IDB.

---

# 26. Capability Classification

Functions should be grouped into malware capabilities.

Initial categories:

```text
Configuration
Network / C2
Persistence
Execution
Process Injection
Credential Access
Discovery
Collection
Defense Evasion
Cryptography / Encoding
File Operations
Registry Operations
Process Operations
Service Operations
Unknown
```

Categories may expand later.

---

# 27. Subsystem Clustering

Individual function analysis should be converted into higher-level malware understanding.

Example:

```text
CONFIGURATION
├── decrypt_configuration
├── parse_configuration
└── load_configuration


NETWORK / C2
├── initialize_http
├── build_beacon
├── send_beacon
└── parse_command


PERSISTENCE
├── create_run_key
└── install_scheduled_task
```

Subsystem information becomes an input to:

- Context propagation
- Report generation
- Important-function selection
- Capability mapping

---

# 28. IOC and Artifact Extraction

Do not extract IOCs only by regex scanning strings.

Preserve behavioral context.

Example:

```json
{
  "value": "example.com",
  "type": "domain",
  "address": "0x140081230",
  "function": "initialize_c2",
  "usage": "Passed to WinHttpConnect",
  "confidence": 0.97
}
```

Supported artifact categories should include:

```text
Domain
URL
IP
File path
Registry path
Mutex
Service
Scheduled task
Pipe
User agent
Campaign ID
Encryption key/material
Email address
Cryptocurrency address
Command identifier
Other malware-specific artifacts
```

An artifact appearing as a string does not automatically make it malicious.

Context is required.

---

# 29. Evidence Model

Every important conclusion should have evidence.

Evidence types may include:

```text
API call
String reference
XREF
Caller relationship
Callee relationship
Data reference
Control flow
Memory value
Constant
Imported function
Structure usage
Behavioral relationship
AI-derived relationship
```

Example:

```text
Finding:
Decrypts embedded configuration

Evidence:
E01 BCryptDecrypt call
E02 encrypted .rdata reference
E03 output passed to configuration parser
E04 caller is initialize_network
```

---

# 30. Provenance

Every AI-generated modification must retain provenance.

Store:

```text
Sample SHA256
Function address
Original name
Proposed name
Applied name
Evidence
Confidence
Analysis pass
Model
Timestamp
Modification type
```

This allows every change in the enriched IDB to be traced back to the analysis that produced it.

---

# 31. Validation Engine

Before IDB enrichment, run a validation pass.

Validation should check:

## Naming

- Duplicate function names
- Invalid IDA names
- Meaningless generic names
- Contradictory names
- Existing analyst names

## Variables

- Duplicate variable names
- Scope conflicts
- Weak confidence

## Types

- Conflicting structures
- Invalid sizes
- Inconsistent field usage

## Findings

- Contradictory capability assignments
- Unsupported claims
- Missing evidence

## IOCs

- Context
- Function usage
- False-positive risk

Validation failures should reduce confidence or prevent modification.

---

# 32. IDB Enrichment

Create a working IDB copy.

```text
original.i64
     │
     ▼
COPY
     │
     ▼
analyzed.i64
```

Apply validated high-confidence modifications.

Supported changes:

```text
Function rename
Variable rename
Type application
Structure application
Function comments
```

The original IDB remains untouched.

---

# 33. Function Comments

Comments should be useful to an analyst.

Example:

```text
[AI ANALYSIS — HIGH]

Purpose:
Decrypts embedded C2 configuration.

Behavior:
- Reads encrypted configuration from .rdata
- Initializes AES key material
- Calls BCryptDecrypt
- Parses decrypted configuration
- Returns configuration to initialize_c2

Key relationships:
Caller:
  initialize_c2

Callees:
  decrypt_aes_buffer
  parse_configuration

Artifacts:
  C2 domain
  C2 port
  Campaign ID
  Sleep interval

Evidence:
- BCryptDecrypt
- encrypted .rdata blob
- decrypted output passed to configuration parser

Original:
sub_140004200
```

Comments should remain concise enough to be useful inside IDA.

---

# 34. Change Log

Generate:

```text
analysis/changes.json
```

Every IDB modification should be recorded.

Example:

```json
{
  "address": "0x140004200",
  "type": "function_rename",
  "before": "sub_140004200",
  "after": "decrypt_c2_configuration",
  "confidence": 0.95,
  "analysis_pass": 3
}
```

This provides auditability even though analysis is fully autonomous.

---

# 35. Report Generation

The report must consume the same evidence database used for IDB enrichment.

Do not independently ask an AI to re-analyze the binary from scratch during report generation.

Suggested structure:

```text
1. Executive Summary

2. Sample Information

3. Technical Overview

4. Execution Flow

5. Configuration

6. Network / C2

7. Persistence

8. Execution

9. Discovery

10. Collection

11. Credential Access

12. Defense Evasion

13. Other Capabilities

14. Indicators of Compromise

15. MITRE ATT&CK Mapping

16. Important Functions

17. Function Relationships

18. Evidence and Confidence

19. Unknown / Unresolved Behavior

20. Appendix
```

Only include sections supported by actual findings.

Do not create empty capability sections simply because they exist in the template.

---

# 36. Report Formats

Generate:

```text
report.md
report.html
report.pdf
```

Markdown is the canonical report representation.

HTML and PDF are generated from the canonical report.

---

# 37. MITRE ATT&CK Mapping

ATT&CK mappings should be based on observed behavior.

Do not map techniques solely because an API exists.

Example:

```text
CreateProcessW
```

alone is insufficient to conclude a specific ATT&CK technique without behavioral context.

Each mapping should contain:

```text
Technique
Evidence
Related functions
Confidence
```

---

# 38. Batch Analysis

Directory input should discover supported candidate files.

Example:

```bash
reai ./samples/
```

Produces:

```text
reai-output/
├── batch-summary.json
├── batch-report.md
│
├── sample1_<hash>/
├── sample2_<hash>/
└── sample3_<hash>/
```

Initial batch implementation analyzes samples independently.

Future versions may add:

- Shared-code detection
- Function similarity
- Shared configuration
- Shared infrastructure
- Family clustering
- Campaign clustering

---

# 39. Parallel Workers

Support:

```bash
reai ./samples/ --workers 2
```

Default:

```text
workers = 1
```

Parallelism must be conservative because of:

- IDA licensing
- Memory consumption
- CPU consumption
- Model API limits
- MCP sessions
- Token cost

Worker failures must not terminate unrelated sample jobs.

---

# 40. Resume and Checkpointing

Every significant analysis step should be persisted.

Example:

```text
Function analyzed
       │
       ▼
Validate response
       │
       ▼
Commit to SQLite
       │
       ▼
Continue
```

If execution stops:

```bash
reai malware.exe
```

should detect an existing incomplete analysis and resume automatically when safe.

Optional explicit command:

```bash
reai resume ./reai-output/malware_<hash>/
```

No completed function should need to be analyzed again unless:

- Analysis configuration changed
- Model changed and re-analysis was requested
- Previous analysis was invalid
- Context propagation explicitly requires another pass

---

# 41. Configuration

Suggested configuration:

```toml
output_dir = "./reai-output"

analysis_mode = "bottom-up"
function_filter = "sub_*"

rename_functions = true
rename_variables = true
apply_types = true
add_comments = true

[confidence]
high = 0.90
medium = 0.70

[mcp]
enabled = true
max_rounds_per_function = 5
max_related_functions = 20
max_depth = 4

[report]
formats = ["md", "html", "pdf"]

[batch]
workers = 1
recursive = false
```

Configuration precedence:

```text
Built-in defaults
        ↓
Config file
        ↓
CLI options
```

CLI arguments have highest priority.

---

# 42. CLI

Primary interface:

```bash
reai <input>
```

Examples:

```bash
reai malware.exe
```

```bash
reai ./samples/
```

```bash
reai malware.exe -o ./output/
```

```bash
reai ./samples/ -o ./campaign/
```

```bash
reai ./samples/ --recursive
```

```bash
reai ./samples/ --workers 2
```

Potential options:

```text
-o, --output
--recursive
--workers
--model
--read-only
--no-report
--report
--aggressive
--verbose
--config
```

Avoid excessive command-line options in the first release.

Good defaults are preferable.

---

# 43. Read-Only Mode

Support:

```bash
reai malware.exe --read-only
```

This performs:

```text
IDA analysis
Bulk extraction
AI analysis
MCP investigation
Validation
Report generation
```

but does not modify the working IDB.

Useful for testing and benchmarking.

---

# 44. Aggressive Mode

Optional:

```bash
reai malware.exe --aggressive
```

Aggressive mode may:

- Lower rename thresholds
- Perform additional MCP investigations
- Apply more variable renames
- Attempt more type recovery

Default mode must remain conservative.

---

# 45. Terminal UI

The CLI should use a polished terminal interface.

Example:

```text
╭──────────────────────────────────────────────────────────────╮
│ REAI • Autonomous Malware Reverse Engineering              │
╰──────────────────────────────────────────────────────────────╯

 Sample        GhostHopper.exe
 SHA256        6e921af7...d291
 Architecture  x64
 Output        ./reai-output/GhostHopper_6e921af7/

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

 IDA Analysis       ✓
 Extraction         ✓
 Bottom-Up RE       █████████████████░░░  82%
 MCP Investigation  47
 Validation         Pending
 IDB Enrichment     Pending
 Report             Pending

 Functions

 Total              1,472
 Target sub_*       1,284
 Analyzed           1,053
 High Confidence      834
 Medium               173
 Low                   46

 Current

 sub_140047210
 → inspecting callers
 → resolving indirect call

 Elapsed 01:42:17
```

Terminal rendering should not be tightly coupled to analysis logic.

The engine must remain usable without interactive rendering.

---

# 46. Logging

Separate:

```text
User-facing terminal output
```

from:

```text
Technical logs
```

Technical logs should contain:

- Exceptions
- IDA messages
- AI request metadata
- MCP calls
- Retry activity
- Timing
- State transitions

Avoid storing secrets or API keys.

---

# 47. AI Prompting Strategy

Prompts should be task-specific.

Avoid one enormous prompt responsible for the entire binary.

Separate prompts for:

```text
Function analysis
Variable analysis
Type recovery
Context propagation
Validation
Capability classification
Report synthesis
```

Structured output should be used wherever possible.

AI context should prioritize:

```text
Relevant function
Relevant children
Relevant callers
Relevant strings
Relevant APIs
Relevant evidence
```

rather than dumping the entire binary into every request.

---

# 48. Token and Context Management

Large binaries may contain thousands of functions.

The system must avoid repeatedly sending irrelevant context.

Preferred strategy:

```text
Bulk extraction
      │
      ▼
Local structured storage
      │
      ▼
Retrieve relevant context
      │
      ▼
AI request
```

Track:

```text
Tokens per function
Tokens per sample
MCP calls
AI calls
Analysis duration
```

Cost tracking should be possible even if exact monetary cost is model-provider dependent.

---

# 49. Error Handling

Errors should be isolated wherever possible.

Example:

```text
Function decompilation failed
```

should not cause:

```text
Entire sample failed
```

Fallback:

```text
Decompiler failure
      │
      ▼
Use disassembly
```

Likewise:

```text
AI request fails
      │
      ▼
Retry
      │
      ▼
Mark function failed
      │
      ▼
Continue
```

The final report should mention important analysis limitations.

---

# 50. Security Considerations

Samples must be treated as untrusted input.

The analysis system should not execute the malware during normal static analysis.

Avoid:

- Launching samples
- Loading them as native libraries
- Running embedded scripts
- Automatically executing extracted payloads

IDA/id​alib analysis should operate on the sample as data.

Output filenames and paths derived from samples must be sanitized.

---

# 51. Testing Strategy

Testing should include:

## Unit Tests

Test:

```text
Hashing
Path handling
Configuration
Schemas
Confidence logic
Graph ordering
SCC handling
IOC normalization
State transitions
```

## Integration Tests

Test:

```text
IDA extraction
AI structured output
MCP calls
IDB changes
Resume
Report generation
```

## Malware Corpus

Maintain a controlled representative test corpus.

The corpus should include:

```text
Simple loader
RAT
Stealer
Downloader
Ransomware
Packed sample
Large C++ binary
Go malware
Rust malware
Sample with failed decompilation
Sample with many library functions
```

Do not commit live malware to a public repository.

---

# 52. Quality Benchmark

Phase 3 must be validated before continuing into advanced features.

Poor result:

```text
sub_14000210 → process_data
sub_14000310 → handle_buffer
sub_14000410 → perform_operation
sub_14000510 → process_response
```

Desired result:

```text
sub_14000210 → decrypt_embedded_config
sub_14000310 → resolve_api_hash
sub_14000410 → initialize_winhttp_session
sub_14000510 → build_c2_beacon
sub_14000610 → parse_c2_command
sub_14000710 → collect_system_information
```

The purpose of the benchmark is not merely rename coverage.

Measure:

```text
Naming usefulness
Naming correctness
Summary correctness
Evidence quality
False confident renames
Variable usefulness
MCP escalation usefulness
Analysis time
Token consumption
```

---

# 53. Development Phases

## Phase 0 — Implementation Plan

Deliverable:

```text
docs/IMPLEMENTATION_PLAN.md
```

Define:

- Architecture
- Components
- Data schemas
- State machines
- Analysis workflow
- CLI
- Output structure
- Confidence policy
- Autonomy policy
- Testing strategy
- Phase boundaries

No major production feature implementation.

---

## Phase 1 — Foundation & CLI

Implement:

- Python project
- CLI
- Configuration
- Sample discovery
- Hashing
- Output manager
- SQLite
- Job state
- Orchestrator skeleton
- Logging
- Basic terminal rendering

Milestone:

```bash
reai malware.exe
```

successfully initializes a sample analysis workspace.

---

## Phase 2 — IDA Extraction

Implement:

- IDA/id​alib integration
- IDA auto-analysis
- IDB creation/preservation
- Function extraction
- Pseudocode extraction
- Disassembly fallback
- Strings
- Imports
- Exports
- Globals
- Segments
- Existing types
- XREF metadata
- Call graph generation

Milestone:

A sample can be transformed into a complete structured static-analysis workspace without AI.

---

## Phase 3 — Bottom-Up AI Reverse Engineering

Implement:

- `sub_*` targeting
- Call graph ordering
- SCC handling
- Function context builder
- Structured AI schemas
- Function-purpose analysis
- Proposed function naming
- Variable analysis
- Function summaries
- Evidence collection
- Confidence scoring
- Per-function persistence

Milestone:

The system produces useful bottom-up function analysis for representative malware.

This is the primary go/no-go milestone.

Do not proceed aggressively into later phases until this works reliably.

---

## Phase 4 — Autonomous MCP Investigation

Implement:

- MCP client
- Investigation queue
- Investigation planner
- XREF retrieval
- Caller/callee retrieval
- Targeted decompilation
- Disassembly
- CFG retrieval
- Memory/data inspection
- Type inspection
- Investigation budget
- Re-analysis

Milestone:

Uncertain functions can autonomously gather additional evidence and improve their conclusions.

---

## Phase 5 — Multi-Pass Malware Understanding

Implement:

- Context propagation
- Parent re-analysis
- Multi-pass state
- Type recovery
- Structure recovery
- IOC extraction
- Capability classification
- Subsystem clustering
- Contradiction detection
- Final validation

Milestone:

The system moves from function-level understanding to malware-level understanding.

---

## Phase 6 — IDB Enrichment

Implement:

- Working IDB creation
- Safe function rename
- Variable rename
- Type application
- Structure application
- Function comments
- Provenance
- Change tracking
- `changes.json`

Milestone:

Produce:

```text
analyzed.i64
```

that is materially easier for an analyst to understand than the original database.

---

## Phase 7 — Report Engine

Implement:

- Evidence-backed report generation
- Technical narrative
- Capability sections
- Execution flow
- C2 analysis
- Persistence analysis
- IOC tables
- ATT&CK mapping
- Important function table
- Evidence references
- Unknown/limitations section
- Markdown
- HTML
- PDF

Milestone:

Produce a complete malware analysis report using the same evidence used to enrich the IDB.

---

## Phase 8 — Batch, Reliability & Terminal UX

Implement:

- Directory mode
- Recursive discovery
- Worker queue
- Parallel sample processing
- Checkpointing
- Automatic resume
- Crash recovery
- API retry logic
- MCP recovery
- Token statistics
- Timing statistics
- Rich terminal UI
- Batch summary
- Final integration testing
- Performance optimization

Milestone:

The tool can reliably analyze individual samples and directories unattended.

---

## Phase 9 — README and Final Documentation

Create the public-facing:

```text
README.md
```

only after the actual implementation is stable.

README should document features that actually exist.

Suggested sections:

```text
# REAI

Overview

Why REAI?

Features

Architecture

How It Works

Requirements

Installation

Configuration

Quick Start

Single Sample Analysis

Batch Analysis

CLI Reference

Output Structure

Bottom-Up Analysis

Autonomous MCP Investigation

IDB Enrichment

Malware Reports

Examples

Limitations

Troubleshooting

Development

Credits

License
```

Include terminal screenshots or recordings only after the terminal UX is implemented.

Do not document planned functionality as if it already exists.

---

# 54. Definition of Done

The project is considered functionally complete when:

```bash
reai malware.exe
```

can autonomously:

```text
1. Identify the sample

2. Analyze it with IDA

3. Preserve the original IDB

4. Extract static-analysis context

5. Build the call graph

6. Identify target sub_* functions

7. Analyze them bottom-up

8. Investigate uncertain functions through MCP

9. Propagate discovered context upward

10. Recover useful function names

11. Recover useful variable names

12. Recover high-confidence types/structures

13. Extract contextual artifacts and IOCs

14. Classify malware capabilities

15. Validate findings

16. Produce an enriched IDB

17. Produce an evidence-backed malware report

18. Save all analysis state and provenance

19. Finish without requiring analyst interaction
```

Likewise:

```bash
reai ./samples/
```

must perform the same workflow for multiple samples while maintaining independent analysis state and outputs.

---

# 55. Final Deliverable

A successful single-sample run should end with:

```text
reai-output/
└── GhostHopper_6e921af7/
    │
    ├── ida/
    │   ├── original.i64
    │   └── analyzed.i64
    │
    ├── report/
    │   ├── report.md
    │   ├── report.html
    │   └── report.pdf
    │
    ├── analysis/
    │   ├── analysis.db
    │   ├── functions.json
    │   ├── findings.json
    │   ├── iocs.json
    │   ├── capabilities.json
    │   ├── callgraph.json
    │   └── changes.json
    │
    ├── raw/
    │   ├── strings.json
    │   ├── imports.json
    │   ├── exports.json
    │   ├── globals.json
    │   ├── segments.json
    │   └── types.json
    │
    ├── pseudocode/
    ├── disassembly/
    └── logs/
```

The two primary analyst deliverables are:

```text
analyzed.i64
report.pdf
```

Everything else exists to make those two outputs reliable, reproducible, auditable, and explainable.

---

# 56. Core Project Philosophy

The system should not attempt to replace the malware analyst.

It should automate the repetitive first-pass reverse-engineering work that normally consumes analyst time.

The intended workflow is:

```text
Malware Sample
      │
      ▼
Autonomous First-Pass Reverse Engineering
      │
      ├──────────────┐
      ▼              ▼
 Enriched IDB     RE Report
      │              │
      └──────┬───────┘
             ▼
      Analyst Verification
```

The project succeeds when an analyst can run:

```bash
reai malware.exe
```

leave the system to work autonomously, and later open an IDB where previously opaque `sub_*` functions have been transformed into evidence-backed, understandable reverse-engineering context alongside a useful technical malware report.

---

# Phase 1 Implementation Note

Phase 1 introduces an `INITIALIZED` sample state between `INITIALIZING` and later analysis stages. This state represents a sample whose input validation, identity hashing, workspace creation, metadata persistence, SQLite initialization, job creation, and state-transition persistence have completed successfully, while no IDA, AI, MCP, enrichment, or report-generation stages have run yet.

---

# Phase 2 Implementation Note

Phase 2 introduces a `READY_FOR_ANALYSIS` sample state after `GRAPH_BUILDING`. This state means IDA auto-analysis, baseline IDB preservation, deterministic bulk extraction, SQLite persistence, JSON export, call graph construction, and SCC metadata generation have completed successfully.

The IDA lifecycle is isolated behind `IDAManager`. REAI discovers IDA from `[ida].path`, `REAI_IDA_PATH`, `IDA_PATH`, or executable names on `PATH`, then launches IDA headlessly with a self-contained IDA Python extraction script. When IDA is unavailable, REAI fails with a clear configuration error instead of an unrelated Python import traceback.

The Phase 2 SQLite schema stores normalized records for binary metadata, functions, function calls, strings, imports, exports, segments, globals, types, XREFs, call graph nodes/components, and extraction failures. JSON and human-readable artifacts remain exports from the same structured model.

---

# Phase 3 Implementation Note

Phase 3 introduces an optional bottom-up AI analysis layer that consumes the Phase 2 SQLite analysis store. The default AI provider is `disabled` to prevent accidental token spend. Real runs can configure `[ai] provider = "openai"` with a model and credentials supplied through the OpenAI SDK environment, while tests and development can use `[ai] provider = "mock"` for deterministic no-token execution.

The provider boundary is `AIClient`, with `MockAIClient` for deterministic tests and `OpenAIClient` using structured Pydantic parsing through the OpenAI Responses API. Prompt version, schema version, confidence-policy version, context-builder version, provider, model, request metadata, token usage, latency, retry count, success/failure, and analysis fingerprints are persisted without storing secrets.

Phase 3 stores AI inference separately from IDA facts. New SQLite tables include `ai_function_analysis`, `ai_evidence`, `ai_variable_proposals`, `ai_type_suggestions`, `ai_artifact_candidates`, and `ai_requests`. Exported artifacts include `analysis/function_analysis.json`, `analysis/findings.json`, `analysis/artifact_candidates.json`, and `analysis/ai_usage.json`.

Phase 3 adds `AI_ANALYZED` after `ANALYZING`. It does not rename IDA functions, rename variables in IDA, apply types, create `analyzed.i64`, create reports, or start MCP. Uncertain functions are marked with `needs_investigation` for Phase 4.

# Phase 4 Implementation Note

Phase 4 introduces an optional autonomous MCP investigation layer behind `[mcp]`. The default is disabled so ordinary runs do not require a live IDA MCP server. The initial provider boundary supports deterministic `mock` execution for tests and development, while real IDA MCP integrations are isolated behind the `IDAInvestigationClient` abstraction.

The Phase 4 engine consumes Phase 3 rows marked `needs_investigation`, low confidence, or failed; ranks them deterministically; discovers available read-only MCP capabilities; plans minimal targeted actions; enforces an allowlist; deduplicates repeated action fingerprints; normalizes MCP results into `MCP_OBSERVED` evidence; and updates the best-known function finding without modifying the IDB.

SQLite schema version 5 adds durable operational memory for `mcp_investigations`, `mcp_rounds`, `mcp_calls`, `mcp_evidence`, and `ai_analysis_versions`. Exported artifacts include `analysis/mcp_investigations.json`, `analysis/mcp_evidence.json`, and `analysis/mcp_usage.json`. Phase 4 adds the `MCP_INVESTIGATED` sample state after `INVESTIGATING`; it does not perform global propagation, IDB enrichment, or final reporting.

# Phase 5 Implementation Note

Phase 5 introduces a deterministic malware-understanding and validation layer behind `[analysis]`. It consumes the current best function findings from Phase 3/4, deterministic Phase 2 facts, MCP evidence, call relationships, imports, strings, globals, and finding history. It does not modify the IDB.

The Phase 5 engine builds queryable semantic relationships, performs bounded context propagation, clusters functions into evidence-backed subsystems, synthesizes malware-level capabilities, validates contextual artifacts and IOCs, proposes cautious recovered structures, models supported execution/data/configuration/command relationships, detects contradictions, and emits Phase 6-ready change candidates with explicit `eligible_for_idb` decisions.

SQLite schema version 6 adds `validated_function_findings`, `semantic_relationships`, `subsystems`, `subsystem_functions`, `execution_flows`, `data_flows`, `recovered_structures`, `recovered_structure_fields`, `validated_artifacts`, `capabilities`, `capability_functions`, `command_handlers`, `configuration_items`, `contradictions`, `validation_results`, `change_candidates`, and `propagation_passes`. Exported artifacts include `analysis/validated_analysis.json`, `analysis/semantic_relationships.json`, `analysis/subsystems.json`, `analysis/capabilities.json`, `analysis/validated_artifacts.json`, `analysis/iocs.json`, `analysis/recovered_structures.json`, `analysis/execution_flows.json`, `analysis/contradictions.json`, `analysis/change_candidates.json`, and `analysis/propagation.json`.

Phase 5 adds the `VALIDATED` sample state after `PROPAGATING` and `VALIDATING`. It leaves IDB enrichment and final report generation to later phases.

# Phase 6 Implementation Note

Phase 6 introduces safe IDB enrichment behind `[enrichment]`. It consumes Phase 5 `change_candidates` from SQLite as the source of truth, copies `ida/original.i64` to a temporary analyzed database, applies only `eligible_for_idb` changes, verifies the result, and atomically publishes `ida/analyzed.i64`. The original IDB is hash-checked before and after enrichment and is never modified.

The enrichment policy validates target existence, expected original state, name safety, and conflicts before applying a change. Function renames only overwrite `sub_*` placeholders, deterministic name collision handling records both proposed and applied names, and REAI comments are maintained in an idempotent managed block while preserving analyst comments. Unsupported or stale changes are recorded as skipped rather than forced.

SQLite schema version 7 adds `enrichment_runs`, `idb_changes`, and `idb_verification`. `analysis/changes.json` exports the run metadata, applied/skipped/failed changes, and verification records. The normal pipeline now moves from `VALIDATED` to `ENRICHING` to `ENRICHED`.

# Phase 7 Implementation Note

Phase 7 introduces an evidence-backed report subsystem behind `[report]`. It consumes validated Phase 5 SQLite rows plus Phase 6 applied-change results and builds a normalized `ReportModel`; it does not perform new reverse engineering, MCP calls, function discovery, IOC discovery, or malware classification. `analysis/report_model.json` is exported for reproducibility.

The section strategy is dynamic. The report always includes executive summary, sample information, technical overview, important functions, evidence/confidence, and appendix sections; execution flow, configuration, behavioral subsystems, command dispatch, IOCs, ATT&CK, recovered structures, contradictions, and limitations are emitted only when supported by validated rows. Narratives are deterministic fallback text generated from section-specific structured facts; no broad "write a malware report" prompt is used in Phase 7.

Report/IDB consistency is handled by reconciling Phase 6 verified function rename rows before rendering. If a rename was applied, the report uses the applied IDB name; otherwise it keeps the semantic name tied to the original function name. IOCs are defanged for presentation when `[report].defang_iocs = true`, while canonical storage remains unchanged. ATT&CK mappings use a small built-in behavior mapping recorded as `[report].attack_version`.

Markdown is the canonical rendered report. Standalone HTML is generated with deterministic escaping, and PDF output uses an internal searchable text PDF fallback so report generation does not require external renderers or network resource loading. Mermaid execution-flow diagrams are produced only from validated execution-flow rows, with labels sanitized before interpolation.

SQLite schema version 8 adds `report_runs` and `report_sections`. Report fingerprints include report settings such as IOC defanging and remain separate from the Phase 5 analysis fingerprint. The normal pipeline now moves from `ENRICHED` or `VALIDATED` to `REPORTING` to `COMPLETE`, producing `report/report.md`, `report/report.html`, and `report/report.pdf` by default.

# Phase 8 Implementation Note

Phase 8 introduces a reliability layer around the existing per-sample pipeline without adding new malware-analysis intelligence. Directory input is treated as a batch of independent samples, still deduplicated by SHA-256. Duplicate inputs reference the canonical workspace rather than creating extra analysis runs.

The initial worker architecture remains conservative and single-process by default. The CLI still accepts `[batch].workers` / `--workers` and records the configured value in batch metadata, but Phase 8 avoids unsafe parallel IDA/MCP/logging execution until process-level isolation is introduced. This preserves existing IDA licensing/resource assumptions while adding the batch state and failure boundaries needed for unattended runs.

Per-sample execution now has an isolation boundary. A non-global sample failure in a directory batch is recorded on that sample and the batch continues. A missing IDA installation remains a global dependency failure and still stops the run with the existing clear configuration error. Single-file runs keep strict behavior and surface failures through the normal CLI error path.

Batch outputs are written at the output root: `batch-summary.json`, `batch-report.md`, and `batch.db`. The summary records batch ID, input path, output root, worker count, recursive setting, discovered/skipped/duplicate counts, per-sample status, workspace path, and redacted failure context. Important text/JSON artifacts now use atomic replacement through the shared serializer.

Workspace mutation is guarded by a `.reai.lock` file in each sample workspace. Locks record owner metadata, block concurrent mutation, and can be treated as stale after `[reliability].lock_stale_seconds`. Logging now redacts common API-key, bearer-token, and OpenAI key shapes before writing log messages.

Resume is phase-aware and artifact-aware at existing boundaries. In-progress `ANALYZING`, `INVESTIGATING`, `PROPAGATING`, `VALIDATING`, `ENRICHING`, and `REPORTING` states map back to the earliest safe completed phase. Missing Phase 6 or Phase 7 artifacts cause deterministic regeneration of IDB enrichment or reports without rerunning earlier reverse-engineering stages when the SQLite evidence is still valid. Phase 2 extraction validity is based on canonical SQLite extraction rows rather than JSON convenience exports.

Phase 8 also adds reusable retry and classification utilities with bounded exponential backoff support. Current pipeline stages can adopt this utility incrementally; existing Phase 3 provider retry behavior remains intact.

# Mermaid
```
flowchart TD

    %% =========================================================
    %% INPUT
    %% =========================================================

    SAMPLE["Malware Sample<br/>PE / ELF / DLL / Mach-O"]

    SAMPLE --> IDA

    %% =========================================================
    %% IDA ANALYSIS
    %% =========================================================

    subgraph IDA_LAYER["1. IDA Analysis Layer"]

        IDA["IDA Pro / idalib"]
        AUTO["IDA Auto Analysis"]

        IDA --> AUTO

        AUTO --> IDB_ORIGINAL["Original IDB / I64<br/>Preserved & Read-Only"]
    end

    %% =========================================================
    %% BULK EXTRACTION
    %% =========================================================

    AUTO --> EXTRACT

    subgraph BULK["2. Bulk Context Extraction — IDA-NO-MCP Style"]

        EXTRACT["Bulk Extractor"]

        EXTRACT --> FUNCS["Functions<br/>Address / Name / Size"]
        EXTRACT --> PSEUDO["Decompiled Pseudocode"]
        EXTRACT --> ASM["Disassembly Fallback"]
        EXTRACT --> STRINGS["Strings + XREF Context"]
        EXTRACT --> IMPORTS["Imports / Exports"]
        EXTRACT --> CALLGRAPH["Call Graph<br/>Callers / Callees"]
        EXTRACT --> GLOBALS["Globals / Data"]
        EXTRACT --> SEGMENTS["Segments / Sections"]
        EXTRACT --> TYPES0["Existing Types / Structs"]

    end

    %% =========================================================
    %% FUNCTION FILTERING
    %% =========================================================

    FUNCS --> FILTER

    subgraph TARGETING["3. Analysis Target Selection"]

        FILTER{"Function Name?"}

        FILTER -->|"sub_*"| TARGET["AI Analysis Target"]
        FILTER -->|"Already Named"| PRESERVE["Preserve Analyst / IDA Name"]

        TARGET --> LIBCHECK{"Library / Thunk / Runtime?"}

        LIBCHECK -->|"Yes"| SKIP["Skip / Low Priority"]
        LIBCHECK -->|"No"| QUEUE["Function Analysis Queue"]

    end

    %% =========================================================
    %% CALL GRAPH ORDER
    %% =========================================================

    CALLGRAPH --> ORDER
    QUEUE --> ORDER

    subgraph ORDERING["4. Bottom-Up Analysis Ordering"]

        ORDER["Build Analysis DAG / Call Graph"]

        ORDER --> LEAVES["Leaf Functions<br/>Few / No Unknown Callees"]

        LEAVES --> LEVEL1["Low-Level Functions"]
        LEVEL1 --> LEVEL2["Mid-Level Functions"]
        LEVEL2 --> LEVEL3["High-Level Functions"]
        LEVEL3 --> ROOTS["Entry Points / Root Functions"]

    end

    %% =========================================================
    %% AI ANALYSIS
    %% =========================================================

    PSEUDO --> AI
    ASM --> AI
    STRINGS --> AI
    IMPORTS --> AI
    GLOBALS --> AI
    TYPES0 --> AI
    LEAVES --> AI

    subgraph AI_ENGINE["5. AI Reverse Engineering Engine"]

        AI["Function Analyzer"]

        AI --> PURPOSE["Determine Function Purpose"]
        AI --> BEHAVIOR["Identify Behavior"]
        AI --> DATAFLOW["Understand Data Flow"]
        AI --> ARTIFACT["Extract Relevant Artifacts"]
        AI --> RELATION["Understand Caller / Callee Context"]

        PURPOSE --> PROPOSAL
        BEHAVIOR --> PROPOSAL
        DATAFLOW --> PROPOSAL
        ARTIFACT --> PROPOSAL
        RELATION --> PROPOSAL

        PROPOSAL["Generate Analysis Proposal"]

        PROPOSAL --> FNAME["Proposed Function Name"]
        PROPOSAL --> VNAME["Proposed Variable Names"]
        PROPOSAL --> SUMMARY["Function Summary"]
        PROPOSAL --> TYPES["Proposed Types / Structs"]
        PROPOSAL --> CAP["Capability Classification"]
        PROPOSAL --> CONF["Confidence Score"]
        PROPOSAL --> EVIDENCE["Evidence / Reasoning"]

    end

    %% =========================================================
    %% UNCERTAINTY / MCP
    %% =========================================================

    CONF --> DECISION

    subgraph INVESTIGATION["6. MCP Investigation / Escalation"]

        DECISION{"Enough Evidence?"}

        DECISION -->|"Yes"| ACCEPT["Accept Analysis"]
        DECISION -->|"No"| INVESTIGATE["Investigation Queue"]

        INVESTIGATE --> MCP["IDA MCP Interface"]

        MCP --> DECOMP["Targeted Decompile"]
        MCP --> XREF["XREF Analysis"]
        MCP --> CALLER["Inspect Callers"]
        MCP --> CALLEE["Inspect Callees"]
        MCP --> CFG["Control Flow"]
        MCP --> MEM["Read Memory / Data"]
        MCP --> TYPEQ["Inspect Types"]
        MCP --> DISASM["Targeted Disassembly"]

        DECOMP --> NEWCTX["Additional Evidence"]
        XREF --> NEWCTX
        CALLER --> NEWCTX
        CALLEE --> NEWCTX
        CFG --> NEWCTX
        MEM --> NEWCTX
        TYPEQ --> NEWCTX
        DISASM --> NEWCTX

        NEWCTX --> AI

    end

    %% =========================================================
    %% EVIDENCE DATABASE
    %% =========================================================

    ACCEPT --> EDB
    EVIDENCE --> EDB

    subgraph KNOWLEDGE["7. Analysis / Evidence Database"]

        EDB[("Analysis DB")]

        EDB --> FRECORD["Function Records"]
        EDB --> IOCs["IOC Records"]
        EDB --> FINDINGS["Behavior Findings"]
        EDB --> RELATIONS["Function Relationships"]
        EDB --> PROVENANCE["AI Provenance"]
        EDB --> CHANGES["Proposed IDB Changes"]

    end

    %% =========================================================
    %% CONTEXT PROPAGATION
    %% =========================================================

    EDB --> PROPAGATE

    subgraph MULTIPASS["8. Multi-Pass Context Propagation"]

        PROPAGATE["Propagate Child Findings<br/>to Parent Functions"]

        PROPAGATE --> REVISIT{"Parent Understanding<br/>Improved?"}

        REVISIT -->|"Yes"| REANALYZE["Re-analyze Parent"]
        REANALYZE --> AI

        REVISIT -->|"No"| CLUSTER["Subsystem Clustering"]

    end

    %% =========================================================
    %% SUBSYSTEM CLUSTERING
    %% =========================================================

    subgraph CLUSTERING["9. Malware Capability / Subsystem Clustering"]

        CLUSTER --> CONFIG["Configuration"]
        CLUSTER --> NETWORK["Network / C2"]
        CLUSTER --> PERSIST["Persistence"]
        CLUSTER --> EXEC["Execution"]
        CLUSTER --> INJECT["Injection"]
        CLUSTER --> COLLECTION["Collection"]
        CLUSTER --> DISCOVERY["Discovery"]
        CLUSTER --> EVASION["Defense Evasion"]
        CLUSTER --> CRYPTO["Crypto / Encoding"]
        CLUSTER --> OTHER["Other / Unknown"]

    end

    %% =========================================================
    %% VALIDATION
    %% =========================================================

    CONFIG --> VALIDATE
    NETWORK --> VALIDATE
    PERSIST --> VALIDATE
    EXEC --> VALIDATE
    INJECT --> VALIDATE
    COLLECTION --> VALIDATE
    DISCOVERY --> VALIDATE
    EVASION --> VALIDATE
    CRYPTO --> VALIDATE
    OTHER --> VALIDATE

    subgraph VALIDATION["10. Validation"]

        VALIDATE["Validation Engine"]

        VALIDATE --> CONTRADICTION["Check Contradictions"]
        VALIDATE --> NAMECHECK["Validate Function Names"]
        VALIDATE --> VARCHECK["Validate Variable Names"]
        VALIDATE --> TYPECHECK["Validate Types / Structs"]
        VALIDATE --> IOCCHECK["Validate IOC Context"]
        VALIDATE --> CONFCHECK["Recalculate Confidence"]

        CONTRADICTION --> FINALSTATE["Final Analysis State"]
        NAMECHECK --> FINALSTATE
        VARCHECK --> FINALSTATE
        TYPECHECK --> FINALSTATE
        IOCCHECK --> FINALSTATE
        CONFCHECK --> FINALSTATE

    end

    %% =========================================================
    %% CONFIDENCE POLICY
    %% =========================================================

    FINALSTATE --> POLICY

    subgraph POLICY_LAYER["11. IDB Modification Policy"]

        POLICY{"Confidence"}

        POLICY -->|"High"| APPLY["Apply Rename / Types / Comments"]
        POLICY -->|"Medium"| COMMENT["Comment + Mark for Review"]
        POLICY -->|"Low"| REPORTONLY["Report Only<br/>Do Not Modify IDB"]

    end

    %% =========================================================
    %% IDB ENRICHMENT
    %% =========================================================

    APPLY --> ENRICH
    COMMENT --> ENRICH
    IDB_ORIGINAL --> COPY

    subgraph IDB_OUTPUT["12. IDB Enrichment"]

        COPY["Create Working IDB Copy"]
        COPY --> ENRICH["IDB Enricher"]

        ENRICH --> RENAMEFUNC["Rename sub_* Functions"]
        ENRICH --> RENAMEVAR["Rename Local Variables"]
        ENRICH --> APPLYTYPE["Apply Types / Structs"]
        ENRICH --> COMMENTS["Add Function Summary Comments"]
        ENRICH --> MARKERS["Add AI Review Markers"]

        RENAMEFUNC --> FINALIDB
        RENAMEVAR --> FINALIDB
        APPLYTYPE --> FINALIDB
        COMMENTS --> FINALIDB
        MARKERS --> FINALIDB

        FINALIDB["Enriched IDB / I64"]

    end

    %% =========================================================
    %% REPORT GENERATION
    %% =========================================================

    FINALSTATE --> REPORT
    REPORTONLY --> REPORT
    IOCs --> REPORT
    FINDINGS --> REPORT
    PROVENANCE --> REPORT

    subgraph REPORTING["13. AI Malware Report Generator"]

        REPORT["Report Generator"]

        REPORT --> EXECUTIVE["Executive Summary"]
        REPORT --> OVERVIEW["Sample Overview"]
        REPORT --> TECH["Technical Analysis"]
        REPORT --> FLOW["Execution / Infection Flow"]
        REPORT --> CAPS["Capabilities"]
        REPORT --> C2REPORT["Network / C2"]
        REPORT --> PERSISTREPORT["Persistence"]
        REPORT --> IOCREPORT["IOC Table"]
        REPORT --> MITRE["MITRE ATT&CK Mapping"]
        REPORT --> FUNCMAP["Important Function Map"]
        REPORT --> EVIDREPORT["Evidence / Confidence"]
        REPORT --> LIMIT["Unknowns / Limitations"]

        EXECUTIVE --> FINALREPORT
        OVERVIEW --> FINALREPORT
        TECH --> FINALREPORT
        FLOW --> FINALREPORT
        CAPS --> FINALREPORT
        C2REPORT --> FINALREPORT
        PERSISTREPORT --> FINALREPORT
        IOCREPORT --> FINALREPORT
        MITRE --> FINALREPORT
        FUNCMAP --> FINALREPORT
        EVIDREPORT --> FINALREPORT
        LIMIT --> FINALREPORT

        FINALREPORT["Full Malware Analysis Report<br/>Markdown / HTML / PDF"]

    end

    %% =========================================================
    %% CHANGE TRACKING
    %% =========================================================

    FINALSTATE --> CHANGELOG

    subgraph AUDIT["14. Audit / Provenance"]

        CHANGELOG["changes.json"]

        CHANGELOG --> BEFORE["Original Name / Type"]
        CHANGELOG --> AFTER["AI Proposed Value"]
        CHANGELOG --> WHY["Evidence"]
        CHANGELOG --> SCORE["Confidence"]
        CHANGELOG --> PASS["Analysis Pass"]
        CHANGELOG --> MODEL["Model / Timestamp"]

    end

    %% =========================================================
    %% FINAL PACKAGE
    %% =========================================================

    FINALIDB --> PACKAGE
    FINALREPORT --> PACKAGE
    CHANGELOG --> PACKAGE
    EDB --> PACKAGE

    subgraph OUTPUT["15. Final Analysis Package"]

        PACKAGE["Analysis Package"]

        PACKAGE --> O1["original.i64"]
        PACKAGE --> O2["analyzed.i64"]
        PACKAGE --> O3["report.pdf"]
        PACKAGE --> O4["report.md"]
        PACKAGE --> O5["findings.json"]
        PACKAGE --> O6["functions.json"]
        PACKAGE --> O7["iocs.json"]
        PACKAGE --> O8["callgraph.json"]
        PACKAGE --> O9["changes.json"]
        PACKAGE --> O10["pseudocode/"]
        PACKAGE --> O11["disassembly/"]

    end

    %% =========================================================
    %% HUMAN REVIEW
    %% =========================================================

    PACKAGE --> ANALYST

    subgraph HUMAN["16. Analyst Verification"]

        ANALYST["Malware Analyst"]

        ANALYST --> REVIEWIDB["Review Enriched IDB"]
        ANALYST --> REVIEWREPORT["Review Report"]
        ANALYST --> REVIEWAI["Review AI-Inferred Functions"]

        REVIEWIDB --> VERIFIED["Mark Verified"]
        REVIEWIDB --> REJECT["Reject / Correct"]
        REVIEWIDB --> DEEP["Request Deeper Investigation"]

        DEEP --> INVESTIGATE
        REJECT --> EDB

    end
```
