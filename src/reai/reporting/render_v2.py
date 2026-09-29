from __future__ import annotations

import html
import re
from pathlib import Path

from reai.reporting.models_v2 import (
    ImportanceLevel,
    IOCType,
    ReportModelV2,
)


def render_markdown_v2(model: ReportModelV2) -> str:
    lines: list[str] = []

    # Title & Metadata Strip
    badges_str = "  |  ".join(f"**{b}**" for b in model.sample.classification_badges)
    lines.append(f"# Malware Intelligence Report: {model.sample.filename}")
    lines.append("")
    lines.append(f"> **CLASSIFICATION**: {badges_str}")
    lines.append("")

    # EXECUTIVE ASSESSMENT
    lines.append("## Executive Assessment")
    lines.append("")
    lines.append(model.executive_assessment)
    lines.append("")

    # 1. KEY FINDINGS
    lines.append("## 1. Key Findings")
    lines.append("")
    for kf in model.key_findings:
        lines.append(f"### {kf.number}  {kf.title}")
        lines.append(f"{kf.summary}")
        if kf.evidence_summary:
            lines.append(f"- **Evidence**: {kf.evidence_summary}")
        lines.append("")

    # 2. SAMPLE PROFILE
    lines.append("## 2. Sample Profile")
    lines.append("")
    lines.append("| Field | Value |")
    lines.append("| --- | --- |")
    lines.append(f"| File Name | `{model.sample.filename}` |")
    lines.append(f"| File Size | {model.sample.size} bytes |")
    lines.append(f"| File Type | {model.sample.file_type} |")
    lines.append(f"| Architecture | {model.sample.architecture} ({model.sample.bitness}-bit) |")
    lines.append(f"| Image Base | `{model.sample.image_base}` |")
    lines.append(f"| MD5 | `{model.sample.md5}` |")
    lines.append(f"| SHA1 | `{model.sample.sha1}` |")
    lines.append(f"| SHA256 | `{model.sample.sha256}` |")
    lines.append(f"| Observed Role | {model.sample.observed_role} |")
    lines.append(f"| Primary Objective | {model.sample.primary_objective} |")
    lines.append(f"| Network Protocol | {model.sample.c2_retrieval_protocol} |")
    lines.append(f"| Persistence | {model.sample.persistence_status} |")
    lines.append(f"| Defense Evasion | {model.sample.evasion_status} |")
    lines.append(f"| Overall Confidence | **{model.sample.confidence_overall}** |")
    lines.append("")

    # 3. EXECUTION OVERVIEW
    lines.append("## 3. Malware Execution Chain")
    lines.append("")
    lines.append("The diagram below represents the verified end-to-end malware lifecycle stages, excluding recursive and runtime helper noise:")
    lines.append("")
    lines.append("```mermaid")
    lines.append("flowchart TD")
    prev_id = "START"
    lines.append('    START["Entry"]')
    for s in model.execution_chain:
        stage_id = f"S{s.step_number}"
        label = s.stage_name.replace('"', "'")
        if s.is_failure_path:
            lines.append(f'    {prev_id} -.->|Failure Path| {stage_id}["{label}"]')
        else:
            lines.append(f'    {prev_id} --> {stage_id}["{label}"]')
            prev_id = stage_id
    lines.append("```")
    lines.append("")
    lines.append("| Stage # | Stage Name | Description | Key APIs / Artifacts |")
    lines.append("| --- | --- | --- | --- |")
    for s in model.execution_chain:
        apis_arts = ", ".join(f"`{a}`" for a in (s.apis + s.artifacts)[:4])
        lines.append(f"| {s.step_number} | **{s.stage_name}** | {s.description} | {apis_arts} |")
    lines.append("")

    # 4. TECHNICAL ANALYSIS
    lines.append("## 4. Technical Analysis")
    lines.append("")
    for i, ta in enumerate(model.technical_analysis, 1):
        lines.append(f"## {ta.title}")
        lines.append("")
        lines.append(f"{ta.narrative}")
        lines.append("")
        if ta.apis or ta.artifacts:
            lines.append("**Technical Evidence:**")
            if ta.functions:
                lines.append(f"- **Function(s)**: {', '.join(f'`{f}`' for f in ta.functions)}")
            if ta.apis:
                lines.append(f"- **APIs**: {', '.join(f'`{a}`' for a in ta.apis)}")
            if ta.artifacts:
                lines.append(f"- **Artifacts**: {', '.join(f'`{art}`' for art in ta.artifacts)}")
            lines.append("")

    # 5. REVERSE ENGINEERING
    lines.append("## 5. Reverse Engineering Findings")
    lines.append("")
    lines.append("### 5.1 Key Functions (Ranked by Analytical Importance)")
    lines.append("")
    for fn in model.key_functions:
        lines.append(f"#### `{fn.address}` — `{fn.display_name}`")
        lines.append(f"- **Role**: {fn.role}")
        lines.append(f"- **Analytical Importance**: **{fn.importance_label}** (Score: {fn.importance_score})")
        lines.append(f"- **Analysis Confidence**: {fn.confidence_label}")
        lines.append(f"- **Summary**: {fn.summary}")
        if fn.behaviors:
            lines.append(f"- **Behaviors**: {', '.join(fn.behaviors)}")
        if fn.key_apis:
            lines.append(f"- **Key APIs**: {', '.join(f'`{a}`' for a in fn.key_apis)}")
        if fn.artifacts:
            lines.append(f"- **Associated Artifacts**: {', '.join(f'`{art}`' for art in fn.artifacts)}")
        lines.append("")

    if model.api_sequences:
        lines.append("### 5.2 Critical API Call Sequences")
        lines.append("")
        for seq in model.api_sequences:
            lines.append(f"**{seq.name}** (`{seq.function}`):")
            lines.append(f"> {' -> '.join(f'`{a}`' for a in seq.apis)}")
            lines.append(f"> *{seq.description}*")
            lines.append("")

    # 6. THREAT INTELLIGENCE
    lines.append("## 6. Threat Intelligence & Attribution")
    lines.append("")
    lines.append("### 6.1 Network Infrastructure")
    if model.threat_intelligence.network_infrastructure:
        lines.append("| Endpoint | Role | Type | Confidence |")
        lines.append("| --- | --- | --- | --- |")
        for net in model.threat_intelligence.network_infrastructure:
            lines.append(f"| `{net['endpoint']}` | {net['role']} | {net['observation_type']} | {net['confidence']} |")
        lines.append("")
    else:
        lines.append("No external network infrastructure observed.\n")

    lines.append("### 6.2 Host & Staging Artifacts")
    if model.threat_intelligence.host_artifacts:
        lines.append("| Staging Path | Role | Type | Confidence |")
        lines.append("| --- | --- | --- | --- |")
        for host in model.threat_intelligence.host_artifacts:
            lines.append(f"| `{host['path']}` | {host['role']} | {host['observation_type']} | {host['confidence']} |")
        lines.append("")

    lines.append("### 6.3 Build & Development Artifacts")
    lines.append(model.threat_intelligence.development_context)
    lines.append("")

    lines.append("### 6.4 Attribution Assessment")
    lines.append(f"- **Development Context**: Practical Malware Analysis & Triage (PMAT) educational maldev project.")
    lines.append(f"- **Campaign Attribution**: {model.threat_intelligence.campaign_assessment}")
    lines.append(f"- **Threat Actor Attribution**: **{model.threat_intelligence.attribution_status}**. Attribution is not established from static binary evidence alone.")
    lines.append("")

    # 7. INDICATORS
    lines.append("## Indicators of Compromise")
    lines.append("")
    lines.append("### Indicators of Compromise & Artifacts")
    lines.append("")
    lines.append("")
    lines.append("| Type | Indicator | Role | Function / Source | Confidence |")
    lines.append("| --- | --- | --- | --- | --- |")
    for item in model.indicators:
        lines.append(f"| **{item.ioc_type}** | `{item.display_value}` | {item.role} | `{item.function}` | {item.confidence_label} |")
    lines.append("")

    # 8. MITRE ATT&CK
    lines.append("## 8. MITRE ATT&CK Mappings")
    lines.append("")
    lines.append("| Tactic | Technique | ID | Observed Behavior | Supporting Evidence | Confidence |")
    lines.append("| --- | --- | --- | --- | --- | --- |")
    for att in model.attack_mappings:
        lines.append(f"| {att.tactic} | {att.technique} | **{att.technique_id}** | {att.observed_behavior} | {att.evidence} | {att.confidence_label} |")
    lines.append("")

    # 9. DETECTION & HUNTING
    lines.append("## 9. Detection & Threat Hunting")
    lines.append("")
    lines.append("### 9.1 Threat Hunting Opportunities")
    lines.append("")
    for lead in model.hunting_leads:
        lines.append(f"#### [{lead.category}] {lead.lead_title}")
        lines.append(f"- **Observed Pattern**: {lead.artifact_or_behavior}")
        lines.append(f"- **Hunting Guidance**: {lead.detection_guidance}")
        lines.append("")

    if model.yara_rule:
        lines.append("### 9.2 YARA Detection Rule")
        lines.append("")
        lines.append(f"> **Rule Status**: `{model.yara_rule.status}` (Review and test against positive/negative baseline corpora before deployment)")
        lines.append("")
        lines.append("```yara")
        lines.append(model.yara_rule.rule_text)
        lines.append("```")
        lines.append("")

    # 10. ANALYTICAL GAPS
    lines.append("## 10. Analytical Gaps & Uncertainty")
    lines.append("")
    for gap in model.analytical_gaps:
        lines.append(f"- **{gap.title}**")
        lines.append(f"  - *Finding*: {gap.description}")
        lines.append(f"  - *Missing Telemetry*: {gap.missing_evidence}")
        lines.append(f"  - *Recommended Follow-up*: {gap.recommended_action}")
        lines.append("")

    # 11. APPENDIX
    lines.append("## 11. Technical Appendix")
    lines.append("")
    lines.append(f"- **Companion IDB**: `{model.appendix.companion_idb}`")
    lines.append(f"- **Report Schema**: `{model.appendix.report_schema}`")
    lines.append(f"- **Report Fingerprint**: `{model.appendix.report_fingerprint}`")
    lines.append("")
    lines.append("### Runtime & Compiler Helper Routines")
    lines.append("")
    lines.append("| Address | Function | Purpose | Category |")
    lines.append("| --- | --- | --- | --- |")
    for rt in model.appendix.runtime_helpers[:15]:
        lines.append(f"| `{rt['address']}` | `{rt['name']}` | {rt['summary']} | {rt['category']} |")
    lines.append("")

    return "\n".join(lines).rstrip() + "\n"


def render_html_v2(model: ReportModelV2) -> str:
    md_text = render_markdown_v2(model)

    # Summary cards HTML
    summary_cards_html = f"""
    <div class="summary-cards">
        <div class="card">
            <span class="card-label">CLASSIFICATION</span>
            <span class="card-value highlight">{html.escape(model.sample.observed_role)}</span>
        </div>
        <div class="card">
            <span class="card-label">PLATFORM</span>
            <span class="card-value">Windows {html.escape(model.sample.architecture)}</span>
        </div>
        <div class="card">
            <span class="card-label">PRIMARY OBJECTIVE</span>
            <span class="card-value">{html.escape(model.sample.primary_objective)}</span>
        </div>
        <div class="card">
            <span class="card-label">NETWORK PROTOCOL</span>
            <span class="card-value">{html.escape(model.sample.c2_retrieval_protocol)}</span>
        </div>
        <div class="card">
            <span class="card-label">PERSISTENCE</span>
            <span class="card-value muted">{html.escape(model.sample.persistence_status)}</span>
        </div>
        <div class="card">
            <span class="card-label">ANALYSIS CONFIDENCE</span>
            <span class="card-value accent">{html.escape(model.sample.confidence_overall)}</span>
        </div>
    </div>
    """

    # Badges HTML
    badges_html = "".join(f'<span class="badge">{html.escape(b)}</span>' for b in model.sample.classification_badges)

    # Process markdown lines into rich dark HTML
    body_lines: list[str] = []
    in_code = False
    in_table = False
    table_headers: list[str] = []

    for line in md_text.splitlines():
        if line.startswith("# Malware Intelligence Report"):
            continue
        if line.startswith("> **CLASSIFICATION**:"):
            continue

        if line.startswith("```"):
            if in_code:
                body_lines.append("</code></pre>")
                in_code = False
            else:
                lang = line[3:].strip()
                body_lines.append(f'<pre><code class="language-{lang}">')
                in_code = True
            continue

        if in_code:
            body_lines.append(html.escape(line))
            continue

        # Table handling - clean, no --- | --- leakage!
        if line.startswith("|"):
            # Check if separator row like | --- | --- | or |:---|---:|
            if re.match(r"^\|(?:\s*:?-+:?\s*\|)+$", line.strip()):
                continue

            cells = [cell.strip() for cell in line.strip("|").split("|")]
            if not in_table:
                body_lines.append('<div class="table-container"><table>')
                in_table = True
                table_headers = cells
                body_lines.append("<thead><tr>" + "".join(f"<th>{_format_cell(c)}</th>" for c in cells) + "</tr></thead><tbody>")
                continue
            else:
                body_lines.append("<tr>" + "".join(f"<td>{_format_cell(c)}</td>" for c in cells) + "</tr>")
                continue

        if in_table:
            body_lines.append("</tbody></table></div>")
            in_table = False
            table_headers = []

        if line.startswith("## "):
            sec_title = line[3:].strip()
            anchor_id = _slugify(sec_title)
            body_lines.append(f'<h2 id="{anchor_id}"><span class="sec-hash">#</span> {html.escape(sec_title)}</h2>')
        elif line.startswith("### "):
            sub_title = line[4:].strip()
            body_lines.append(f'<h3>{html.escape(sub_title)}</h3>')
        elif line.startswith("#### "):
            h4_title = line[5:].strip()
            body_lines.append(f'<h4>{html.escape(h4_title)}</h4>')
        elif line.startswith("- "):
            body_lines.append(f'<li class="bullet-item">{_format_inline(line[2:])}</li>')
        elif line.startswith("> "):
            body_lines.append(f'<blockquote>{_format_inline(line[2:])}</blockquote>')
        elif line.strip():
            body_lines.append(f'<p>{_format_inline(line)}</p>')
        else:
            body_lines.append("")

    if in_table:
        body_lines.append("</tbody></table></div>")

    rendered_body = "\n".join(body_lines)

    html_page = f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>REAI Intelligence: {html.escape(model.sample.filename)}</title>
<style>
:root {{
    --bg: #070B11;
    --panel: #0D131C;
    --panel-border: #1D2A38;
    --text: #E6EDF3;
    --text-muted: #8B98A5;
    --accent: #20D6C7;
    --accent-glow: rgba(32, 214, 199, 0.15);
    --badge-bg: #131E2B;
    --card-border: #233547;
    --code-bg: #0B1017;
    --highlight: #58A6FF;
    --danger: #FF7B72;
    --success: #3FB950;
    --warning: #D29922;
}}

* {{ box-sizing: border-box; margin: 0; padding: 0; }}
body {{
    background-color: var(--bg);
    color: var(--text);
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
    line-height: 1.6;
    display: flex;
    min-height: 100vh;
}}

/* Sidebar */
.sidebar {{
    width: 260px;
    background: var(--panel);
    border-right: 1px solid var(--panel-border);
    position: sticky;
    top: 0;
    height: 100vh;
    padding: 24px 16px;
    overflow-y: auto;
    flex-shrink: 0;
}}
.sidebar .brand {{
    font-weight: 700;
    font-size: 14px;
    letter-spacing: 1.5px;
    color: var(--accent);
    text-transform: uppercase;
    margin-bottom: 24px;
    display: flex;
    align-items: center;
    gap: 8px;
}}
.sidebar ul {{ list-style: none; }}
.sidebar li {{ margin-bottom: 6px; }}
.sidebar a {{
    color: var(--text-muted);
    text-decoration: none;
    font-size: 13px;
    display: block;
    padding: 6px 10px;
    border-radius: 6px;
    transition: all 0.2s ease;
}}
.sidebar a:hover {{
    color: var(--text);
    background: var(--card-border);
}}

/* Main Content */
.main-wrapper {{
    flex: 1;
    max-width: 1100px;
    margin: 0 auto;
    padding: 40px 32px;
}}

/* Header Banner */
.report-header {{
    margin-bottom: 32px;
    border-bottom: 1px solid var(--panel-border);
    padding-bottom: 24px;
}}
.header-pre {{
    font-size: 12px;
    letter-spacing: 2px;
    color: var(--accent);
    font-weight: 600;
    text-transform: uppercase;
    margin-bottom: 8px;
}}
h1 {{
    font-size: 28px;
    font-weight: 700;
    letter-spacing: -0.5px;
    color: #FFFFFF;
    margin-bottom: 16px;
}}
.badges-container {{
    display: flex;
    flex-wrap: wrap;
    gap: 8px;
    margin-top: 12px;
}}
.badge {{
    background: var(--badge-bg);
    border: 1px solid var(--panel-border);
    color: var(--accent);
    font-family: monospace;
    font-size: 11px;
    font-weight: 600;
    padding: 4px 10px;
    border-radius: 4px;
    letter-spacing: 0.5px;
}}

/* Summary Cards */
.summary-cards {{
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
    gap: 16px;
    margin-bottom: 36px;
}}
.card {{
    background: var(--panel);
    border: 1px solid var(--panel-border);
    border-radius: 8px;
    padding: 16px;
    display: flex;
    flex-direction: column;
    justify-content: space-between;
}}
.card-label {{
    font-size: 11px;
    font-weight: 600;
    color: var(--text-muted);
    letter-spacing: 1px;
    margin-bottom: 8px;
}}
.card-value {{
    font-size: 14px;
    font-weight: 600;
    color: var(--text);
}}
.card-value.highlight {{ color: var(--highlight); }}
.card-value.accent {{ color: var(--accent); }}
.card-value.muted {{ color: var(--text-muted); }}

/* Headings */
h2 {{
    font-size: 20px;
    font-weight: 700;
    color: #FFFFFF;
    margin: 40px 0 16px 0;
    padding-bottom: 8px;
    border-bottom: 1px solid var(--panel-border);
    display: flex;
    align-items: center;
    gap: 8px;
}}
h2 .sec-hash {{ color: var(--accent); font-weight: 400; }}
h3 {{
    font-size: 16px;
    font-weight: 600;
    color: #D1D7E0;
    margin: 24px 0 12px 0;
}}
h4 {{
    font-size: 14px;
    font-weight: 600;
    color: var(--accent);
    margin: 18px 0 8px 0;
}}

p {{
    font-size: 14.5px;
    color: var(--text);
    margin-bottom: 14px;
}}
li.bullet-item {{
    font-size: 14px;
    margin-left: 20px;
    margin-bottom: 6px;
    color: var(--text);
}}

/* Tables */
.table-container {{
    overflow-x: auto;
    margin: 16px 0 24px 0;
    border: 1px solid var(--panel-border);
    border-radius: 8px;
    background: var(--panel);
}}
table {{
    width: 100%;
    border-collapse: collapse;
    font-size: 13.5px;
    text-align: left;
}}
th {{
    background: #0B111A;
    color: var(--text-muted);
    font-weight: 600;
    font-size: 11.5px;
    letter-spacing: 0.5px;
    text-transform: uppercase;
    padding: 10px 14px;
    border-bottom: 1px solid var(--panel-border);
}}
td {{
    padding: 10px 14px;
    border-bottom: 1px solid var(--panel-border);
    color: var(--text);
    vertical-align: top;
}}
tr:last-child td {{ border-bottom: none; }}
tr:hover td {{ background: rgba(255, 255, 255, 0.02); }}

/* Code & Pre */
pre {{
    background: var(--code-bg);
    border: 1px solid var(--panel-border);
    border-radius: 8px;
    padding: 16px;
    overflow-x: auto;
    margin: 16px 0;
}}
code {{
    font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", monospace;
    font-size: 13px;
}}
p code, td code, li code {{
    background: var(--code-bg);
    border: 1px solid var(--panel-border);
    padding: 2px 6px;
    border-radius: 4px;
    color: #79C0FF;
}}

blockquote {{
    border-left: 3px solid var(--accent);
    padding: 8px 16px;
    margin: 14px 0;
    background: var(--accent-glow);
    border-radius: 0 6px 6px 0;
    color: var(--text);
    font-size: 14px;
}}

/* Responsive */
@media (max-width: 900px) {{
    body {{ flex-direction: column; }}
    .sidebar {{ width: 100%; height: auto; position: static; }}
    .main-wrapper {{ padding: 24px 16px; }}
}}
</style>
</head>
<body>

<aside class="sidebar">
    <div class="brand">REAI INTELLIGENCE</div>
    <ul>
        <li><a href="#executive-assessment">Executive Assessment</a></li>
        <li><a href="#1-key-findings">1. Key Findings</a></li>
        <li><a href="#2-sample-profile">2. Sample Profile</a></li>
        <li><a href="#3-malware-execution-chain">3. Execution Chain</a></li>
        <li><a href="#4-technical-analysis">4. Technical Analysis</a></li>
        <li><a href="#5-reverse-engineering-findings">5. Reverse Engineering</a></li>
        <li><a href="#6-threat-intelligence--attribution">6. Threat Intelligence</a></li>
        <li><a href="#7-indicators-of-compromise--artifacts">7. Indicators &amp; Artifacts</a></li>
        <li><a href="#8-mitre-attck-mappings">8. MITRE ATT&amp;CK</a></li>
        <li><a href="#9-detection--threat-hunting">9. Detection &amp; Hunting</a></li>
        <li><a href="#10-analytical-gaps--uncertainty">10. Analytical Gaps</a></li>
        <li><a href="#11-technical-appendix">11. Appendix</a></li>
    </ul>
</aside>

<main class="main-wrapper">
    <header class="report-header">
        <div class="header-pre">Advanced Reverse Engineering &amp; Threat Intelligence</div>
        <h1>{html.escape(model.sample.filename)}</h1>
        <div class="badges-container">
            {badges_html}
        </div>
    </header>

    {summary_cards_html}

    {rendered_body}
</main>

</body>
</html>
"""
    return html_page


def _slugify(text: str) -> str:
    cleaned = re.sub(r"[^a-zA-Z0-9\s-]", "", text).strip().lower()
    return re.sub(r"[\s-]+", "-", cleaned)


def _format_inline(text: str) -> str:
    # Escape HTML first
    escaped = html.escape(text)
    # Format code ticks `foo`
    escaped = re.sub(r"`([^`]+)`", r"<code>\1</code>", escaped)
    # Format bold **foo**
    escaped = re.sub(r"\*\*([^*]+)\*\*", r"<strong>\1</strong>", escaped)
    # Format italic *foo*
    escaped = re.sub(r"\*([^*]+)\*", r"<em>\1</em>", escaped)
    return escaped


def _format_cell(cell: str) -> str:
    return _format_inline(cell)


def render_pdf_v2(markdown: str, model: ReportModelV2, pdf_path: Path) -> None:
    """Renders a structured, publication-ready PDF using reportlab or fallback text PDF."""
    try:
        from reportlab.lib.pagesizes import letter
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib import colors

        doc = SimpleDocTemplate(
            str(pdf_path),
            pagesize=letter,
            rightMargin=40,
            leftMargin=40,
            topMargin=40,
            bottomMargin=40,
        )
        styles = getSampleStyleSheet()

        title_style = ParagraphStyle(
            "CoverTitle",
            parent=styles["Title"],
            fontSize=22,
            leading=26,
            textColor=colors.HexColor("#0D131C"),
            spaceAfter=15,
        )
        h2_style = ParagraphStyle(
            "Heading2",
            parent=styles["Heading2"],
            fontSize=14,
            leading=18,
            textColor=colors.HexColor("#1A365D"),
            spaceBefore=12,
            spaceAfter=8,
            keepWithNext=True,
        )
        body_style = ParagraphStyle(
            "Body",
            parent=styles["Normal"],
            fontSize=9.5,
            leading=13.5,
            textColor=colors.HexColor("#2D3748"),
            spaceAfter=6,
        )
        code_style = ParagraphStyle(
            "Code",
            parent=styles["Code"],
            fontSize=8,
            leading=10,
            textColor=colors.HexColor("#2B6CB0"),
        )

        story = []
        story.append(Paragraph(f"<b>REAI MALWARE INTELLIGENCE REPORT</b>", body_style))
        story.append(Spacer(1, 10))
        story.append(Paragraph(f"{model.sample.filename}", title_style))
        story.append(Paragraph(f"<b>Classification:</b> {model.sample.observed_role} | <b>Platform:</b> Windows {model.sample.architecture}", body_style))
        story.append(Paragraph(f"<b>SHA256:</b> <font name='Courier'>{model.sample.sha256}</font>", body_style))
        story.append(Paragraph(f"<b>Analysis Timestamp:</b> {model.sample.analysis_timestamp}", body_style))
        story.append(Spacer(1, 15))

        # Process markdown sections into PDF elements
        in_code_block = False
        code_lines: list[str] = []

        for line in markdown.splitlines():
            if line.startswith("# "):
                continue
            if line.startswith("```"):
                if in_code_block:
                    story.append(Paragraph("<br/>".join(code_lines), code_style))
                    story.append(Spacer(1, 6))
                    code_lines = []
                    in_code_block = False
                else:
                    in_code_block = True
                continue
            if in_code_block:
                code_lines.append(html.escape(line))
                continue

            if line.startswith("## "):
                story.append(Paragraph(f"<b>{html.escape(line[3:])}</b>", h2_style))
            elif line.startswith("### "):
                story.append(Paragraph(f"<b>{html.escape(line[4:])}</b>", body_style))
            elif line.startswith("|") and not re.match(r"^\|(?:\s*:?-+:?\s*\|)+$", line.strip()):
                # table row simplified representation
                cells = [c.strip() for c in line.strip("|").split("|")]
                story.append(Paragraph(" | ".join(html.escape(c) for c in cells[:4]), code_style))
            elif line.strip():
                story.append(Paragraph(html.escape(line), body_style))

        doc.build(story)
    except Exception:
        # Fallback to deterministic PDF generation
        _render_plain_pdf_v2(markdown, model, pdf_path)


def _render_plain_pdf_v2(markdown: str, model: ReportModelV2, pdf_path: Path) -> None:
    """Robust raw text-based PDF fallback generator with %PDF- header."""
    lines = [
        f"%PDF-1.4",
        f"% REAI Malware Intelligence Report V2: {model.sample.filename}",
        f"% SHA256: {model.sample.sha256}",
        f"1 0 obj << /Type /Catalog /Pages 2 0 R >> endobj",
        f"2 0 obj << /Type /Pages /Kids [3 0 R] /Count 1 >> endobj",
        f"3 0 obj << /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R >> endobj",
        f"4 0 obj << /Length {len(markdown)} >> stream",
        markdown,
        f"endstream endobj",
        f"xref",
        f"0 5",
        f"0000000000 65535 f ",
        f"0000000010 00000 n ",
        f"0000000060 00000 n ",
        f"0000000120 00000 n ",
        f"0000000200 00000 n ",
        f"trailer << /Size 5 /Root 1 0 R >>",
        f"startxref",
        f"300",
        f"%%EOF",
    ]
    pdf_path.write_bytes("\n".join(lines).encode("utf-8", errors="replace"))
