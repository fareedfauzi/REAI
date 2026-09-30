from __future__ import annotations

import html
import re
import textwrap
from pathlib import Path

from reai.core.config import ReportConfig
from reai.reporting.schemas import ReportModel


def render_markdown(model: ReportModel, config: ReportConfig) -> str:
    lines = [
        f"# Malware Analysis Report: {_md(model.sample.filename)}",
        "",
        _section_text(model, "executive_summary"),
        _sample_information(model),
        _section_text(model, "technical_overview"),
    ]
    if model.execution_flows:
        lines.extend([_section_text(model, "execution_flow"), _execution_flow(model)])
    if model.configuration:
        lines.extend([_section_text(model, "configuration"), _configuration_table(model)])
    for section in model.sections:
        if section.section_id.startswith("behavior_"):
            subsystem_id = section.section_id.removeprefix("behavior_")
            subsystem = next(item for item in model.subsystems if item.subsystem_id == subsystem_id)
            lines.extend([_section_text(model, section.section_id), _subsystem_table(subsystem)])
    if model.commands:
        lines.extend([_section_text(model, "command_dispatch"), _command_table(model)])
    if model.iocs:
        lines.extend([_section_text(model, "iocs"), _ioc_table(model)])
    if model.attack_mappings:
        lines.extend([_section_text(model, "mitre_attack"), _attack_table(model, config.attack_version)])
    lines.extend([_section_text(model, "important_functions"), _function_table(model, config)])
    if model.structures:
        lines.extend([_section_text(model, "recovered_structures"), _structures(model)])
    lines.extend([_section_text(model, "evidence_confidence")])
    if model.contradictions or model.limitations:
        lines.extend([_section_text(model, "limitations"), _limitations(model)])
    if any(s.section_id == "yara_rule" for s in model.sections):
        lines.extend([_section_text(model, "yara_rule"), _yara_rule_block(model)])
    lines.extend([_section_text(model, "appendix"), _appendix(model)])
    return "\n".join(line for line in lines if line is not None).rstrip() + "\n"


def render_html(markdown: str, model: ReportModel) -> str:
    body_lines: list[str] = []
    in_code = False
    in_table = False
    for line in markdown.splitlines():
        if line.startswith("```"):
            if in_code:
                body_lines.append("</code></pre>")
                in_code = False
            else:
                body_lines.append("<pre><code>")
                in_code = True
            continue
        if in_code:
            body_lines.append(html.escape(line))
            continue
        if line.startswith("|"):
            if not in_table:
                body_lines.append("<table>")
                in_table = True
            if re.match(r"^\|[-: ]+\|$", line):
                continue
            cells = [html.escape(cell.strip()) for cell in line.strip("|").split("|")]
            tag = "th" if cells and cells[0] in {"Field", "Address", "Type", "Command", "Technique", "Name", "Offset", "Source", "Category", "Algorithm"} else "td"
            body_lines.append("<tr>" + "".join(f"<{tag}>{cell}</{tag}>" for cell in cells) + "</tr>")
            continue
        if in_table:
            body_lines.append("</table>")
            in_table = False
        if line.startswith("# "):
            body_lines.append(f"<h1>{html.escape(line[2:])}</h1>")
        elif line.startswith("## "):
            body_lines.append(f"<h2 id=\"{_anchor(line[3:])}\">{html.escape(line[3:])}</h2>")
        elif line.startswith("### "):
            body_lines.append(f"<h3 id=\"{_anchor(line[4:])}\">{html.escape(line[4:])}</h3>")
        elif line.startswith("- "):
            body_lines.append(f"<p>{html.escape(line)}</p>")
        elif line.strip():
            body_lines.append(f"<p>{html.escape(line)}</p>")
        else:
            body_lines.append("")
    if in_table:
        body_lines.append("</table>")
    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>{html.escape(model.sample.filename)} malware analysis report</title>
<style>
body {{ font-family: Segoe UI, Arial, sans-serif; line-height: 1.45; max-width: 1100px; margin: 32px auto; padding: 0 24px; color: #151515; }}
h1, h2, h3 {{ color: #111; }}
code, pre {{ background: #f4f4f4; }}
pre {{ padding: 12px; overflow-x: auto; }}
table {{ border-collapse: collapse; width: 100%; margin: 16px 0; font-size: 14px; }}
th, td {{ border: 1px solid #d0d0d0; padding: 6px 8px; vertical-align: top; }}
th {{ background: #efefef; text-align: left; }}
</style>
</head>
<body>
{chr(10).join(body_lines)}
</body>
</html>
"""


def render_pdf(markdown: str, output: Path) -> None:
    text_lines = _markdown_to_text(markdown)
    pages = []
    current: list[str] = []
    for line in text_lines:
        wrapped = textwrap.wrap(line, width=92) or [""]
        for item in wrapped:
            current.append(item)
            if len(current) >= 54:
                pages.append(current)
                current = []
    if current:
        pages.append(current)
    _write_simple_pdf(output, pages or [["Malware Analysis Report"]])


def _section_text(model: ReportModel, section_id: str) -> str:
    section = next((item for item in model.sections if item.section_id == section_id), None)
    if section is None:
        return ""
    text = f"## {section.title}\n\n"
    if section.narrative:
        text += f"{_md(section.narrative)}\n"
    return text


def _sample_information(model: ReportModel) -> str:
    sample = model.sample
    rows = [
        ("File name", sample.filename),
        ("File size", str(sample.size)),
        ("MD5", sample.md5),
        ("SHA1", sample.sha1),
        ("SHA256", sample.sha256),
        ("Architecture", sample.architecture or "unknown"),
        ("Bitness", str(sample.bitness) if sample.bitness else "unknown"),
        ("File type", sample.file_type or "unknown"),
        ("Image base", sample.image_base or "unknown"),
        ("IDA version", sample.ida_version or "unknown"),
        ("REAI version", sample.reai_version),
        ("Analysis timestamp", sample.analysis_timestamp),
    ]
    return "## Sample Information\n\n" + _table(["Field", "Value"], rows)


def _execution_flow(model: ReportModel) -> str:
    rows = [
        (
            f"{flow.source.display_name} ({flow.source.address})",
            f"{flow.target.display_name} ({flow.target.address})",
            flow.relationship,
            f"{flow.confidence:.2f}",
        )
        for flow in model.execution_flows
    ]
    diagram = _mermaid_flow(model)
    return diagram + "\n" + _table(["Source", "Target", "Relationship", "Confidence"], rows)


def _mermaid_flow(model: ReportModel) -> str:
    nodes: dict[str, str] = {}
    lines = ["```mermaid", "flowchart TD"]
    for flow in model.execution_flows[:30]:
        source_id = nodes.setdefault(flow.source.address, f"N{len(nodes) + 1}")
        target_id = nodes.setdefault(flow.target.address, f"N{len(nodes) + 1}")
        lines.append(f'    {source_id}["{_mermaid_label(flow.source.display_name)}"] --> {target_id}["{_mermaid_label(flow.target.display_name)}"]')
    lines.append("```")
    return "\n".join(lines) + "\n"


def _configuration_table(model: ReportModel) -> str:
    return _table(
        ["Field", "Value", "Type", "Function", "Confidence"],
        [
            (
                item.key,
                item.display_value or "",
                item.value_type,
                item.function.display_name if item.function else "",
                f"{item.confidence:.2f}",
            )
            for item in model.configuration
        ],
    )


def _subsystem_table(subsystem) -> str:
    rows = [
        (function.address, function.display_name, function.summary or "", ", ".join(function.imports[:5]), f"{function.confidence:.2f}")
        for function in subsystem.functions[:15]
    ]
    return _table(["Address", "Function", "Purpose", "APIs", "Confidence"], rows)


def _command_table(model: ReportModel) -> str:
    return _table(
        ["Command", "Dispatcher", "Handler", "Behavior", "Confidence"],
        [
            (
                command.command_id,
                command.dispatcher.display_name if command.dispatcher else "",
                command.handler.display_name if command.handler else command.handler_name or "",
                command.handler.summary if command.handler else "",
                f"{command.confidence:.2f}",
            )
            for command in model.commands
        ],
    )


def _ioc_table(model: ReportModel) -> str:
    return _table(
        ["Type", "Indicator", "Role", "Context", "Confidence"],
        [(ioc.artifact_type, ioc.display_value, ioc.role, ioc.usage or "", f"{ioc.confidence:.2f}") for ioc in model.iocs],
    )


def _attack_table(model: ReportModel, version: str) -> str:
    intro = f"ATT&CK mapping source: `{_md(version)}`.\n\n"
    return intro + _table(
        ["Technique", "ID", "Evidence", "Functions", "Confidence"],
        [
            (
                mapping.technique,
                mapping.technique_id,
                mapping.evidence,
                ", ".join(function.display_name for function in mapping.functions),
                f"{mapping.confidence:.2f}",
            )
            for mapping in model.attack_mappings
        ],
    )


def _function_table(model: ReportModel, config: ReportConfig) -> str:
    return _table(
        ["Address", "Function", "Purpose", "Confidence", "IDB Status"],
        [
            (
                function.address,
                function.display_name,
                function.summary or "",
                f"{function.confidence_label} ({function.confidence:.2f})",
                function.idb_status or "semantic-only",
            )
            for function in model.functions[: config.max_important_functions]
        ],
    )


def _structures(model: ReportModel) -> str:
    chunks = []
    for structure in model.structures:
        chunks.append(f"### {_md(structure.name)}\n")
        chunks.append(_table(["Offset", "Field", "Type", "Confidence"], [(field.offset, field.name, field.field_type, f"{field.confidence:.2f}") for field in structure.fields]))
    return "\n".join(chunks)


def _limitations(model: ReportModel) -> str:
    lines = []
    for limitation in model.limitations:
        lines.append(f"- {_md(limitation)}")
    for contradiction in model.contradictions:
        lines.append(f"- {_md(contradiction.severity)} contradiction: {_md(contradiction.description)}")
    return "\n".join(lines)


def _yara_rule_block(model: ReportModel) -> str:
    safe_name = re.sub(r"[^A-Za-z0-9_]", "_", model.sample.filename).strip("_")
    rule_name = f"Trojan_Win32_{safe_name}"
    sha256 = model.sample.sha256
    md5 = model.sample.md5
    date_str = str(model.sample.analysis_timestamp).split("T")[0] if "T" in str(model.sample.analysis_timestamp) else "2026-09-30"

    strings_lines = []
    seen = set()
    idx = 0
    for artifact in model.artifacts:
        val = artifact.normalized_value or artifact.original_value
        if not val or val.lower() in seen or len(val) < 4:
            continue
        if artifact.artifact_type in {"url", "domain", "file_path", "pdb_path", "command_line"} or artifact.is_ioc:
            seen.add(val.lower())
            idx += 1
            escaped = val.replace("\\", "\\\\").replace('"', '\\"')
            if artifact.artifact_type in {"url", "file_path", "command_line"}:
                strings_lines.append(f'        $s{idx} = "{escaped}" ascii wide nocase')
            else:
                strings_lines.append(f'        $s{idx} = "{escaped}" ascii nocase')

    if not strings_lines:
        strings_lines.append(f'        $sha256 = "{sha256}" ascii')

    cond = ["uint16(0) == 0x5A4D", f"filesize < {max(50000, model.sample.size * 2)}"]
    if idx >= 2:
        cond.append("2 of ($s*)")
    elif idx == 1:
        cond.append("$s1")
    else:
        cond.append("all of them")

    rule_lines = [
        f"rule {rule_name}",
        "{",
        "    meta:",
        f'        description = "Detects {model.sample.filename} malware artifacts and stager logic"',
        '        author = "REAI Automated Threat Analysis"',
        f'        date = "{date_str}"',
        f'        sample_sha256 = "{sha256}"',
        f'        sample_md5 = "{md5}"',
        '        tlp = "CLEAR"',
        "    strings:",
        *strings_lines[:15],
        "    condition:",
        f"        {' and '.join(cond)}",
        "}",
    ]
    return "```yara\n" + "\n".join(rule_lines) + "\n```\n"


def _appendix(model: ReportModel) -> str:
    rows = [
        ("Report schema", model.schema_version),
        ("Report fingerprint", model.fingerprint),
        ("Validated analysis fingerprint", model.source_analysis_fingerprint or ""),
        ("IDB enrichment fingerprint", model.enrichment_fingerprint or ""),
        ("Companion IDB", "IDB Files/analyzed.i64"),
    ]
    return _table(["Field", "Value"], rows)


def _table(headers: list[str], rows: list[tuple]) -> str:
    lines = ["| " + " | ".join(_md(header) for header in headers) + " |"]
    lines.append("| " + " | ".join("---" for _ in headers) + " |")
    for row in rows:
        lines.append("| " + " | ".join(_md(str(cell)) for cell in row) + " |")
    return "\n".join(lines) + "\n"


def _md(value: str) -> str:
    return str(value).replace("|", "\\|").replace("<", "&lt;").replace(">", "&gt;")


def _mermaid_label(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9_ .:/()-]", "_", value)[:80].replace('"', "'")


def _anchor(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")


def _markdown_to_text(markdown: str) -> list[str]:
    lines = []
    in_code = False
    for line in markdown.splitlines():
        if line.startswith("```"):
            in_code = not in_code
            continue
        if line.startswith("|") and re.match(r"^\|[-: ]+\|$", line):
            continue
        line = re.sub(r"^#{1,6}\s*", "", line)
        line = line.replace("|", "  ")
        lines.append(html.unescape(line))
    return lines


def _write_simple_pdf(output: Path, pages: list[list[str]]) -> None:
    objects: list[bytes] = []
    catalog_id = 1
    pages_id = 2
    font_id = 3
    page_ids = []
    content_ids = []
    for page in pages:
        page_ids.append(len(objects) + 4)
        content_ids.append(len(objects) + 5)
        objects.extend([b"", b""])
    kids = " ".join(f"{page_id} 0 R" for page_id in page_ids)
    objects = [
        f"<< /Type /Catalog /Pages {pages_id} 0 R >>".encode("ascii"),
        f"<< /Type /Pages /Kids [{kids}] /Count {len(page_ids)} >>".encode("ascii"),
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Courier >>",
    ]
    for page_id, content_id, page in zip(page_ids, content_ids, pages):
        stream = _pdf_text_stream(page)
        objects.append(
            f"<< /Type /Page /Parent {pages_id} 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 {font_id} 0 R >> >> /Contents {content_id} 0 R >>".encode("ascii")
        )
        objects.append(f"<< /Length {len(stream)} >>\nstream\n".encode("ascii") + stream + b"\nendstream")
    offsets = [0]
    data = bytearray(b"%PDF-1.4\n")
    for index, obj in enumerate(objects, start=1):
        offsets.append(len(data))
        data.extend(f"{index} 0 obj\n".encode("ascii"))
        data.extend(obj)
        data.extend(b"\nendobj\n")
    xref_offset = len(data)
    data.extend(f"xref\n0 {len(objects) + 1}\n0000000000 65535 f \n".encode("ascii"))
    for offset in offsets[1:]:
        data.extend(f"{offset:010d} 00000 n \n".encode("ascii"))
    data.extend(f"trailer << /Root {catalog_id} 0 R /Size {len(objects) + 1} >>\nstartxref\n{xref_offset}\n%%EOF\n".encode("ascii"))
    output.write_bytes(bytes(data))


def _pdf_text_stream(lines: list[str]) -> bytes:
    chunks = ["BT", "/F1 9 Tf", "50 760 Td", "12 TL"]
    for line in lines:
        chunks.append(f"({_pdf_escape(line)}) Tj")
        chunks.append("T*")
    chunks.append("ET")
    return "\n".join(chunks).encode("latin-1", errors="replace")


def _pdf_escape(value: str) -> str:
    return value.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")
