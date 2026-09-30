from __future__ import annotations

from reai.mcp.importance import FILE_TERMS, NETWORK_TERMS, PROCESS_TERMS
from reai.mcp.schemas import AnalyticalImportance, InvestigationQuestion, InvestigationReason


def generate_investigation_questions(
    *,
    sample_id: str,
    function_address: str,
    importance: AnalyticalImportance,
    name: str,
    proposed_name: str | None,
    summary: str | None,
    unknowns: list[str],
    evidence: list[dict],
    imports: list[str],
    confidence_label: str,
) -> list[InvestigationQuestion]:
    text = _text(name, proposed_name, summary, unknowns, evidence, imports)
    questions: list[InvestigationQuestion] = []

    def add(question: str, reason: InvestigationReason, priority: AnalyticalImportance | None = None) -> None:
        if question not in {item.question for item in questions}:
            questions.append(
                InvestigationQuestion(
                    sample_id=sample_id,
                    function_address=function_address,
                    question=question,
                    reason=reason,
                    priority=priority or importance,
                )
            )

    if confidence_label == "LOW":
        add("What is this function's primary purpose?", InvestigationReason.LOW_CONFIDENCE, AnalyticalImportance.MEDIUM)
    if importance == AnalyticalImportance.HIGH:
        add("Does this function belong to the malware execution path?", InvestigationReason.IMPORTANT_FUNCTION)
        add("Who calls this function and what depends on its result?", InvestigationReason.UNKNOWN_CALL_RELATIONSHIP)
    if any(term in text for term in NETWORK_TERMS):
        add("What endpoint or network artifact does this function use?", InvestigationReason.UNKNOWN_NETWORK_CONTEXT)
        add("Where does network response data go after this function runs?", InvestigationReason.UNKNOWN_DATA_USAGE)
    if any(term in text for term in FILE_TERMS):
        add("How is the referenced file path used: created, written, read, executed, or deleted?", InvestigationReason.UNKNOWN_FILE_CONTEXT)
    if any(term in text for term in PROCESS_TERMS):
        add("What path or command does this function execute?", InvestigationReason.UNKNOWN_EXECUTION_CONTEXT)
    if any("string" in item.lower() or "xref" in item.lower() for item in unknowns):
        add("Where is the important string or artifact referenced?", InvestigationReason.UNKNOWN_STRING_USAGE)
    if any(word in text for word in ("config", "configuration", "campaign", "mutex")):
        add("Which function parses or consumes this configuration-like value?", InvestigationReason.UNKNOWN_CONFIGURATION_CONTEXT)
    for unknown in unknowns[:3]:
        add(unknown.rstrip("?") + "?", _reason_for_unknown(unknown), AnalyticalImportance.MEDIUM)

    return questions[:6]


def _reason_for_unknown(unknown: str) -> InvestigationReason:
    lowered = unknown.lower()
    if "caller" in lowered or "callee" in lowered:
        return InvestigationReason.UNKNOWN_CALL_RELATIONSHIP
    if "network" in lowered or "url" in lowered or "http" in lowered:
        return InvestigationReason.UNKNOWN_NETWORK_CONTEXT
    if "file" in lowered or "path" in lowered:
        return InvestigationReason.UNKNOWN_FILE_CONTEXT
    if "execute" in lowered or "process" in lowered or "command" in lowered:
        return InvestigationReason.UNKNOWN_EXECUTION_CONTEXT
    if "data" in lowered or "buffer" in lowered:
        return InvestigationReason.UNKNOWN_DATA_USAGE
    if "string" in lowered or "xref" in lowered or "reference" in lowered:
        return InvestigationReason.UNKNOWN_STRING_USAGE
    return InvestigationReason.UNKNOWN_ARTIFACT_USAGE


def _text(
    name: str,
    proposed_name: str | None,
    summary: str | None,
    unknowns: list[str],
    evidence: list[dict],
    imports: list[str],
) -> str:
    evidence_text = " ".join(
        " ".join(str(value) for value in item.values())
        for item in evidence
        if isinstance(item, dict)
    )
    return " ".join([name, proposed_name or "", summary or "", " ".join(unknowns), evidence_text, " ".join(imports)]).lower()
