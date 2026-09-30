from __future__ import annotations

from reai.mcp.schemas import AnalyticalImportance


RUNTIME_HELPER_TERMS = (
    "return_zero",
    "return_one",
    "nullsub",
    "security_cookie",
    "scrt",
    "crt_",
    "except_handler",
    "initterm",
    "memset",
    "memcpy",
)

NETWORK_TERMS = ("internet", "winhttp", "urldownload", "socket", "connect", "recv", "send", "dns", "http")
PROCESS_TERMS = ("createprocess", "shellexecute", "winexec", "createthread", "loadlibrary")
FILE_TERMS = ("createfile", "writefile", "deletefile", "copyfile", "movefile", "file path", "dropped")
PERSISTENCE_TERMS = ("registry", "run key", "startup", "service", "schtasks", "persistence")
CRYPTO_TERMS = ("crypt", "aes", "rc4", "sha", "md5", "xor")


def classify_importance(
    *,
    name: str,
    proposed_name: str | None,
    summary: str | None,
    confidence_label: str,
    unknowns: list[str],
    evidence: list[dict],
    imports: list[str],
    caller_count: int,
    callee_count: int,
) -> tuple[AnalyticalImportance, float, list[str]]:
    text = _text(name, proposed_name, summary, unknowns, evidence, imports)
    if any(term in text for term in RUNTIME_HELPER_TERMS):
        return AnalyticalImportance.LOW, 0.05, ["runtime/helper pattern"]

    score = 0.0
    reasons: list[str] = []
    if "_main" in text or "winmain" in text or "entry" in text:
        score += 0.35
        reasons.append("entry-point or main relationship")
    if caller_count + callee_count >= 4:
        score += 0.15
        reasons.append("meaningful call relationships")
    if any(term in text for term in NETWORK_TERMS):
        score += 0.30
        reasons.append("network behavior")
    if any(term in text for term in PROCESS_TERMS):
        score += 0.25
        reasons.append("process execution behavior")
    if any(term in text for term in FILE_TERMS):
        score += 0.20
        reasons.append("file behavior")
    if any(term in text for term in PERSISTENCE_TERMS):
        score += 0.20
        reasons.append("persistence context")
    if any(term in text for term in CRYPTO_TERMS):
        score += 0.15
        reasons.append("crypto or decoding context")
    if unknowns:
        score += min(0.15, len(unknowns) * 0.04)
        reasons.append("unanswered analysis questions")
    if confidence_label == "LOW":
        score += 0.10
        reasons.append("low confidence")

    if score >= 0.45:
        return AnalyticalImportance.HIGH, min(score, 1.0), reasons
    if score >= 0.20:
        return AnalyticalImportance.MEDIUM, score, reasons
    return AnalyticalImportance.LOW, score, reasons or ["limited malware relevance"]


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
