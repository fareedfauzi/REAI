from __future__ import annotations

import json

from reai.analysis.schemas import CurrentFunctionFinding
from reai.storage.repository import AnalysisRepository


def load_current_function_findings(repository: AnalysisRepository, sample_id: str) -> list[CurrentFunctionFinding]:
    findings: list[CurrentFunctionFinding] = []
    for row in repository.get_ai_analysis_rows(sample_id):
        result = json.loads(row["result_json"])
        findings.append(
            CurrentFunctionFinding(
                address=row["address"],
                original_name=row["original_name"],
                proposed_name=row["proposed_name"],
                summary=row["summary"],
                confidence=float(row["confidence"]),
                confidence_label=row["confidence_label"],
                capabilities=list(result.get("capabilities") or []),
                behavior=list(result.get("behavior") or []),
                evidence=list(result.get("evidence") or []),
                unknowns=list(result.get("unknowns") or []),
                variables=list(result.get("variables") or []),
                types=list(result.get("types") or []),
                artifacts=list(result.get("artifacts") or []),
                analysis_pass=int(row["analysis_pass"]),
                needs_investigation=bool(row["needs_investigation"]),
            )
        )
    return findings

