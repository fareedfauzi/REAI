from __future__ import annotations

from pathlib import Path

from reai.core.exceptions import ExtractionError
from reai.extraction.models import ExtractionBundle, ExtractionStats
from reai.extraction.serialization import write_json
from reai.extraction.stats import calculate_stats
from reai.reporting.findings import write_extraction_findings
from reai.utils.paths import WorkspacePaths


def export_bundle(workspace: WorkspacePaths, bundle: ExtractionBundle) -> ExtractionStats:
    # Guard against silent IDA failures that produce an empty extraction.
    # An empty function list would propagate through all downstream phases,
    # producing empty reports and fake-successful analysis runs.
    if not bundle.functions:
        raise ExtractionError(
            "IDA extraction produced no functions. "
            "The binary may be empty, heavily packed, or the extractor script failed silently."
        )

    stats = calculate_stats(bundle)
    bundle.stats = stats

    write_json(workspace.analysis / "binary_metadata.json", bundle.metadata)
    write_json(workspace.analysis / "functions.json", {"functions": bundle.functions, "stats": stats})
    write_json(workspace.analysis / "callgraph.json", bundle.callgraph)
    write_json(workspace.analysis / "extraction_stats.json", stats)

    write_json(workspace.raw / "strings.json", {"strings": bundle.strings})
    write_json(workspace.raw / "imports.json", {"imports": bundle.imports})
    write_json(workspace.raw / "exports.json", {"exports": bundle.exports})
    write_json(workspace.raw / "globals.json", {"globals": bundle.globals})
    write_json(workspace.raw / "segments.json", {"segments": bundle.segments})
    write_json(workspace.raw / "types.json", {"types": bundle.types})
    write_json(
        workspace.raw / "decompile_failed.json",
        {
            "failures": [
                failure
                for failure in bundle.failures
                if failure.extractor == "pseudocode" or "decompil" in failure.reason.lower()
            ]
        },
    )
    write_json(workspace.raw / "xrefs.json", {"xrefs": bundle.xrefs})
    write_extraction_findings(workspace, bundle, stats)
    return stats



def load_exported_stats(workspace: WorkspacePaths) -> ExtractionStats | None:
    import json

    path = workspace.analysis / "extraction_stats.json"
    if not path.exists():
        return None
    try:
        return ExtractionStats.model_validate(json.loads(path.read_text(encoding="utf-8")))
    except (OSError, ValueError):
        return None
