from __future__ import annotations

from reai.extraction.models import ExtractionBundle, ExtractionStats


def calculate_stats(bundle: ExtractionBundle) -> ExtractionStats:
    functions = bundle.functions
    return ExtractionStats(
        total_functions=len(functions),
        sub_functions=sum(1 for function in functions if function.name.startswith("sub_")),
        named_functions=sum(1 for function in functions if not function.name.startswith("sub_")),
        library_functions=sum(1 for function in functions if function.is_library),
        thunks=sum(1 for function in functions if function.is_thunk),
        decompiled_successfully=sum(1 for function in functions if function.decompilation_status == "success"),
        decompilation_failures=sum(1 for function in functions if function.decompilation_status == "failed"),
        strings=len(bundle.strings),
        imports=len(bundle.imports),
        exports=len(bundle.exports),
        globals=len(bundle.globals),
        segments=len(bundle.segments),
        types=len(bundle.types),
        call_edges=len(bundle.callgraph.edges),
        recursive_components=sum(1 for component in bundle.callgraph.components if component.recursive),
        partial_failures=sum(1 for failure in bundle.failures if not failure.fatal),
    )
