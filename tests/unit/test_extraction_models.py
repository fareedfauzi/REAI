from reai.extraction.filenames import function_artifact_filename
from reai.extraction.models import ExtractionBundle, FunctionRecord
from reai.extraction.stats import calculate_stats


def test_function_record_serializes_addresses_as_hex():
    record = FunctionRecord(
        address=0x140001000,
        end_address=0x140001020,
        name="sub_140001000",
        size=0x20,
        callers=[0x140000100],
        callees=[0x140002000],
    )

    data = record.model_dump(mode="json")

    assert data["address"] == "0x140001000"
    assert data["callees"] == ["0x140002000"]


def test_function_artifact_filename_is_stable_and_sanitized():
    assert (
        function_artifact_filename(0x140001000, "../bad:name", ".c")
        == "0000000140001000_bad_name.c"
    )


def test_extraction_stats_count_phase2_facts_only():
    bundle = ExtractionBundle(
        functions=[
            FunctionRecord(
                address=0x1000,
                end_address=0x1010,
                name="sub_1000",
                size=0x10,
                decompilation_status="success",
            ),
            FunctionRecord(
                address=0x2000,
                end_address=0x2010,
                name="named_func",
                size=0x10,
                is_thunk=True,
                decompilation_status="failed",
            ),
        ]
    )

    stats = calculate_stats(bundle)

    assert stats.total_functions == 2
    assert stats.sub_functions == 1
    assert stats.named_functions == 1
    assert stats.decompiled_successfully == 1
    assert stats.decompilation_failures == 1
    assert stats.thunks == 1
