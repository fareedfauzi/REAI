from reai.utils.paths import WorkspacePaths, sanitize_filename_stem


def test_sanitize_filename_stem_handles_malicious_names():
    assert sanitize_filename_stem("../evil.exe") == "evil"
    assert sanitize_filename_stem("CON") == "CON_sample"
    assert sanitize_filename_stem("bad/name\x00?.bin") == "name"
    assert sanitize_filename_stem("   ") == "sample"


def test_workspace_generation_creates_expected_directories(tmp_path):
    workspace = WorkspacePaths.for_sample(tmp_path, "GhostHopper.exe", "6e921af7" + "0" * 56)
    workspace.create_directories()

    assert workspace.root.name == "GhostHopper_6e921af7"
    for name in ["ida", "report", "analysis", "raw", "pseudocode", "disassembly", "logs"]:
        assert (workspace.root / name).is_dir()
    assert workspace.database == workspace.root / "analysis" / "analysis.db"
    assert workspace.sample_metadata == workspace.root / "analysis" / "sample.json"
