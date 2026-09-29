from pathlib import Path

from reai.core.config import load_config_file


ROOT = Path(__file__).resolve().parents[2]


def test_public_documentation_files_exist():
    expected = [
        "README.md",
        "CHANGELOG.md",
        "CONTRIBUTING.md",
        "SECURITY.md",
        "docs/installation.md",
        "docs/configuration.md",
        "docs/analysis-pipeline.md",
        "docs/confidence-and-evidence.md",
        "docs/output-structure.md",
        "docs/troubleshooting.md",
        "docs/development.md",
        "docs/database.md",
        "docs/state-machine.md",
        "docs/examples/basic-analysis.md",
        "docs/examples/batch-analysis.md",
        "docs/RELEASE_CHECKLIST.md",
        "reai.example.toml",
    ]

    for relative in expected:
        assert (ROOT / relative).is_file(), relative


def test_example_config_loads():
    config = load_config_file(ROOT / "reai.example.toml")

    assert config.output_dir.as_posix() == "reai-output"
    assert config.ai.provider == "disabled"
    assert config.ai.model == "gpt-4o-mini"
    assert config.report.formats == ["markdown", "html", "pdf"]


def test_readme_does_not_document_missing_subcommands():
    readme = (ROOT / "README.md").read_text(encoding="utf-8")

    assert "There are no separate `doctor`, `status`, `resume`, or `report` subcommands" in readme
    assert "python -m reai [OPTIONS] INPUT" in readme
