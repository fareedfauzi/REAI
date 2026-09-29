from typer.testing import CliRunner

from reai import __version__
from reai.cli.main import app

runner = CliRunner()


def test_cli_help():
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    assert "INPUT" in result.output
    assert "--recursive" in result.output


def test_cli_version():
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0
    assert f"reai {__version__}" in result.output


def test_cli_single_file_and_custom_output(tmp_path):
    sample = tmp_path / "malware.exe"
    sample.write_bytes(b"payload")
    output = tmp_path / "case"
    config = tmp_path / "reai.toml"
    config.write_text("[ida]\npath = './definitely-missing-ida'\n", encoding="utf-8")

    result = runner.invoke(app, [str(sample), "-o", str(output), "--config", str(config)])

    assert result.exit_code == 2, result.output
    assert "IDA environment not available" in result.output
    assert any(child.name.startswith("malware_") for child in output.iterdir())


def test_cli_directory_and_recursive(tmp_path):
    samples = tmp_path / "samples"
    nested = samples / "nested"
    nested.mkdir(parents=True)
    (samples / "one.bin").write_bytes(b"one")
    (nested / "two.bin").write_bytes(b"two")
    output = tmp_path / "out"
    config = tmp_path / "reai.toml"
    config.write_text("[ida]\npath = './definitely-missing-ida'\n", encoding="utf-8")

    result = runner.invoke(app, [str(samples), "--recursive", "-o", str(output), "--config", str(config)])

    assert result.exit_code == 2, result.output
    assert "IDA environment not available" in result.output


def test_cli_invalid_input(tmp_path):
    result = runner.invoke(app, [str(tmp_path / "missing.bin")])

    assert result.exit_code == 2
    assert "Input does not exist" in result.output
