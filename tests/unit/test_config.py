from pathlib import Path

import pytest

from reai.core.config import build_config, load_config_file
from reai.core.exceptions import ConfigError


def test_config_precedence_defaults_config_cli(tmp_path):
    config_file = tmp_path / "reai.toml"
    config_file.write_text(
        'output_dir = "./from-config"\n\n[batch]\nworkers = 3\nrecursive = true\n\n[ida]\npath = "./ida"\ntimeout_seconds = 10\n\n[ai]\nprovider = "mock"\nmax_functions = 20\n',
        encoding="utf-8",
    )

    config = build_config(
        config_path=config_file,
        output_dir=Path("./from-cli"),
        workers=2,
        recursive=False,
    )

    assert config.output_dir == Path("./from-cli")
    assert config.workers == 2
    assert config.recursive is False
    assert config.ida.path == Path("./ida")
    assert config.ida.timeout_seconds == 10
    assert config.ai.provider == "mock"
    assert config.ai.max_functions == 20


def test_unknown_config_key_is_error(tmp_path):
    config_file = tmp_path / "bad.toml"
    config_file.write_text("model = 'future'\n", encoding="utf-8")

    with pytest.raises(ConfigError):
        load_config_file(config_file)


def test_unknown_ida_config_key_is_error(tmp_path):
    config_file = tmp_path / "bad.toml"
    config_file.write_text("[ida]\nmodel = 'future'\n", encoding="utf-8")

    with pytest.raises(ConfigError):
        load_config_file(config_file)


def test_ai_config_accepts_api_key_aliases(tmp_path):
    config_file = tmp_path / "ok.toml"
    config_file.write_text("[ai]\napi-key = 'secret-placeholder'\n", encoding="utf-8")

    assert load_config_file(config_file).ai.api_key == "secret-placeholder"

    config_file.write_text("[ai]\napi_key = 'secret-placeholder-2'\n", encoding="utf-8")

    assert load_config_file(config_file).ai.api_key == "secret-placeholder-2"


def test_unknown_ai_config_key_is_error(tmp_path):
    config_file = tmp_path / "bad.toml"
    config_file.write_text("[ai]\napi_secret = 'nope'\n", encoding="utf-8")

    with pytest.raises(ConfigError):
        load_config_file(config_file)


def test_analysis_config_accepts_phase5_sections(tmp_path):
    config_file = tmp_path / "ok.toml"
    config_file.write_text(
        "[analysis]\nenabled = true\n\n[analysis.propagation]\nmax_passes = 2\nminimum_confidence_delta = 0.1\n\n[analysis.validation]\nrename_confidence_threshold = 0.9\n",
        encoding="utf-8",
    )

    config = load_config_file(config_file)

    assert config.analysis.enabled is True
    assert config.analysis.propagation.max_passes == 2
    assert config.analysis.propagation.minimum_confidence_delta == 0.1
    assert config.analysis.validation.rename_confidence_threshold == 0.9


def test_report_config_accepts_phase7_section(tmp_path):
    config_file = tmp_path / "ok.toml"
    config_file.write_text(
        "[report]\nenabled = true\ndefang_iocs = false\nformats = ['markdown', 'html']\nmax_important_functions = 10\n",
        encoding="utf-8",
    )

    config = load_config_file(config_file)

    assert config.report.enabled is True
    assert config.report.defang_iocs is False
    assert config.report.formats == ["markdown", "html"]
    assert config.report.max_important_functions == 10


def test_phase8_reliability_and_resource_config(tmp_path):
    config_file = tmp_path / "ok.toml"
    config_file.write_text(
        "[reliability]\nsample_retry_limit = 2\nlock_stale_seconds = 10\n\n[ida]\nmax_concurrent_instances = 1\n\n[ai]\nmax_concurrent_requests = 2\ntimeout_seconds = 30\n",
        encoding="utf-8",
    )

    config = load_config_file(config_file)

    assert config.reliability.sample_retry_limit == 2
    assert config.reliability.lock_stale_seconds == 10
    assert config.ida.max_concurrent_instances == 1
    assert config.ai.max_concurrent_requests == 2
    assert config.ai.timeout_seconds == 30
