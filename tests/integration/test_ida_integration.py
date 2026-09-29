import os
from pathlib import Path

import pytest

from reai.core.config import ApplicationConfig, IDAConfig
from reai.ida.environment import detect_ida_environment


@pytest.mark.skipif(
    not (os.environ.get("REAI_IDA_PATH") or os.environ.get("IDA_PATH")),
    reason="IDA integration tests require REAI_IDA_PATH or IDA_PATH.",
)
def test_ida_environment_detects_configured_installation():
    path = Path(os.environ.get("REAI_IDA_PATH") or os.environ["IDA_PATH"])
    environment = detect_ida_environment(IDAConfig(path=path))

    assert environment.available
    assert environment.executable is not None


def test_ida_environment_reports_unavailable_path(tmp_path):
    environment = detect_ida_environment(IDAConfig(path=tmp_path / "missing-ida"))

    assert environment.available is False
