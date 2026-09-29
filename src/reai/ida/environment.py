from __future__ import annotations

import os
import shutil
from pathlib import Path

from pydantic import BaseModel, ConfigDict

from reai.core.config import IDAConfig


IDA_EXECUTABLE_NAMES = (
    "ida64.exe",
    "ida.exe",
    "idat64.exe",
    "idat.exe",
    "ida64",
    "ida",
    "idat64",
    "idat",
)


class IDAEnvironment(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True)

    executable: Path | None
    configured_path: Path | None = None
    discovery_source: str = "not found"

    @property
    def available(self) -> bool:
        return self.executable is not None


def detect_ida_environment(config: IDAConfig) -> IDAEnvironment:
    if config.path is not None:
        executable = _resolve_configured_path(config.path)
        return IDAEnvironment(
            executable=executable,
            configured_path=config.path,
            discovery_source="config" if executable else "configured path not executable",
        )

    for env_name in ("REAI_IDA_PATH", "IDA_PATH"):
        value = os.environ.get(env_name)
        if value:
            path = Path(value)
            executable = _resolve_configured_path(path)
            return IDAEnvironment(
                executable=executable,
                configured_path=path,
                discovery_source=env_name if executable else f"{env_name} not executable",
            )

    for name in IDA_EXECUTABLE_NAMES:
        found = shutil.which(name)
        if found:
            return IDAEnvironment(executable=Path(found), discovery_source="PATH")

    return IDAEnvironment(executable=None)


def _resolve_configured_path(path: Path) -> Path | None:
    expanded = path.expanduser()
    if expanded.is_file():
        return expanded
    if expanded.is_dir():
        for name in IDA_EXECUTABLE_NAMES:
            candidate = expanded / name
            if candidate.is_file():
                return candidate
    return None


def get_clean_ida_environment() -> dict[str, str]:
    """Return an isolated environment dictionary for launching IDA Pro subprocesses.

    When REAI is executed from an active Python virtual environment (.venv),
    environment variables such as VIRTUAL_ENV, __PYVENV_LAUNCHER__, and PYTHONPATH
    leak into the child IDA process. This causes IDA's embedded Python interpreter
    to attempt resolving standard libraries from the virtualenv, triggering
    'Could not find platform dependent libraries <exec_prefix>' errors and crashing.

    This function purges virtualenv overrides and points PYTHONHOME directly to IDA's
    configured target Python runtime or the system base prefix.
    """
    env = os.environ.copy()

    py_home: str | None = None
    if os.name == "nt":
        try:
            import winreg

            for hive in (winreg.HKEY_CURRENT_USER, winreg.HKEY_LOCAL_MACHINE):
                try:
                    with winreg.OpenKey(hive, r"Software\Hex-Rays\IDA") as key:
                        val, _ = winreg.QueryValueEx(key, "Python3TargetDLL")
                        if val and Path(val).is_file():
                            py_home = str(Path(val).parent)
                            break
                except OSError:
                    pass
        except Exception:
            pass

    if not py_home:
        import sys
        py_home = getattr(sys, "base_prefix", sys.prefix)

    if py_home:
        env["PYTHONHOME"] = py_home

    # Purge virtualenv and interfering python flags
    for var in (
        "VIRTUAL_ENV",
        "__PYVENV_LAUNCHER__",
        "PYTHONPATH",
        "PYTHONSTARTUP",
        "PYTHONEXECUTABLE",
        "PYTHONINSPECT",
    ):
        env.pop(var, None)

    # Sanitize PATH so virtualenv's Scripts directory does not intercept python3 DLLs
    if py_home:
        paths = env.get("PATH", "").split(os.pathsep)
        clean_paths = [
            p
            for p in paths
            if "\\.venv" not in p.lower() and "/.venv" not in p.lower()
        ]
        clean_paths.insert(0, py_home)
        scripts = str(Path(py_home) / "Scripts")
        if scripts not in clean_paths:
            clean_paths.insert(1, scripts)
        env["PATH"] = os.pathsep.join(clean_paths)

    return env

