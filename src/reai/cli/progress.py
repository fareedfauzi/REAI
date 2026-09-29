from contextlib import contextmanager
from typing import Iterator

from rich.status import Status

from reai.cli.console import console


@contextmanager
def phase_status(message: str) -> Iterator[Status]:
    with console.status(message, spinner="dots") as status:
        yield status
