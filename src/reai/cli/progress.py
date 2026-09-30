from __future__ import annotations

import re
import sys
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Iterator

from rich.console import Group
from rich.live import Live
from rich.markup import escape
from rich.spinner import Spinner
from rich.text import Text

from reai.cli.console import console


PHASE_TITLES: dict[int, str] = {
    1: "initializing workspace",
    2: "running IDA extraction",
    3: "running bottom-up AI function analysis",
    4: "running REAI MCP investigation",
    5: "validating malware understanding",
    6: "renaming, commenting, and saving analyzed IDB",
    7: "generating analysis report",
}

_PHASE_RE = re.compile(r"^(?:(?P<sample>.+?):\s*)?Phase\s+(?P<phase>[1-7]):\s*(?P<detail>.+)$")


def _can_encode(value: str) -> bool:
    encoding = getattr(sys.stdout, "encoding", None) or "utf-8"
    try:
        value.encode(encoding)
    except UnicodeEncodeError:
        return False
    return True


CHECK_SYMBOL = "✔" if _can_encode("✔") else "+"
FAIL_SYMBOL = "✖" if _can_encode("✖") else "x"
PENDING_SYMBOL = "·" if _can_encode("·") else "-"
SPINNER_NAME = "dots" if _can_encode("⠋") else "line"


@dataclass
class PhaseLine:
    detail: str
    status: str = "pending"


class PhaseProgress:
    def __init__(self, initial_message: str = "Starting REAI analysis...") -> None:
        self.sample_name: str | None = None
        self.current_message = initial_message
        self.lines = {phase: PhaseLine(detail) for phase, detail in PHASE_TITLES.items()}
        self.active_phase: int | None = None

    def update(self, message: str) -> None:
        self.current_message = message
        match = _PHASE_RE.match(message)
        if not match:
            sample = _sample_from_message(message)
            if sample:
                self.sample_name = sample
            return

        sample = match.group("sample")
        phase = int(match.group("phase"))
        detail = match.group("detail").strip()
        if sample:
            self.sample_name = sample

        for previous in range(1, phase):
            if self.lines[previous].status != "failed":
                self.lines[previous].status = "done"

        self.lines[phase].detail = detail
        if _is_failure(detail):
            self.lines[phase].status = "failed"
            self.active_phase = None
        elif _is_completion(detail):
            self.lines[phase].status = "done"
            self.active_phase = None
        else:
            self.lines[phase].status = "running"
            self.active_phase = phase

    def render(self) -> Group:
        title = Text()
        if self.sample_name:
            title.append(f"{self.sample_name}:", style="bold cyan")
        else:
            title.append(escape(self.current_message), style="bold cyan")

        rows = [title]
        for phase in range(1, 8):
            line = self.lines[phase]
            rows.append(_render_phase_line(phase, line, running=phase == self.active_phase))
        return Group(*rows)


@contextmanager
def phase_progress(initial_message: str = "Starting REAI analysis...") -> Iterator[PhaseProgress]:
    progress = PhaseProgress(initial_message)
    with Live(progress.render(), console=console, refresh_per_second=10, transient=False) as live:
        original_update = progress.update

        def update_and_refresh(message: str) -> None:
            original_update(message)
            live.update(progress.render())

        progress.update = update_and_refresh  # type: ignore[method-assign]
        yield progress


def _render_phase_line(phase: int, line: PhaseLine, *, running: bool) -> Text | Group:
    detail = escape(line.detail)
    if line.status == "done":
        return Text.from_markup(f"[green]{CHECK_SYMBOL}[/green]  Phase {phase}: {detail}")
    if line.status == "failed":
        return Text.from_markup(f"[red]{FAIL_SYMBOL}[/red]  Phase {phase}: {detail}")
    if running:
        return Group(Spinner(SPINNER_NAME, text=Text.from_markup(f" Phase {phase}: {detail}")))
    return Text.from_markup(f"[dim]{PENDING_SYMBOL}  Phase {phase}: {detail}[/dim]")


def _is_completion(detail: str) -> bool:
    lowered = detail.lower()
    return "complete" in lowered or "finished" in lowered


def _is_failure(detail: str) -> bool:
    lowered = detail.lower()
    return "failed" in lowered or "failure" in lowered


def _sample_from_message(message: str) -> str | None:
    if ": " not in message:
        return None
    sample, _ = message.split(": ", 1)
    return sample or None
