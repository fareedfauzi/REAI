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
    1: "discovering sample and preparing workspace",
    2: "waiting for IDA auto-analysis",
    3: "running bottom-up AI function analysis",
    4: "running REAI MCP investigation",
    5: "validating malware understanding",
    6: "renaming, commenting, and saving analyzed IDB",
    7: "generating analysis report",
}

ENRICHIDB_PHASE_TITLES: dict[int, str] = {
    1: "discovering sample and preparing workspace",
    2: "extracting IDA functions and code context",
    3: "analyzing functions for names, variables, and comments",
    4: "saving renamed and commented analyzed IDB",
}

_PHASE_RE = re.compile(r"^(?:(?P<sample>.+?):\s*)?Phase\s+(?P<phase>\d+):\s*(?P<detail>.+)$")


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
    def __init__(self, initial_message: str = "Starting REAI analysis...", *, phase_titles: dict[int, str] | None = None) -> None:
        self.sample_name: str | None = None
        self.current_message = initial_message
        self.phase_titles = dict(phase_titles or PHASE_TITLES)
        self.lines = {phase: PhaseLine(detail=detail) for phase, detail in self.phase_titles.items()}
        self.active_phase: int | None = 1
        if 1 in self.lines:
            self.lines[1].status = "running"

    def update(self, message: str) -> None:
        self.current_message = message
        match = _PHASE_RE.match(message)
        if not match:
            sample = _sample_from_message(message)
            if sample:
                self.sample_name = sample
            phase1_detail = _phase1_detail_from_message(message)
            if phase1_detail:
                self.lines[1].detail = phase1_detail
                if self.lines[1].status != "done":
                    self.lines[1].status = "running"
                    self.active_phase = 1
            return

        sample = match.group("sample")
        phase = int(match.group("phase"))
        detail = match.group("detail").strip()
        if phase not in self.lines:
            return
        if sample:
            self.sample_name = sample

        for previous in sorted(item for item in self.lines if item < phase):
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
        for phase in sorted(self.lines):
            line = self.lines[phase]
            rows.append(_render_phase_line(phase, line, running=phase == self.active_phase))
        return Group(*rows)


@contextmanager
def phase_progress(
    initial_message: str = "Starting REAI analysis...",
    *,
    phase_titles: dict[int, str] | None = None,
) -> Iterator[PhaseProgress]:
    progress = PhaseProgress(initial_message, phase_titles=phase_titles)
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
        return Spinner(SPINNER_NAME, text=Text.from_markup(f" Phase {phase}: {detail}"))
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


def _phase1_detail_from_message(message: str) -> str | None:
    lowered = message.lower()
    if lowered.startswith("starting reai analysis"):
        return "starting analysis"
    if lowered == "discovering input samples":
        return "discovering input samples"
    if lowered.startswith("hashing "):
        return "hashing sample identity"
    if ": checking workspace" in lowered:
        return "checking existing workspace"
    if ": resuming existing workspace" in lowered:
        return "resuming existing workspace"
    if ": creating workspace" in lowered:
        return "creating workspace and database"
    return None
