from __future__ import annotations

import logging
from pathlib import Path

from reai.utils.redaction import redact_secrets


class RedactingFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        record.msg = redact_secrets(record.msg)
        if record.args:
            record.args = tuple(redact_secrets(arg) for arg in record.args)
        # Redact the fully-formatted string (includes exc_text / traceback).
        # This prevents API keys in exception messages from bypassing redaction.
        return redact_secrets(super().format(record))


def configure_logging(log_path: Path | None = None, *, verbose: bool = False) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    root = logging.getLogger("reai")
    root.setLevel(level)
    for handler in root.handlers:
        handler.close()
    root.handlers.clear()
    root.propagate = False

    if log_path is None:
        return

    formatter = RedactingFormatter("%(asctime)sZ %(levelname)s %(name)s: %(message)s")

    log_path.parent.mkdir(parents=True, exist_ok=True)
    handler = logging.FileHandler(log_path, encoding="utf-8")
    handler.setFormatter(formatter)
    handler.setLevel(level)
    root.addHandler(handler)
