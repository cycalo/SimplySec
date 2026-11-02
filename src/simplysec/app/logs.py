"""Rotating log file in %LOCALAPPDATA%\\SimplySec\\logs."""

from __future__ import annotations

import logging
import logging.handlers

from .paths import log_dir


def setup(verbose: bool = False) -> None:
    root = logging.getLogger()
    if any(getattr(h, "_simplysec", False) for h in root.handlers):
        return
    root.setLevel(logging.DEBUG if verbose else logging.INFO)
    try:
        folder = log_dir()
        folder.mkdir(parents=True, exist_ok=True)
        handler: logging.Handler = logging.handlers.RotatingFileHandler(
            folder / "simplysec.log", maxBytes=1_000_000, backupCount=3, encoding="utf-8"
        )
    except OSError:
        handler = logging.NullHandler()
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)-7s %(name)s: %(message)s"))
    handler._simplysec = True  # type: ignore[attr-defined]
    root.addHandler(handler)
