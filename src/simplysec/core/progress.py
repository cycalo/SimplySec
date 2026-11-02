"""A tiny progress convention shared by the collector, engine, CLI and GUI.

Callbacks receive plain strings. A string starting with ``DONE`` marks a finished step; any
other string says what is being worked on now. The GUI counts finished steps against the
expected totals below to draw a real progress bar.
"""

from __future__ import annotations

DONE = "\u2713 "

SCAN_STEPS = 6  # listeners, firewall, signatures, Wi-Fi, Windows settings, analysis
NETWORK_STEPS_PER_TARGET = 4  # devices, services, names, router


def done(text: str) -> str:
    return DONE + text


def is_done(text: str) -> bool:
    return text.startswith(DONE)
