"""Small pure helpers shared across layers."""

from __future__ import annotations

from typing import Any


def as_list(value: Any) -> list[Any]:
    """PowerShell turns 1-item arrays into objects and empty arrays into {} or null."""
    if value is None or value == {}:
        return []
    if isinstance(value, list):
        return value
    return [value]
