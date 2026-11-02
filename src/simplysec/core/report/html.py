"""Self-contained, printable HTML report (Jinja2 with autoescape on: device names are untrusted)."""

from __future__ import annotations

import datetime as dt
from pathlib import Path
from typing import TYPE_CHECKING, Any

from jinja2 import Environment, FileSystemLoader, select_autoescape

from ... import __version__
from ..models import FindingStatus, Severity

if TYPE_CHECKING:
    from ..engine import Engine, ScanResult

TEMPLATES = Path(__file__).resolve().parent / "templates"

# Five small-business control areas (the Cyber Essentials themes), mapped from finding areas.
CONTROL_AREAS: list[tuple[str, str, set[str]]] = [
    (
        "Firewalls",
        "Which services other devices and the internet can reach.",
        {"Firewall", "Exposure", "Router"},
    ),
    (
        "Secure configuration",
        "Settings that remove unnecessary ways in.",
        {
            "Remote access",
            "Legacy protocols",
            "File sharing",
            "System",
            "Wi-Fi",
            "Home network",
            "Housekeeping",
        },
    ),
    ("User access control", "Who can sign in and with which rights.", {"Accounts"}),
    ("Malware protection", "Antivirus and ransomware protection.", {"Malware protection"}),
    ("Security update management", "Keeping Windows patched.", {"Updates"}),
]


def control_area(area: str) -> str:
    for name, _, areas in CONTROL_AREAS:
        if area in areas:
            return name
    return "Secure configuration"


def environment() -> Environment:
    return Environment(
        loader=FileSystemLoader(str(TEMPLATES)),
        autoescape=select_autoescape(enabled_extensions=("html", "j2"), default=True),
        trim_blocks=True,
        lstrip_blocks=True,
    )


def build_context(
    result: ScanResult,
    changes: list[dict[str, Any]] | None = None,
    accepted: list[dict[str, Any]] | None = None,
    trend: list[tuple[str, int]] | None = None,
) -> dict[str, Any]:
    groups = []
    for name, blurb, _areas in CONTROL_AREAS:
        items = [f for f in result.findings if control_area(f.area) == name]
        open_items = [
            f for f in items if f.status == FindingStatus.OPEN and f.severity > Severity.INFO
        ]
        worst = max((f.severity for f in open_items), default=None)
        groups.append(
            {
                "name": name,
                "blurb": blurb,
                "findings": items,
                "open": len(open_items),
                "status": "Needs attention"
                if worst and worst >= Severity.HIGH
                else "Could be better"
                if open_items
                else "Good",
            }
        )
    return {
        "version": __version__,
        "generated": dt.datetime.now().astimezone().strftime("%Y-%m-%d %H:%M"),
        "result": result,
        "counts": result.counts(),
        "groups": groups,
        "ports": [p for p in result.ports if p.verdict.value in ("reachable", "uncertain")],
        "devices": result.extras.get("devices") or [],
        "router": result.extras.get("router") or {},
        "changes": changes or [],
        "accepted": accepted or [],
        "trend": trend or [],
        "severity_class": lambda s: s.name.lower(),
    }


def render(context: dict[str, Any]) -> str:
    return environment().get_template("report.html.j2").render(**context)


def write_report(path: Path, result: ScanResult, engine: Engine | None = None) -> Path:
    changes: list[dict[str, Any]] = []
    accepted: list[dict[str, Any]] = []
    trend: list[tuple[str, int]] = []
    if engine is not None:
        try:
            from ...app import paths
            from ..journal import Journal

            journal = Journal(paths.journal_path(), readonly=True)
            changes = [c.to_dict() for c in journal.changes()]
        except Exception:
            changes = []
        try:
            accepted = engine.history.accepted()
            trend = [(s.ts[:10], s.score) for s in reversed(engine.history.scans(limit=30))]
        except Exception:
            pass
    html = render(build_context(result, changes, accepted, trend))
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(html, encoding="utf-8")
    return path
