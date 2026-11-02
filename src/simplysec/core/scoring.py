"""Risk weighting for exposures, and the overall score and grade."""

from __future__ import annotations

from collections.abc import Iterable

from .models import Exposure, Finding, InterfaceKind, Profile, Scope, Severity, Verdict

WEIGHTS = {
    Severity.CRITICAL: 25,
    Severity.HIGH: 12,
    Severity.MEDIUM: 5,
    Severity.LOW: 2,
    Severity.INFO: 0,
}

# How widely something is reachable. A "Keep" decision is remembered with its width and the
# finding only comes back when the width grows.
WIDTH_NONE = 0
WIDTH_VPN = 1  # only via a VPN (Tailscale) or a virtual adapter on this PC
WIDTH_PRIVATE_SUBNET = 2
WIDTH_PRIVATE_ANY = 3
WIDTH_PUBLIC_SUBNET = 4
WIDTH_PUBLIC_ANY = 5
WIDTH_EDGE = 6  # internet via edge traversal

WIDTH_LABELS = {
    WIDTH_NONE: "nobody",
    WIDTH_VPN: "your VPN or virtual machines only",
    WIDTH_PRIVATE_SUBNET: "devices on your home (Private) network",
    WIDTH_PRIVATE_ANY: "anyone who can reach your home (Private) network",
    WIDTH_PUBLIC_SUBNET: "devices on a Public network",
    WIDTH_PUBLIC_ANY: "anyone on a Public network",
    WIDTH_EDGE: "the internet (edge traversal)",
}


def exposure_width(exposures: Iterable[Exposure]) -> int:
    width = WIDTH_NONE
    for exp in exposures:
        for ie in exp.per_interface:
            if ie.verdict != Verdict.REACHABLE:
                continue
            if ie.edge_traversal:
                w = WIDTH_EDGE
            elif ie.interface_kind in (InterfaceKind.VPN, InterfaceKind.VIRTUAL):
                w = WIDTH_VPN
            elif ie.profile == Profile.PUBLIC:
                w = WIDTH_PUBLIC_ANY if ie.scope == Scope.ANYONE else WIDTH_PUBLIC_SUBNET
            else:
                w = WIDTH_PRIVATE_ANY if ie.scope == Scope.ANYONE else WIDTH_PRIVATE_SUBNET
            width = max(width, w)
    return width


def exposure_severity(
    base: Severity,
    width: int,
    *,
    unsigned: bool = False,
    user_writable: bool = False,
    user_configured: bool = False,
) -> Severity:
    """Start from the knowledge-base risk (defined for Public exposure) and weight it.

    Public weighs most; Private networks count one level lower; VPN/virtual-only two levels.
    Unsigned programs, user-writable locations and edge traversal raise it.
    """
    if width == WIDTH_NONE or base == Severity.INFO:
        return Severity.INFO  # "info" in the knowledge base means harmless by design
    sev: Severity
    if width in (WIDTH_PUBLIC_ANY, WIDTH_PUBLIC_SUBNET):
        sev = base
    elif width == WIDTH_EDGE:
        sev = base.shifted(+1)
    elif width == WIDTH_VPN:
        sev = base.shifted(-2)
    else:
        sev = base.shifted(-1)
    raise_by = int(unsigned) + int(user_writable)
    if raise_by:
        sev = sev.shifted(min(raise_by, 1) if sev >= Severity.HIGH else raise_by)
        sev = max(sev, Severity.LOW)
    if user_configured:
        cap = Severity.LOW if width >= WIDTH_PUBLIC_SUBNET else Severity.INFO
        sev = min(sev, cap)
    return Severity(sev)


def score(findings: Iterable[Finding]) -> int:
    """Risk score: 0 means nothing open, higher means riskier (capped at 100)."""
    total = 0
    for f in findings:
        if f.scored:
            total += WEIGHTS[f.severity]
    return min(100, total)


# (highest risk score, letter): 31 with no High or Critical finding is a C, not an alarm.
_BANDS = ((9, "A"), (19, "B"), (34, "C"), (54, "D"), (74, "E"))


def grade(value: int, findings: Iterable[Finding] = ()) -> str:
    """Letter for a risk score: A is the lowest risk, F the highest.

    A Critical finding makes the grade at least D and a High one at least C, however few
    other findings there are, so a single serious problem is never graded as "good".
    """
    letter = next((g for limit, g in _BANDS if value <= limit), "F")
    worst = max((f.severity for f in findings if f.scored), default=Severity.INFO)
    floor = "D" if worst == Severity.CRITICAL else "C" if worst == Severity.HIGH else "A"
    return max(letter, floor)  # letters sort A < F
