"""Minimal SDDL reader for firewall rule user conditions.

Firewall rules can be limited to some local users with an SDDL string such as
``O:LSD:(A;;CC;;;S-1-5-21-...-1004)``. We only need the allow/deny ACE SIDs. Pure Python so
that the evaluator stays testable without pywin32.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

# SDDL SID aliases that appear in firewall conditions.
ALIASES = {
    "WD": "S-1-1-0",  # Everyone
    "AU": "S-1-5-11",  # Authenticated Users
    "IU": "S-1-5-4",  # Interactive
    "SY": "S-1-5-18",  # LocalSystem
    "LS": "S-1-5-19",  # LocalService
    "NS": "S-1-5-20",  # NetworkService
    "BA": "S-1-5-32-544",  # Administrators
    "BU": "S-1-5-32-545",  # Users
    "BG": "S-1-5-32-546",  # Guests
    "AC": "S-1-15-2-1",  # All application packages
}

EVERYONE_LIKE = {"S-1-1-0", "S-1-5-11"}

_ACE = re.compile(r"\(([^)]*)\)")


@dataclass
class UserCondition:
    allow: set[str] = field(default_factory=set)
    deny: set[str] = field(default_factory=set)

    def decide(self, user_sid: str | None) -> bool | None:
        """True: applies to this user; False: does not; None: cannot tell."""
        groups_involved = any(
            s.startswith("S-1-5-32-") or s in {"S-1-5-4", "S-1-15-2-1"}
            for s in self.allow | self.deny
        )
        if user_sid is None:
            return None
        sid = user_sid.upper()
        if sid in self.deny:
            return False
        if sid in self.allow or self.allow & EVERYONE_LIKE:
            return True
        # Group SIDs (Administrators, Users, Interactive) need token group membership,
        # which we do not model.
        return None if groups_involved else False


def parse_user_condition(sddl: str) -> UserCondition:
    cond = UserCondition()
    dacl = sddl.split("D:", 1)[1] if "D:" in sddl else sddl
    for ace in _ACE.findall(dacl):
        parts = ace.split(";")
        if len(parts) < 6:
            continue
        ace_type, sid = parts[0].upper(), parts[5].strip().upper()
        sid = ALIASES.get(sid, sid)
        if ace_type == "A":
            cond.allow.add(sid)
        elif ace_type == "D":
            cond.deny.add(sid)
    return cond
