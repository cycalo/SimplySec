"""Local accounts, found by well-known RID (never by localized name)."""

from __future__ import annotations

from dataclasses import dataclass

UF_ACCOUNTDISABLE = 0x0002
GUEST_RID = 501


class AccountError(RuntimeError):
    pass


@dataclass
class Account:
    name: str
    rid: int
    enabled: bool


def find_by_rid(rid: int) -> Account | None:
    import win32net

    resume = 0
    while True:
        users, _, resume = win32net.NetUserEnum(None, 20, 0, resume)
        for u in users:
            if int(u["user_id"]) == rid:
                return Account(u["name"], rid, not (u["flags"] & UF_ACCOUNTDISABLE))
        if not resume:
            return None


def is_enabled(name: str) -> bool:
    import win32net

    info = win32net.NetUserGetInfo(None, name, 1)
    return not (info["flags"] & UF_ACCOUNTDISABLE)


def set_enabled(name: str, enabled: bool) -> None:
    import win32net

    try:
        info = win32net.NetUserGetInfo(None, name, 1)
        flags = info["flags"] & ~UF_ACCOUNTDISABLE if enabled else info["flags"] | UF_ACCOUNTDISABLE
        win32net.NetUserSetInfo(None, name, 1008, {"flags": flags})
    except Exception as exc:
        raise AccountError(
            f"could not {'enable' if enabled else 'disable'} account {name}: {exc}"
        ) from exc
