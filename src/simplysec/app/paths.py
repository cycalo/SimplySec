"""Where SimplySec keeps its files, and the admin-only ACL on the journal folder.

* ``%ProgramData%\\SimplySec``: change journal (``simplysec.db``) and firewall backups.
  Administrators and SYSTEM can write; standard users can only read.
* ``%LOCALAPPDATA%\\SimplySec``: per-user scan history, devices, settings, accepted risks
  and the log. Read-only scans still get a history this way.

Both can be overridden with ``SIMPLYSEC_DATA_DIR`` / ``SIMPLYSEC_USER_DIR`` (tests, portable use).
"""

from __future__ import annotations

import logging
import os
import sys
from pathlib import Path

log = logging.getLogger(__name__)

APP = "SimplySec"


def is_frozen() -> bool:
    return bool(getattr(sys, "frozen", False))


def package_root() -> Path:
    """Folder of the ``simplysec`` package (inside the PyInstaller bundle when frozen)."""
    if is_frozen():
        return Path(getattr(sys, "_MEIPASS", Path(sys.executable).parent)) / "simplysec"
    return Path(__file__).resolve().parent.parent


def data_dir() -> Path:
    override = os.environ.get("SIMPLYSEC_DATA_DIR")
    if override:
        return Path(override)
    return Path(os.environ.get("ProgramData", r"C:\ProgramData")) / APP


def user_dir() -> Path:
    override = os.environ.get("SIMPLYSEC_USER_DIR")
    if override:
        return Path(override)
    base = os.environ.get("LOCALAPPDATA") or str(Path.home() / "AppData" / "Local")
    return Path(base) / APP


def journal_path() -> Path:
    return data_dir() / "simplysec.db"


def backups_dir() -> Path:
    return data_dir() / "backups"


def history_path() -> Path:
    return user_dir() / "history.db"


def log_dir() -> Path:
    return user_dir() / "logs"


def facts_script() -> Path:
    return package_root() / "windows" / "scripts" / "facts.ps1"


def resource(name: str) -> Path:
    return package_root() / "resources" / name


# --------------------------------------------------------------------------- ACL

SYSTEM_SID = "S-1-5-18"
ADMINS_SID = "S-1-5-32-544"
USERS_SID = "S-1-5-32-545"


def harden_data_dir(path: Path | None = None) -> None:
    """Admin-only write ACL: SYSTEM and Administrators full control, Users read & execute.

    Inheritance from ProgramData is cut, so standard users can't create or modify files there.
    Must run elevated. Safe to call repeatedly.
    """
    import ntsecuritycon as con
    import win32security

    path = path or data_dir()
    path.mkdir(parents=True, exist_ok=True)
    system = win32security.ConvertStringSidToSid(SYSTEM_SID)
    admins = win32security.ConvertStringSidToSid(ADMINS_SID)
    users = win32security.ConvertStringSidToSid(USERS_SID)
    inherit = con.OBJECT_INHERIT_ACE | con.CONTAINER_INHERIT_ACE
    dacl = win32security.ACL()
    dacl.AddAccessAllowedAceEx(win32security.ACL_REVISION_DS, inherit, con.FILE_ALL_ACCESS, system)
    dacl.AddAccessAllowedAceEx(win32security.ACL_REVISION_DS, inherit, con.FILE_ALL_ACCESS, admins)
    dacl.AddAccessAllowedAceEx(
        win32security.ACL_REVISION_DS,
        inherit,
        con.FILE_GENERIC_READ | con.FILE_GENERIC_EXECUTE,
        users,
    )
    win32security.SetNamedSecurityInfo(
        str(path),
        win32security.SE_FILE_OBJECT,
        win32security.DACL_SECURITY_INFORMATION
        | win32security.PROTECTED_DACL_SECURITY_INFORMATION
        | win32security.OWNER_SECURITY_INFORMATION,
        admins,
        None,
        dacl,
        None,
    )
    log.info("hardened ACL on %s", path)


def data_dir_is_trusted(path: Path | None = None) -> tuple[bool, str]:
    """Check that only Administrators/SYSTEM (and trusted installers) can write the folder."""
    import ntsecuritycon as con
    import win32security

    path = path or data_dir()
    if not path.exists():
        return True, "not created yet"
    sd = win32security.GetNamedSecurityInfo(
        str(path),
        win32security.SE_FILE_OBJECT,
        win32security.DACL_SECURITY_INFORMATION | win32security.OWNER_SECURITY_INFORMATION,
    )
    owner = win32security.ConvertSidToStringSid(sd.GetSecurityDescriptorOwner())
    trusted = {
        SYSTEM_SID,
        ADMINS_SID,
        "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464",
    }
    if owner not in trusted:
        return False, f"folder owner is {owner}"
    dacl = sd.GetSecurityDescriptorDacl()
    if dacl is None:
        return False, "folder has no access list (everyone can write)"
    write_bits = (
        con.FILE_WRITE_DATA | con.FILE_APPEND_DATA | con.WRITE_DAC | con.WRITE_OWNER | con.DELETE
    )
    for i in range(dacl.GetAceCount()):
        (ace_type, _flags), mask, sid = dacl.GetAce(i)
        if ace_type != win32security.ACCESS_ALLOWED_ACE_TYPE:
            continue
        sid_s = win32security.ConvertSidToStringSid(sid)
        if sid_s not in trusted and mask & write_bits:
            return False, f"{sid_s} can write to the folder"
    return True, "ok"
