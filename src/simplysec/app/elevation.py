"""Administrator detection and "Restart as administrator" (runas relaunch).

Scanning is read-only and works without admin; only applying or undoing changes needs it.
"""

from __future__ import annotations

import ctypes
import logging
import subprocess
import sys

from .paths import is_frozen

log = logging.getLogger(__name__)


def is_admin() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except (AttributeError, OSError):
        return False


def _command(args: list[str], gui: bool) -> tuple[str, str]:
    if is_frozen():
        return sys.executable, subprocess.list2cmdline(args)
    exe = sys.executable
    if gui and exe.lower().endswith("python.exe"):
        candidate = exe[: -len("python.exe")] + "pythonw.exe"
        exe = candidate
    return exe, subprocess.list2cmdline(["-m", "simplysec", *args])


def relaunch_elevated(args: list[str] | None = None, gui: bool = True) -> bool:
    """Start a new elevated instance via the UAC prompt. Returns False if the user declined."""
    exe, params = _command(args or [], gui)
    log.info("relaunching elevated: %s %s", exe, params)
    rc = ctypes.windll.shell32.ShellExecuteW(None, "runas", exe, params, None, 1)
    return int(rc) > 32


def run_elevated_and_wait(args: list[str], timeout_ms: int = 600_000) -> int | None:
    """Run a CLI command elevated (console hidden) and wait for its exit code."""
    import win32con
    import win32event
    import win32process
    from win32com.shell import shell, shellcon

    exe, params = _command(args, gui=False)
    try:
        info = shell.ShellExecuteEx(
            fMask=shellcon.SEE_MASK_NOCLOSEPROCESS,
            lpVerb="runas",
            lpFile=exe,
            lpParameters=params,
            nShow=win32con.SW_HIDE,
        )
    except Exception as exc:  # user pressed "No" on the UAC prompt
        log.info("elevation declined: %s", exc)
        return None
    handle = info["hProcess"]
    win32event.WaitForSingleObject(handle, timeout_ms)
    return int(win32process.GetExitCodeProcess(handle))
