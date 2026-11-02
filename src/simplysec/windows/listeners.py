"""Listening sockets with their exact program, services, user and AppContainer.

psutil gives protocol, address, port and PID for every socket in about a millisecond. For
each PID we add the program path, the services it hosts (one EnumServicesStatusEx call), the
user SID and the AppContainer package SID (from the process token when readable).
"""

from __future__ import annotations

import ctypes
import logging
import ntpath
import os
import re
import socket
from ctypes import wintypes
from dataclasses import dataclass

import psutil

from ..core.models import Listener
from . import runner

log = logging.getLogger(__name__)

SYSTEM_SID = "S-1-5-18"
ACCOUNT_SIDS = {
    "localsystem": SYSTEM_SID,
    "nt authority\\system": SYSTEM_SID,
    "nt authority\\localservice": "S-1-5-19",
    "nt authority\\local service": "S-1-5-19",
    "nt authority\\networkservice": "S-1-5-20",
    "nt authority\\network service": "S-1-5-20",
}
# Binaries that always run as LocalSystem; used only when the token itself is unreadable.
ALWAYS_SYSTEM = {
    "wininit.exe",
    "services.exe",
    "lsass.exe",
    "csrss.exe",
    "smss.exe",
    "winlogon.exe",
}

PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
TOKEN_QUERY = 0x0008
TokenUser = 1
TokenIsAppContainer = 29
TokenAppContainerSid = 31


@dataclass
class ProcessIdentity:
    name: str = ""
    exe: str = ""
    user_sid: str | None = None
    package_sid: str | None = None


# --------------------------------------------------------------------------- tokens (ctypes)

_k32 = ctypes.WinDLL("kernel32", use_last_error=True)
_adv = ctypes.WinDLL("advapi32", use_last_error=True)
_k32.OpenProcess.restype = wintypes.HANDLE
_k32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
_k32.CloseHandle.argtypes = [wintypes.HANDLE]
_k32.LocalFree.argtypes = [ctypes.c_void_p]
_adv.OpenProcessToken.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)]
_adv.GetTokenInformation.argtypes = [
    wintypes.HANDLE,
    ctypes.c_int,
    ctypes.c_void_p,
    wintypes.DWORD,
    ctypes.POINTER(wintypes.DWORD),
]
_adv.ConvertSidToStringSidW.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_wchar_p)]


def _token_info(token: wintypes.HANDLE, cls: int) -> ctypes.Array[ctypes.c_char] | None:
    size = wintypes.DWORD(0)
    _adv.GetTokenInformation(token, cls, None, 0, ctypes.byref(size))
    if size.value == 0:
        return None
    buf = ctypes.create_string_buffer(size.value)
    if not _adv.GetTokenInformation(token, cls, buf, size, ctypes.byref(size)):
        return None
    return buf


def _sid_string(psid: int) -> str | None:
    out = ctypes.c_wchar_p()
    if not _adv.ConvertSidToStringSidW(ctypes.c_void_p(psid), ctypes.byref(out)):
        return None
    try:
        return out.value
    finally:
        _k32.LocalFree(ctypes.cast(out, ctypes.c_void_p))


def read_token(pid: int) -> tuple[str | None, str | None]:
    """(user SID, AppContainer SID or "") for a process, or (None, None) if unreadable."""
    hproc = _k32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
    if not hproc:
        return None, None
    token = wintypes.HANDLE()
    try:
        if not _adv.OpenProcessToken(hproc, TOKEN_QUERY, ctypes.byref(token)):
            return None, None
        try:
            user_buf = _token_info(token, TokenUser)
            user = None
            if user_buf is not None:
                psid = ctypes.cast(user_buf, ctypes.POINTER(ctypes.c_void_p))[0]
                user = _sid_string(psid)
            package: str | None = ""
            is_ac = _token_info(token, TokenIsAppContainer)
            if is_ac is not None and ctypes.cast(is_ac, ctypes.POINTER(wintypes.DWORD))[0]:
                sid_buf = _token_info(token, TokenAppContainerSid)
                package = None
                if sid_buf is not None:
                    package = _sid_string(ctypes.cast(sid_buf, ctypes.POINTER(ctypes.c_void_p))[0])
            return user, package
        finally:
            _k32.CloseHandle(token)
    finally:
        _k32.CloseHandle(hproc)


# --------------------------------------------------------------------------- services


def services_by_pid() -> dict[int, list[str]]:
    """Running Win32 services grouped by PID."""
    import win32service

    by_pid: dict[int, list[str]] = {}
    scm = win32service.OpenSCManager(None, None, win32service.SC_MANAGER_ENUMERATE_SERVICE)
    try:
        for s in win32service.EnumServicesStatusEx(
            scm, win32service.SERVICE_WIN32, win32service.SERVICE_ACTIVE, None
        ):
            pid = int(s.get("ProcessId") or 0)
            if pid:
                by_pid.setdefault(pid, []).append(s["ServiceName"])
    finally:
        win32service.CloseServiceHandle(scm)
    return by_pid


def service_account_sid(name: str) -> str | None:
    import win32service

    try:
        scm = win32service.OpenSCManager(None, None, win32service.SC_MANAGER_CONNECT)
        try:
            h = win32service.OpenService(scm, name, win32service.SERVICE_QUERY_CONFIG)
            try:
                cfg = win32service.QueryServiceConfig(h)
            finally:
                win32service.CloseServiceHandle(h)
        finally:
            win32service.CloseServiceHandle(scm)
    except Exception:
        return None
    account = (cfg[7] or "LocalSystem").strip().lower()
    return ACCOUNT_SIDS.get(account)


# --------------------------------------------------------------------------- listeners


def _identity(
    pid: int, services: list[str] | None, cache: dict[int, ProcessIdentity]
) -> ProcessIdentity:
    if pid in cache:
        return cache[pid]
    ident = ProcessIdentity()
    if pid == 4:
        ident = ProcessIdentity(name="System", exe="", user_sid=SYSTEM_SID, package_sid="")
    elif pid == 0:
        ident = ProcessIdentity(name="System Idle Process", user_sid=SYSTEM_SID, package_sid="")
    else:
        try:
            p = psutil.Process(pid)
            ident.name = p.name()
            try:
                ident.exe = p.exe()
            except (psutil.AccessDenied, psutil.ZombieProcess, OSError):
                ident.exe = ""
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
        user, package = read_token(pid)
        if user is None and services:
            # Services can't be AppContainers; their account comes from the service config.
            sids = {service_account_sid(s) for s in services}
            sids.discard(None)
            if len(sids) == 1:
                user = sids.pop()
            package = ""
        if user is None and ident.exe:
            # A child of a service process running the same program inherits its account
            # (e.g. tailscaled.exe starts a helper copy of itself).
            try:
                parent = psutil.Process(pid).ppid()
                parent_services = _SERVICE_MAP.get(parent)
                if parent_services and psutil.Process(parent).exe().lower() == ident.exe.lower():
                    sids = {service_account_sid(s) for s in parent_services}
                    sids.discard(None)
                    if len(sids) == 1:
                        user, package = sids.pop(), ""
            except (psutil.Error, OSError):
                pass
        if user is None and ident.exe:
            base = ntpath.basename(ident.exe).lower()
            sysdir = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32").lower()
            if base in ALWAYS_SYSTEM and ntpath.dirname(ident.exe).lower() == sysdir:
                user, package = SYSTEM_SID, ""
        ident.user_sid = user
        ident.package_sid = package
    cache[pid] = ident
    return ident


_SERVICE_MAP: dict[int, list[str]] = {}


def read_listeners() -> list[Listener]:
    global _SERVICE_MAP
    try:
        svc_map = services_by_pid()
        _SERVICE_MAP = svc_map
    except Exception as exc:  # pragma: no cover - depends on SCM access
        log.warning("could not enumerate services: %s", exc)
        svc_map = {}
        services_known = False
    else:
        services_known = True

    cache: dict[int, ProcessIdentity] = {}
    out: list[Listener] = []
    seen: set[tuple[str, str, int]] = set()
    for c in psutil.net_connections(kind="inet"):
        if c.type == socket.SOCK_STREAM:
            if c.status != psutil.CONN_LISTEN:
                continue
            proto = "tcp"
        else:
            if c.raddr:
                continue
            proto = "udp"
        if not c.laddr:
            continue
        key = (proto, c.laddr.ip, c.laddr.port)
        if key in seen:
            continue
        seen.add(key)
        pid = int(c.pid or 0)
        services: list[str] | None = svc_map.get(pid, []) if services_known else None
        if pid == 4:
            services = []
        ident = _identity(pid, services, cache)
        out.append(
            Listener(
                protocol=proto,
                address=c.laddr.ip,
                port=c.laddr.port,
                pid=pid,
                process=ident.name,
                exe=ident.exe,
                services=services,
                user_sid=ident.user_sid,
                package_sid=ident.package_sid,
            )
        )
    out.sort(key=lambda listener: (listener.protocol, listener.port, listener.address))
    return out


# --------------------------------------------------------------------------- signatures


@dataclass
class Signature:
    status: str  # Valid, NotSigned, HashMismatch, UnknownError, ...
    signer: str = ""

    @property
    def signed(self) -> bool:
        return self.status == "Valid"

    @property
    def publisher(self) -> str:
        """'CN=Microsoft Windows, O=Microsoft Corporation, ...' -> 'Microsoft Corporation'."""
        for key in ("O", "CN"):
            m = re.search(rf'(?:^|,\s*){key}=("([^"]+)"|[^,]+)', self.signer)
            if m:
                return (m.group(2) or m.group(1)).strip()
        return ""


_SIG_SCRIPT = r"""
$out = @()
foreach ($path in $P.paths) {
  try {
    $s = Get-AuthenticodeSignature -LiteralPath $path -ErrorAction Stop
    $signer = ''
    if ($s.SignerCertificate) { $signer = $s.SignerCertificate.Subject }
    $out += [pscustomobject]@{ path = $path; status = [string]$s.Status; signer = $signer }
  } catch {
    $out += [pscustomobject]@{ path = $path; status = 'Unreadable'; signer = '' }
  }
}
ConvertTo-Json -InputObject @($out) -Compress
"""


def signatures(paths: list[str]) -> dict[str, Signature]:
    """Authenticode status for many files in one PowerShell call (catalog-aware)."""
    unique = sorted({p for p in paths if p})
    if not unique:
        return {}
    data = runner.powershell_json(_SIG_SCRIPT, {"paths": unique}, timeout=120) or []
    if isinstance(data, dict):
        data = [data]
    return {d["path"].lower(): Signature(d.get("status", ""), d.get("signer", "")) for d in data}
