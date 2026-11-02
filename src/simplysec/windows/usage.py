"""What is actually being used right now: evidence for "what would this fix affect?".

Read-only. Collected with every scan and stored as the ``usage`` fact:

* inbound connections: other devices connected to a listening program on this PC;
* Remote Desktop: active RDP sessions, and whether *this* session is remote;
* mapped drives and network printers (and whether they use short names that may depend on
  NetBIOS or LLMNR name lookups);
* SMB sessions with their dialect (administrator only: shows SMB1 clients);
* when local accounts were last used (Guest);
* whether Remote Assistance (msra.exe) is running.
"""

from __future__ import annotations

import ctypes
import logging
import socket
from typing import Any

import psutil

from ..core.models import Listener
from . import runner

log = logging.getLogger(__name__)

SM_REMOTESESSION = 0x1000
WTS_PROTOCOL_RDP = 2

_PS = r"""
$out = [ordered]@{}
try {
  $out.mappings = @(Get-SmbMapping -ErrorAction Stop | ForEach-Object {
    [ordered]@{ local = $_.LocalPath; remote = $_.RemotePath; status = [string]$_.Status } })
} catch { $out.mappings = @() }
try {
  $out.printers = @(Get-Printer -ErrorAction Stop | Where-Object { $_.Type -eq 1 -or $_.PortName -like '\\*' -or $_.PortName -like 'WSD*' -or $_.PortName -like 'IP_*' } |
    ForEach-Object { [ordered]@{ name = $_.Name; port = $_.PortName; computer = $_.ComputerName } })
} catch { $out.printers = @() }
try {
  $out.smb_sessions = @(Get-SmbSession -ErrorAction Stop | ForEach-Object {
    [ordered]@{ client = $_.ClientComputerName; user = $_.ClientUserName; dialect = [string]$_.Dialect } })
  $out.smb_sessions_status = 'ok'
} catch { $out.smb_sessions = @(); $out.smb_sessions_status = 'needs_admin' }
try {
  $out.last_logons = @(Get-LocalUser | ForEach-Object {
    [ordered]@{ sid = $_.SID.Value; last = if ($_.LastLogon) { $_.LastLogon.ToUniversalTime().ToString('o') } else { $null } } })
} catch { $out.last_logons = @() }
$out | ConvertTo-Json -Depth 5 -Compress
"""


def inbound_connections(listeners: list[Listener]) -> list[dict[str, Any]]:
    """Established TCP connections from other machines to a port this PC listens on."""
    listening = {(x.port, x.pid) for x in listeners if x.protocol == "tcp"}
    names = {x.pid: x.process for x in listeners}
    out = []
    for c in psutil.net_connections(kind="tcp"):
        if c.status != psutil.CONN_ESTABLISHED or not c.raddr or not c.laddr:
            continue
        if (c.laddr.port, c.pid or 0) not in listening:
            continue
        remote = c.raddr.ip
        if remote.startswith(("127.", "::1", "::ffff:127.")):
            continue
        out.append(
            {
                "protocol": "tcp",
                "local_port": c.laddr.port,
                "local_ip": c.laddr.ip,
                "remote_ip": remote,
                "pid": c.pid or 0,
                "process": names.get(c.pid or 0, ""),
            }
        )
    return out


def rdp_sessions() -> list[dict[str, Any]]:
    try:
        import win32ts
    except ImportError:  # pragma: no cover
        return []
    out = []
    for s in win32ts.WTSEnumerateSessions(win32ts.WTS_CURRENT_SERVER_HANDLE):
        try:
            proto = win32ts.WTSQuerySessionInformation(
                None, s["SessionId"], win32ts.WTSClientProtocolType
            )
        except Exception:
            continue
        if proto == WTS_PROTOCOL_RDP and s.get("State") == 0:
            out.append({"session": s["SessionId"], "station": s.get("WinStationName", "")})
    return out


def collect(listeners: list[Listener]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    try:
        value["connections"] = inbound_connections(listeners)
    except Exception as exc:
        log.warning("connections: %s", exc)
        value["connections"] = []
    try:
        value["remote_session"] = bool(ctypes.windll.user32.GetSystemMetrics(SM_REMOTESESSION))
    except OSError:
        value["remote_session"] = False
    value["rdp_sessions"] = rdp_sessions()
    value["msra_running"] = any(
        p.info.get("name", "").lower() == "msra.exe" for p in psutil.process_iter(["name"])
    )
    value["hostname"] = socket.gethostname()
    try:
        value.update(runner.powershell_json(_PS, timeout=60) or {})
    except Exception as exc:
        log.warning("usage facts: %s", exc)
    return {"status": "ok", "value": value}
