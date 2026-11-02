"""Small setters that need PowerShell or WMI: SMB server, Defender, NetBIOS, restore points.

Each returns real values (as JSON) so the caller can snapshot and verify; failures raise.
"""

from __future__ import annotations

import os
from typing import Any

from . import runner


def smb_server_get() -> dict[str, Any]:
    return runner.powershell_json(
        "$c = Get-SmbServerConfiguration; [ordered]@{ smb1 = [bool]$c.EnableSMB1Protocol } | ConvertTo-Json -Compress"
    )


def smb_server_set(smb1: bool) -> None:
    runner.powershell_json(
        "Set-SmbServerConfiguration -EnableSMB1Protocol ([bool]$P.smb1) -Force -Confirm:$false; 'null'",
        {"smb1": bool(smb1)},
    )


def defender_get() -> dict[str, Any]:
    return runner.powershell_json(
        "$p = Get-MpPreference; [ordered]@{ controlled_folder_access = [int]$p.EnableControlledFolderAccess }"
        " | ConvertTo-Json -Compress"
    )


def defender_set_cfa(mode: int) -> None:
    runner.powershell_json(
        "Set-MpPreference -EnableControlledFolderAccess ([int]$P.mode); 'null'", {"mode": int(mode)}
    )


def update_signatures() -> None:
    runner.powershell_json("Update-MpSignature; 'null'", timeout=600)


def netbios_get(config_index: int) -> int:
    data = runner.powershell_json(
        '$a = Get-CimInstance Win32_NetworkAdapterConfiguration -Filter ("Index={0}" -f [int]$P.index);'
        " if ($a) { [int]$a.TcpipNetbiosOptions } else { 'null' }",
        {"index": int(config_index)},
    )
    if data is None:
        raise runner.CommandError(f"network adapter configuration {config_index} not found")
    return int(data)


def netbios_set(config_index: int, option: int) -> None:
    """0 = default (DHCP decides), 1 = enabled, 2 = disabled. Uses SetTcpipNetbios (as v1 did)."""
    data = runner.powershell_json(
        '$a = Get-CimInstance Win32_NetworkAdapterConfiguration -Filter ("Index={0}" -f [int]$P.index);'
        " $r = Invoke-CimMethod -InputObject $a -MethodName SetTcpipNetbios"
        " -Arguments @{ TcpipNetbiosOptions = [uint32]$P.option };"
        " [int]$r.ReturnValue",
        {"index": int(config_index), "option": int(option)},
    )
    if int(data) not in (0, 1):  # 1 = success, reboot required
        raise runner.CommandError(f"SetTcpipNetbios returned {data}")


def create_restore_point(description: str) -> None:
    runner.powershell_json(
        "Checkpoint-Computer -Description $P.description -RestorePointType MODIFY_SETTINGS; 'null'",
        {"description": description[:60]},
        timeout=300,
    )


SETTINGS_URIS = {
    "windows_security": "windowsdefender:",
    "virus_protection": "windowsdefender://threat",
    "ransomware": "windowsdefender://ransomwareprotection",
    "windows_update": "ms-settings:windowsupdate",
    "bitlocker": "ms-settings:deviceencryption",
    "network": "ms-settings:network-status",
    "remote_desktop": "ms-settings:remotedesktop",
    "sharing": "ms-settings:network-advancedsettings",
}


def open_settings(target: str) -> None:
    uri = SETTINGS_URIS.get(target)
    if uri is None:
        raise ValueError(f"unknown settings page {target}")
    os.startfile(uri)
