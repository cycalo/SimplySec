"""Saved Wi-Fi profiles on this PC, via ``netsh wlan export profile`` (locale-neutral XML).

Profiles are exported WITHOUT ``key=clear``; only name, SSID, connection mode, authentication
and encryption are read, and the temporary export folder is deleted immediately.
"""

from __future__ import annotations

import logging
import shutil
import tempfile
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from defusedxml import ElementTree

from . import runner

log = logging.getLogger(__name__)

NS = "{http://www.microsoft.com/networking/WLAN/profile/v1}"
NETSH = str(runner.SYSTEM32 / "netsh.exe")


@dataclass
class WifiProfile:
    name: str
    ssid: str
    connection_mode: str  # auto | manual
    authentication: str  # open, WEP?, WPA2PSK, WPA3SAE, ...
    encryption: str  # none, WEP, TKIP, AES, GCMP...

    @property
    def weak(self) -> str | None:
        """Why this network's security is weak, or None."""
        auth, enc = self.authentication.lower(), self.encryption.lower()
        if auth == "open" and enc in ("none", ""):
            return "open (no password, no encryption)"
        if enc == "wep" or auth == "shared":
            return "WEP (broken encryption)"
        if enc == "tkip":
            return "TKIP (outdated encryption)"
        if auth in ("wpapsk", "wpa"):
            return "WPA (outdated)"
        return None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def parse_profile(xml_text: str) -> WifiProfile | None:
    root = ElementTree.fromstring(xml_text)

    def text(path: str) -> str:
        el = root.find(path)
        return (el.text or "").strip() if el is not None else ""

    name = text(f"{NS}name")
    if not name:
        return None
    return WifiProfile(
        name=name,
        ssid=text(f"{NS}SSIDConfig/{NS}SSID/{NS}name") or name,
        connection_mode=text(f"{NS}connectionMode") or "auto",
        authentication=text(f"{NS}MSM/{NS}security/{NS}authEncryption/{NS}authentication"),
        encryption=text(f"{NS}MSM/{NS}security/{NS}authEncryption/{NS}encryption"),
    )


def _export(name: str | None = None) -> list[WifiProfile]:
    folder = Path(tempfile.mkdtemp(prefix="simplysec-wlan-"))
    try:
        args = [NETSH, "wlan", "export", "profile", f"folder={folder}"]
        if name:
            args.insert(4, f"name={name}")
        res = runner.run(args, timeout=30)
        if not res.ok and not any(folder.iterdir()):
            return []  # no Wi-Fi adapter or WLAN service not running
        out = []
        for f in folder.glob("*.xml"):
            try:
                prof = parse_profile(f.read_text(encoding="utf-8", errors="replace"))
            except Exception as exc:
                log.warning("could not parse a Wi-Fi profile: %s", exc)
                continue
            if prof:
                out.append(prof)
        return out
    finally:
        shutil.rmtree(folder, ignore_errors=True)


def profiles() -> list[WifiProfile]:
    return _export()


def get_connection_mode(profile_name: str) -> str:
    found = [p for p in _export(profile_name) if p.name == profile_name]
    if not found:
        raise runner.CommandError(f"Wi-Fi profile {profile_name!r} not found")
    return found[0].connection_mode


def set_connection_mode(profile_name: str, mode: str) -> None:
    if mode not in ("auto", "manual"):
        raise ValueError("mode must be auto or manual")
    runner.run(
        [
            NETSH,
            "wlan",
            "set",
            "profileparameter",
            f"name={profile_name}",
            f"connectionmode={mode}",
        ],
        timeout=30,
        check=True,
    )
