"""Typed registry reads and writes with exact before-state snapshots."""

from __future__ import annotations

import winreg
from dataclasses import dataclass
from typing import Any

HIVES = {
    "HKLM": winreg.HKEY_LOCAL_MACHINE,
    "HKEY_LOCAL_MACHINE": winreg.HKEY_LOCAL_MACHINE,
    "HKCU": winreg.HKEY_CURRENT_USER,
    "HKEY_CURRENT_USER": winreg.HKEY_CURRENT_USER,
}
TYPES = {
    "REG_DWORD": winreg.REG_DWORD,
    "REG_QWORD": winreg.REG_QWORD,
    "REG_SZ": winreg.REG_SZ,
    "REG_EXPAND_SZ": winreg.REG_EXPAND_SZ,
    "REG_MULTI_SZ": winreg.REG_MULTI_SZ,
}
TYPE_NAMES = {v: k for k, v in TYPES.items()}


class RegistryError(RuntimeError):
    pass


@dataclass
class RegSnapshot:
    key_existed: bool
    exists: bool
    type: str | None = None
    value: Any = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "key_existed": self.key_existed,
            "exists": self.exists,
            "type": self.type,
            "value": self.value,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> RegSnapshot:
        return cls(d["key_existed"], d["exists"], d.get("type"), d.get("value"))


def split_path(path: str) -> tuple[int, str]:
    hive, _, sub = path.replace("/", "\\").partition("\\")
    if hive.upper() not in HIVES:
        raise RegistryError(f"unsupported hive in {path!r}")
    return HIVES[hive.upper()], sub


def read(path: str, name: str) -> RegSnapshot:
    hive, sub = split_path(path)
    try:
        key = winreg.OpenKey(hive, sub, 0, winreg.KEY_READ | winreg.KEY_WOW64_64KEY)
    except FileNotFoundError:
        return RegSnapshot(key_existed=False, exists=False)
    with key:
        try:
            value, vtype = winreg.QueryValueEx(key, name)
        except FileNotFoundError:
            return RegSnapshot(key_existed=True, exists=False)
    return RegSnapshot(True, True, TYPE_NAMES.get(vtype, str(vtype)), value)


def write(path: str, name: str, value: Any, vtype: str) -> None:
    if vtype not in TYPES:
        raise RegistryError(f"unsupported registry type {vtype}")
    hive, sub = split_path(path)
    try:
        with winreg.CreateKeyEx(hive, sub, 0, winreg.KEY_SET_VALUE | winreg.KEY_WOW64_64KEY) as key:
            winreg.SetValueEx(key, name, 0, TYPES[vtype], value)
    except PermissionError as exc:
        raise RegistryError(
            f"access denied writing {path}\\{name} (administrator rights are needed)"
        ) from exc
    except OSError as exc:
        raise RegistryError(f"could not write {path}\\{name}: {exc}") from exc


def delete_value(path: str, name: str) -> None:
    hive, sub = split_path(path)
    try:
        with winreg.OpenKey(hive, sub, 0, winreg.KEY_SET_VALUE | winreg.KEY_WOW64_64KEY) as key:
            winreg.DeleteValue(key, name)
    except FileNotFoundError:
        return
    except PermissionError as exc:
        raise RegistryError(f"access denied deleting {path}\\{name}") from exc


def delete_key_if_empty(path: str) -> bool:
    """Delete a key we created, but only if nothing else was put in it since."""
    hive, sub = split_path(path)
    try:
        with winreg.OpenKey(hive, sub, 0, winreg.KEY_READ | winreg.KEY_WOW64_64KEY) as key:
            subkeys, values, _ = winreg.QueryInfoKey(key)
        if subkeys or values:
            return False
        winreg.DeleteKeyEx(hive, sub, winreg.KEY_WOW64_64KEY, 0)
        return True
    except FileNotFoundError:
        return True
    except PermissionError as exc:
        raise RegistryError(f"access denied deleting key {path}") from exc


def restore(path: str, name: str, before: RegSnapshot | dict[str, Any]) -> None:
    if isinstance(before, dict):
        before = RegSnapshot.from_dict(before)
    if before.exists:
        assert before.type is not None
        write(path, name, before.value, before.type)
        return
    delete_value(path, name)
    if not before.key_existed:
        delete_key_if_empty(path)
