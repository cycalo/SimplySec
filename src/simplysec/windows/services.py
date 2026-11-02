"""Windows service start type and state (only ever used on allow-listed services)."""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any

START_TYPES = {"boot": 0, "system": 1, "auto": 2, "manual": 3, "disabled": 4}
START_NAMES = {v: k for k, v in START_TYPES.items()}


class ServiceError(RuntimeError):
    pass


@dataclass
class ServiceState:
    name: str
    exists: bool
    start_type: str = ""
    delayed: bool = False
    running: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "exists": self.exists,
            "start_type": self.start_type,
            "delayed": self.delayed,
            "running": self.running,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> ServiceState:
        return cls(**d)


def get(name: str) -> ServiceState:
    import win32service

    try:
        scm = win32service.OpenSCManager(None, None, win32service.SC_MANAGER_CONNECT)
    except Exception as exc:
        raise ServiceError(f"cannot open the service manager: {exc}") from exc
    try:
        try:
            h = win32service.OpenService(
                scm, name, win32service.SERVICE_QUERY_CONFIG | win32service.SERVICE_QUERY_STATUS
            )
        except Exception:
            return ServiceState(name=name, exists=False)
        try:
            cfg = win32service.QueryServiceConfig(h)
            status = win32service.QueryServiceStatusEx(h)
            delayed = False
            try:
                delayed = bool(
                    win32service.QueryServiceConfig2(
                        h, win32service.SERVICE_CONFIG_DELAYED_AUTO_START_INFO
                    )
                )
            except Exception:
                delayed = False
            return ServiceState(
                name=name,
                exists=True,
                start_type=START_NAMES.get(cfg[1], str(cfg[1])),
                delayed=delayed,
                running=status["CurrentState"] == win32service.SERVICE_RUNNING,
            )
        finally:
            win32service.CloseServiceHandle(h)
    finally:
        win32service.CloseServiceHandle(scm)


def set_start_type(name: str, start_type: str, delayed: bool = False) -> None:
    import win32service

    if start_type not in START_TYPES:
        raise ServiceError(f"unknown start type {start_type}")
    scm = win32service.OpenSCManager(None, None, win32service.SC_MANAGER_CONNECT)
    try:
        h = win32service.OpenService(scm, name, win32service.SERVICE_CHANGE_CONFIG)
        try:
            win32service.ChangeServiceConfig(
                h,
                win32service.SERVICE_NO_CHANGE,
                START_TYPES[start_type],
                win32service.SERVICE_NO_CHANGE,
                None,
                None,
                0,
                None,
                None,
                None,
                None,
            )
            if start_type == "auto":
                win32service.ChangeServiceConfig2(
                    h, win32service.SERVICE_CONFIG_DELAYED_AUTO_START_INFO, bool(delayed)
                )
        finally:
            win32service.CloseServiceHandle(h)
    except Exception as exc:
        raise ServiceError(f"could not change {name}: {exc}") from exc
    finally:
        win32service.CloseServiceHandle(scm)


def _control(name: str, start: bool, timeout: float = 30) -> None:
    import win32service
    import win32serviceutil

    try:
        if start:
            win32serviceutil.StartService(name)
            want = win32service.SERVICE_RUNNING
        else:
            win32serviceutil.StopService(name)
            want = win32service.SERVICE_STOPPED
    except Exception as exc:
        raise ServiceError(f"could not {'start' if start else 'stop'} {name}: {exc}") from exc
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        state = win32serviceutil.QueryServiceStatus(name)[1]
        if state == want:
            return
        time.sleep(0.5)
    raise ServiceError(f"{name} did not {'start' if start else 'stop'} within {timeout:.0f}s")


def start(name: str) -> None:
    _control(name, True)


def stop(name: str) -> None:
    _control(name, False)
