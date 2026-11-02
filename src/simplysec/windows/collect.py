"""Collect everything a scan needs, in parallel. Read-only; works without admin."""

from __future__ import annotations

import datetime as dt
import logging
import os
import time
import winreg
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from typing import Any

from ..app import elevation, paths
from ..core import knowledge
from ..core.checks.base import SignatureInfo
from ..core.engine import RawScan
from ..core.exposure import normalize_app_path
from ..core.models import FirewallState, Profile
from . import firewall, listeners, network, runner

log = logging.getLogger(__name__)

# Only these environment variables are kept (for path expansion and "you set this up"
# detection). Everything else, which may hold secrets, is never stored.
PATH_VARS = {
    "SYSTEMROOT",
    "WINDIR",
    "SYSTEMDRIVE",
    "PROGRAMFILES",
    "PROGRAMFILES(X86)",
    "PROGRAMW6432",
    "COMMONPROGRAMFILES",
    "COMMONPROGRAMFILES(X86)",
    "PROGRAMDATA",
    "ALLUSERSPROFILE",
    "LOCALAPPDATA",
    "APPDATA",
    "USERPROFILE",
    "PUBLIC",
    "TEMP",
    "TMP",
}


def environment() -> dict[str, str]:
    """Process env plus the user's and machine's stored variables, filtered to safe keys."""
    wanted = PATH_VARS | {p.intent_env.upper() for p in knowledge.get().programs if p.intent_env}
    env: dict[str, str] = {}
    for root, sub in (
        (
            winreg.HKEY_LOCAL_MACHINE,
            r"SYSTEM\CurrentControlSet\Control\Session Manager\Environment",
        ),
        (winreg.HKEY_CURRENT_USER, "Environment"),
    ):
        try:
            with winreg.OpenKey(root, sub) as key:
                i = 0
                while True:
                    try:
                        name, value, _ = winreg.EnumValue(key, i)
                    except OSError:
                        break
                    i += 1
                    if name.upper() in wanted and isinstance(value, str):
                        env[name.upper()] = os.path.expandvars(value)
        except OSError:
            continue
    for k, v in os.environ.items():
        if k.upper() in wanted:
            env[k.upper()] = v
    return env


def _facts() -> dict[str, Any]:
    data = runner.powershell_file(paths.facts_script(), timeout=180)
    return data if isinstance(data, dict) else {}


def collect(progress: Callable[[str], None] | None = None) -> RawScan:
    started = time.monotonic()
    stamp = dt.datetime.now().astimezone().isoformat(timespec="seconds")
    errors: list[str] = []

    def say(text: str) -> None:
        if progress:
            progress(text)

    say("Reading Windows security settings…")
    with ThreadPoolExecutor(max_workers=3, thread_name_prefix="collect") as pool:
        f_facts = pool.submit(_facts)
        say("Finding programs that listen for connections…")
        f_listeners = pool.submit(listeners.read_listeners)
        f_firewall = pool.submit(firewall.read_state)

        try:
            lst = f_listeners.result()
        except Exception as exc:
            log.exception("listeners failed")
            errors.append(f"could not list listening ports: {exc}")
            lst = []
        try:
            fw = f_firewall.result()
        except Exception as exc:
            log.exception("firewall read failed")
            errors.append(f"could not read the firewall: {exc}")
            fw = FirewallState(profiles={})

        env = environment()
        windows_dir = env.get("SYSTEMROOT", r"C:\Windows")
        exes = {x.exe for x in lst if x.exe}
        for r in fw.rules:
            if (
                r.enabled
                and r.direction == "in"
                and r.action == "allow"
                and r.profile_mask & Profile.PUBLIC
            ):
                app = normalize_app_path(r.application, env)
                if app and app != "system" and not app.startswith(windows_dir.lower()):
                    exes.add(app)
        say("Checking program signatures…")
        f_sigs = pool.submit(listeners.signatures, sorted(exes))

        try:
            facts = f_facts.result()
        except Exception as exc:
            log.exception("facts.ps1 failed")
            errors.append(f"could not read Windows settings: {exc}")
            facts = {}
        try:
            sigs = {k: SignatureInfo(v.status, v.publisher) for k, v in f_sigs.result().items()}
        except Exception as exc:
            log.warning("signature check failed: %s", exc)
            errors.append(f"could not check signatures: {exc}")
            sigs = {}

    net_fact = (
        facts.get("network", {}).get("value") if isinstance(facts.get("network"), dict) else None
    )
    try:
        interfaces = network.build_interfaces(net_fact)
    except Exception as exc:
        log.exception("interfaces failed")
        errors.append(f"could not read network adapters: {exc}")
        interfaces = []

    return RawScan(
        facts=facts,
        listeners=lst,
        firewall=fw,
        interfaces=interfaces,
        signatures=sigs,
        env=env,
        is_admin=elevation.is_admin(),
        windows_dir=windows_dir,
        errors=errors,
        started=stamp,
        duration=time.monotonic() - started,
    )
