"""What would this fix affect? Evidence-based impact analysis for every fix.

Two kinds of evidence:

* **Simulation** (firewall rules, firewall profiles, network category): the change is applied
  to a copy of the firewall model and every affected listener is re-evaluated. The result lists
  exactly which programs and ports stop (or start) being reachable, and from which network.
* **Live use** (the ``usage`` fact collected with every scan): devices connected right now,
  Remote Desktop sessions (including whether you are connected remotely yourself), mapped drives
  and printers that rely on short names, SMB1 clients, when the Guest account was last used, and
  whether Remote Assistance is running.

Levels, shown in plain words and colours in the preview:

* ``in_use``: something is using it right now; Fix recommended leaves it out;
* ``may_affect``: it would change something you might use (listed);
* ``none_found``: nothing on this PC appears to use it;
* ``unknown``: SimplySec can't check this (said explicitly, never presented as safe).
"""

from __future__ import annotations

import copy
import datetime as dt
import enum
import ipaddress
from dataclasses import asdict, dataclass, field
from typing import Any

from .checks.base import ScanContext
from .exposure import EvalContext, compile_rules, evaluate, normalize_app_path, parse_ports
from .models import ActionSpec, FirewallRule, Listener, Profile, Verdict
from .util import as_list


class Level(enum.StrEnum):
    IN_USE = "in_use"
    MAY_AFFECT = "may_affect"
    NONE_FOUND = "none_found"
    UNKNOWN = "unknown"

    @property
    def rank(self) -> int:
        return ["none_found", "unknown", "may_affect", "in_use"].index(self.value)

    @property
    def label(self) -> str:
        return {
            "in_use": "In use right now",
            "may_affect": "Might affect something you use",
            "none_found": "Nothing found using this",
            "unknown": "SimplySec can't check this",
        }[self.value]


@dataclass
class Impact:
    level: Level
    headline: str
    evidence: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["level"] = self.level.value
        return d

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> Impact:
        return cls(Level(d["level"]), d.get("headline", ""), list(d.get("evidence", [])))


def worst(impacts: list[Impact]) -> Impact:
    if not impacts:
        return Impact(Level.NONE_FOUND, "Nothing found using this.")
    top = max(impacts, key=lambda i: i.level.rank)
    evidence = [e for i in impacts for e in i.evidence]
    return Impact(top.level, top.headline, list(dict.fromkeys(evidence)))


# --------------------------------------------------------------------------- usage helpers


def usage(ctx: ScanContext) -> dict[str, Any]:
    return ctx.facts.get("usage") or {}


def _is_short_name(host: str) -> bool:
    host = host.strip("[]")
    if not host or "." in host:
        return False
    try:
        ipaddress.ip_address(host)
        return False
    except ValueError:
        return True


def _unc_host(path: str) -> str:
    p = (path or "").lstrip("\\")
    return p.split("\\", 1)[0] if p else ""


def short_name_dependencies(ctx: ScanContext) -> list[str]:
    """Mapped drives and printers reached by a short name (may rely on NetBIOS/LLMNR)."""
    u = usage(ctx)
    out = []
    for m in as_list(u.get("mappings")):
        host = _unc_host(m.get("remote", ""))
        if _is_short_name(host):
            out.append(
                f"Drive {m.get('local') or ''} → {m.get('remote')} uses the short name '{host}'"
            )
    for p in as_list(u.get("printers")):
        host = _unc_host(p.get("port", "")) or p.get("computer", "")
        if _is_short_name(host):
            out.append(f"Printer '{p.get('name')}' is reached by the short name '{host}'")
    return out


def connections_to(ctx: ScanContext, port: int, pid: int | None = None) -> list[dict[str, Any]]:
    return [
        c
        for c in as_list(usage(ctx).get("connections"))
        if c.get("local_port") == port and (pid is None or c.get("pid") == pid)
    ]


# --------------------------------------------------------------------------- simulation


@dataclass
class Change:
    listener: Listener
    interface: str
    profile: Profile
    became_reachable: bool


def _apply_to_model(ctx: ScanContext, specs: list[ActionSpec]) -> tuple[Any, list[Any]] | None:
    fw = copy.deepcopy(ctx.firewall)
    interfaces = copy.deepcopy(ctx.interfaces)
    touched = False
    for s in specs:
        if s.kind == "firewall.add_rule":
            fw.rules.append(FirewallRule.from_dict(s.params["rule"]))
            touched = True
        elif s.kind == "firewall.remove_rule":
            fw.rules = [r for r in fw.rules if r.name != s.params["name"]]
            touched = True
        elif s.kind == "firewall.profile":
            st = fw.profiles[Profile(int(s.params["profile"]))]
            if "enabled" in s.params:
                st.enabled = s.params["enabled"]
            if "default_inbound_block" in s.params:
                st.default_inbound_block = s.params["default_inbound_block"]
            touched = True
        elif s.kind == "network.category":
            for i in interfaces:
                if i.index == int(s.params["index"]):
                    i.profile = Profile[s.params["profile"].upper()]
                    touched = True
    return (fw, interfaces) if touched else None


def _candidates(ctx: ScanContext, specs: list[ActionSpec]) -> list[Listener]:
    """Only re-evaluate listeners a new block rule could match (fast path)."""
    if not all(s.kind == "firewall.add_rule" for s in specs):
        return ctx.listeners
    out = []
    for s in specs:
        rule = FirewallRule.from_dict(s.params["rule"])
        app = normalize_app_path(rule.application, ctx.env)
        ports = parse_ports(rule.local_ports)
        for lst in ctx.listeners:
            if app and normalize_app_path(lst.exe, ctx.env) != app:
                continue
            if not ports.any and not any(lo <= lst.port <= hi for lo, hi in ports.ranges):
                continue
            out.append(lst)
    return list({id(x): x for x in out}.values())


def simulate(ctx: ScanContext, specs: list[ActionSpec]) -> list[Change] | None:
    model = _apply_to_model(ctx, specs)
    if model is None:
        return None
    fw, interfaces = model
    before = {e.listener.key: e for e in ctx.exposures}
    evalctx = EvalContext(interfaces, env=ctx.env)
    rules = compile_rules(fw.rules, evalctx.env)
    changes = []
    for lst in _candidates(ctx, specs):
        old = before.get(lst.key)
        new = evaluate(lst, fw, evalctx, rules)
        old_v = {ie.interface: ie for ie in (old.per_interface if old else [])}
        for ie in new.per_interface:
            was = old_v.get(ie.interface)
            was_reachable = bool(was and was.verdict == Verdict.REACHABLE)
            now_reachable = ie.verdict == Verdict.REACHABLE
            if was_reachable != now_reachable:
                changes.append(Change(lst, ie.interface, ie.profile, now_reachable))
    return changes


def _describe(lst: Listener) -> str:
    name = lst.process or ("Windows" if lst.pid == 4 else f"PID {lst.pid}")
    return f"{name} ({lst.protocol.upper()} {lst.port})"


def firewall_impact(ctx: ScanContext, specs: list[ActionSpec], program: str = "") -> Impact:
    changes = simulate(ctx, specs)
    if changes is None:
        return Impact(Level.UNKNOWN, "SimplySec could not simulate this change.")
    lost: dict[str, list[str]] = {}
    gained: dict[str, list[str]] = {}
    connected: list[str] = []
    iface_ips = {i.alias: {str(x.ip) for x in i.ip_interfaces()} for i in ctx.interfaces}
    for ch in changes:
        target = gained if ch.became_reachable else lost
        where = f"{ch.interface} ({ch.profile.label})"
        target.setdefault(_describe(ch.listener), [])
        if where not in target[_describe(ch.listener)]:
            target[_describe(ch.listener)].append(where)
        if not ch.became_reachable and ch.listener.protocol == "tcp":
            for c in connections_to(ctx, ch.listener.port, ch.listener.pid):
                local = c.get("local_ip", "")
                if local in iface_ips.get(ch.interface, set()) or (
                    ch.listener.is_wildcard and not local
                ):
                    connected.append(
                        f"{c.get('remote_ip')} is connected to {_describe(ch.listener)} right now"
                    )
    evidence = [
        f"{what} would stop being reachable from {', '.join(where)}" for what, where in lost.items()
    ]
    evidence += [
        f"{what} would become reachable from {', '.join(where)}" for what, where in gained.items()
    ]
    if connected:
        return Impact(
            Level.IN_USE,
            "Another device is connected to this right now and would be cut off.",
            list(dict.fromkeys(connected)) + evidence,
        )
    if lost or gained:
        headline = (
            "Nothing is connected right now, but if you use these from other devices they will stop working there:"
            if lost and not gained
            else "This changes who can reach the following:"
        )
        return Impact(Level.MAY_AFFECT, headline, evidence)
    if program:
        running = any(
            normalize_app_path(x.exe, ctx.env) == normalize_app_path(program, ctx.env)
            for x in ctx.listeners
        )
        if not running:
            return Impact(
                Level.NONE_FOUND,
                "This program isn't accepting connections right now, so nothing would be cut off today.",
                ["When it runs, devices on the affected networks won't be able to connect to it."],
            )
    return Impact(Level.NONE_FOUND, "Nothing listening on this PC right now would be affected.")


# --------------------------------------------------------------------------- per-fix rules


def _days_ago(iso: str | None) -> int | None:
    if not iso:
        return None
    try:
        when = dt.datetime.fromisoformat(iso.replace("Z", "+00:00")[:32])
    except ValueError:
        return None
    if when.tzinfo is None:
        when = when.replace(tzinfo=dt.UTC)
    return (dt.datetime.now(dt.UTC) - when).days


def _name_lookup_impact(ctx: ScanContext, what: str, ports: tuple[int, ...]) -> Impact:
    deps = short_name_dependencies(ctx)
    conns = [c for p in ports for c in connections_to(ctx, p)]
    if conns:
        return Impact(
            Level.IN_USE,
            f"Another device is using {what} with this PC right now.",
            [f"{c.get('remote_ip')} is connected to port {c.get('local_port')}" for c in conns]
            + deps,
        )
    if deps:
        return Impact(
            Level.MAY_AFFECT,
            "These connections use short names, which Windows may look up this way. Check they still work afterwards (undo is one click):",
            deps,
        )
    return Impact(
        Level.NONE_FOUND,
        f"No mapped drives, printers or connections on this PC rely on {what}.",
        [
            "SimplySec can't see which names other devices look up, so very old devices are the only realistic risk."
        ],
    )


NO_USAGE_NEEDED = {
    "accounts.uac_prompt",
    "system.autorun_off",
    "malware.update_signatures",
    "malware.cfa_on",
}


def assess(
    fix_id: str, params: dict[str, Any], specs: list[ActionSpec], ctx: ScanContext | None
) -> Impact:
    """Impact of applying one fix, based on this scan. Never claims "nothing uses this" when
    the live-usage information could not be collected."""
    impact = _assess(fix_id, params, specs, ctx)
    if ctx is None or ctx.facts.status("usage") == "ok" or fix_id in NO_USAGE_NEEDED:
        return impact
    if impact.level == Level.NONE_FOUND:
        return Impact(
            Level.UNKNOWN,
            "SimplySec couldn't check what is in use right now, so it can't say whether "
            "anything relies on this.",
            impact.evidence,
        )
    if impact.level == Level.MAY_AFFECT and impact.headline.startswith("Nothing is connected"):
        return Impact(
            Level.MAY_AFFECT,
            "SimplySec couldn't check current connections. If you use these from other "
            "devices they will stop working there:",
            impact.evidence,
        )
    return impact


def _assess(
    fix_id: str, params: dict[str, Any], specs: list[ActionSpec], ctx: ScanContext | None
) -> Impact:
    if ctx is None:
        return Impact(Level.UNKNOWN, "Scan first to see what this would affect.")
    u = usage(ctx)
    if fix_id.startswith("exposure.") or fix_id in (
        "firewall.enable",
        "firewall.default_block",
        "network.mark_private",
        "housekeeping.remove_v1_rules",
    ):
        return firewall_impact(ctx, specs, params.get("exe", ""))
    if fix_id == "legacy.netbios_off":
        return _name_lookup_impact(ctx, "NetBIOS (old Windows file sharing)", (139,))
    if fix_id == "legacy.llmnr_off":
        return _name_lookup_impact(ctx, "LLMNR name lookups", ())
    if fix_id == "legacy.smb1_off":
        if u.get("smb_sessions_status") != "ok":
            return Impact(
                Level.UNKNOWN,
                "Only administrators can see which devices use SMBv1. Modern Windows, Mac, Android and NAS devices don't.",
            )
        old = [
            s for s in as_list(u.get("smb_sessions")) if str(s.get("dialect", "")).startswith("1")
        ]
        if old:
            return Impact(
                Level.IN_USE,
                "A device is using SMBv1 to reach this PC right now.",
                [f"{s.get('client')} ({s.get('user')})" for s in old],
            )
        return Impact(Level.NONE_FOUND, "No device is using SMBv1 with this PC.")
    if fix_id in ("rdp.disable", "rdp.require_nla"):
        evidence = []
        if u.get("remote_session"):
            evidence.append("You are using this PC through Remote Desktop right now.")
        evidence += [
            f"Remote Desktop session '{s.get('station')}' is active"
            for s in as_list(u.get("rdp_sessions"))
        ]
        evidence += [
            f"{c.get('remote_ip')} is connected to Remote Desktop"
            for c in connections_to(ctx, 3389)
        ]
        if evidence and fix_id == "rdp.disable":
            return Impact(
                Level.IN_USE,
                "Remote Desktop is in use: turning it off would disconnect it.",
                list(dict.fromkeys(evidence)),
            )
        if evidence:
            return Impact(
                Level.MAY_AFFECT,
                "Remote Desktop is in use; very old clients would no longer connect.",
                list(dict.fromkeys(evidence)),
            )
        return Impact(Level.NONE_FOUND, "Nobody is connected through Remote Desktop right now.")
    if fix_id == "rdp.remote_assistance_off":
        if u.get("msra_running"):
            return Impact(
                Level.IN_USE,
                "Windows Remote Assistance is open right now.",
                ["msra.exe is running"],
            )
        return Impact(
            Level.NONE_FOUND, "Remote Assistance isn't running. Quick Assist keeps working."
        )
    if fix_id == "accounts.guest_off":
        last = next(
            (
                x.get("last")
                for x in as_list(u.get("last_logons"))
                if str(x.get("sid", "")).endswith("-501")
            ),
            None,
        )
        days = _days_ago(last)
        if days is None:
            return Impact(Level.NONE_FOUND, "The Guest account has never been used to sign in.")
        if days <= 30:
            return Impact(
                Level.IN_USE,
                f"Someone signed in as Guest {days} day(s) ago.",
                ["Make sure they have their own account first."],
            )
        return Impact(Level.MAY_AFFECT, f"The Guest account was last used {days} days ago.")
    if fix_id == "accounts.blank_password_limit":
        accounts = ctx.facts.get("accounts") or {}
        blank = [
            a.get("name")
            for a in as_list(accounts.get("users"))
            if a.get("enabled") and a.get("password_required") is False
        ]
        if blank:
            return Impact(
                Level.MAY_AFFECT,
                "These accounts have no password; other PCs could no longer open this PC's shares with them:",
                [str(b) for b in blank],
            )
        return Impact(Level.NONE_FOUND, "No enabled account here is set up without a password.")
    if fix_id == "malware.cfa_on":
        return Impact(
            Level.MAY_AFFECT,
            "Some programs (older games, editors, backup tools) may be stopped from saving into Documents, Pictures or Desktop until you allow them in Windows Security.",
        )
    if fix_id == "wifi.manual_connect":
        connected = {i.network_name for i in ctx.active_interfaces()}
        names = [n for n in params.get("profiles", []) if n in connected]
        if names:
            return Impact(
                Level.MAY_AFFECT,
                "You're connected to this network now; you'll stay connected but must pick it by hand next time.",
                names,
            )
        return Impact(
            Level.NONE_FOUND, "You're not connected to these networks now; the saved networks stay."
        )
    if fix_id in ("accounts.uac_prompt", "system.autorun_off", "malware.update_signatures"):
        return Impact(
            Level.NONE_FOUND, "Nothing stops working; Windows just behaves as it does by default."
        )
    return Impact(Level.UNKNOWN, "SimplySec has no specific check for what this affects.")
