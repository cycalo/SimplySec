"""Exposure findings: what other devices can actually reach, by program or port.

Findings about known apps are about *who can reach them*, never about the app being bad.
When the user deliberately configured the exposure (for example ``OLLAMA_HOST=0.0.0.0``)
the finding says so and starts at Low or Info. Fixes are offered in steps:
"Only this PC", "Home network or VPN only", or "Keep: I need this" (handled by the UI).
"""

from __future__ import annotations

import datetime as dt
import ipaddress
import ntpath
import secrets
from dataclasses import dataclass, field
from typing import Any

from ..exposure import address_set, normalize_app_path, requires_authentication
from ..knowledge import PortInfo, ProgramInfo, RangeInfo
from ..models import (
    ActionSpec,
    FindingStatus,
    FirewallRule,
    Profile,
    Severity,
    Verdict,
)
from ..scoring import (
    WIDTH_LABELS,
    WIDTH_PUBLIC_ANY,
    WIDTH_PUBLIC_SUBNET,
    exposure_severity,
    exposure_width,
)
from .base import Allow, Check, FixDef, PortGroup, ScanContext, Warning_, finding

CHECK = "exposure"
AREA = "Exposure"
GROUP = "SimplySec"


# --------------------------------------------------------------------------- identity


@dataclass
class Identity:
    label: str
    explain: str
    base: Severity
    program: ProgramInfo | None
    port: PortInfo | RangeInfo | None
    third_party: bool
    subject_kind: str  # "program" | "port"
    subject: str  # exe path or "tcp/445"


def is_user_writable(path: str, env: dict[str, str]) -> bool:
    p = (path or "").lower()
    if not p:
        return False
    roots = [r"c:\users" + "\\"]
    for var in ("USERPROFILE", "LOCALAPPDATA", "APPDATA", "TEMP", "TMP", "PROGRAMDATA"):
        v = env.get(var)
        if v:
            roots.append(v.lower().rstrip("\\") + "\\")
    return any(p.startswith(r) for r in roots)


def user_configured(program: ProgramInfo | None, env: dict[str, str]) -> bool:
    """True when the user set an env var that binds the program to the network on purpose."""
    if program is None or not program.intent_env:
        return False
    value = env.get(program.intent_env.upper(), "").strip()
    if not value:
        return False
    host = value.split("://")[-1]
    if host.startswith("["):
        host = host[1:].split("]")[0]
    elif host.count(":") == 1:
        host = host.split(":")[0]
    if host in ("", "*", "0.0.0.0", "::"):
        return True
    if host.lower() == "localhost":
        return False
    try:
        return not ipaddress.ip_address(host).is_loopback
    except ValueError:
        return True  # a host name: reachable by others


def identify(g: PortGroup, ctx: ScanContext) -> Identity:
    kb = ctx.kb
    program = kb.program(g.exe or g.process) if g.pid != 4 else None
    services = [s for s in (kb.service(n) for n in (g.services or [])) if s is not None]
    exact = kb.port(g.protocol, g.port)
    port_or_range = exact or kb.port_or_range(g.protocol, g.port)
    third_party = g.pid != 4 and bool(g.exe) and not ctx.is_windows_binary(g.exe)

    risks = [r.risk for r in ([exact] if exact else [])]
    if exact is None or not exact.discovery:
        if program:
            risks.append(program.risk)
        risks.extend(s.risk for s in services)
    if risks:
        base = max(risks)
    elif port_or_range is not None:
        base = port_or_range.risk
        if third_party:
            base = max(base, Severity.MEDIUM)
    else:
        base = Severity.MEDIUM if third_party else Severity.LOW

    if g.pid == 4:
        label = f"Windows {exact.name}" if exact else f"A Windows kernel listener on port {g.port}"
        explain = exact.explain if exact else "Windows itself (the System process) listens here."
    elif program:
        label = program.description[0].upper() + program.description[1:]
        explain = program.explain
    elif services:
        label = f"Windows service: {services[0].display}"
        explain = services[0].description + (f" {exact.explain}" if exact else "")
    elif exact:
        label = f"{g.process or 'A program'} ({exact.name})"
        explain = exact.explain
    else:
        label = g.process or f"An unknown program (PID {g.pid})"
        explain = (
            port_or_range.summary if port_or_range else "SimplySec does not know this program."
        )

    if program or third_party:
        return Identity(
            label, explain, base, program, port_or_range, third_party, "program", g.exe or g.process
        )
    return Identity(
        label, explain, base, program, port_or_range, third_party, "port", f"{g.protocol}/{g.port}"
    )


# --------------------------------------------------------------------------- fixes


def _rule_name(fix: str) -> str:
    return f"SimplySec:{fix}:{secrets.token_hex(4)}"


def _description(why: str) -> str:
    today = dt.date.today().isoformat()
    return f"Added by SimplySec on {today}: {why}. Undo it in SimplySec > Changes."


def _block_rule(fix: str, why: str, **kw: Any) -> dict[str, Any]:
    rule = FirewallRule(
        name=_rule_name(fix),
        action="block",
        direction="in",
        enabled=True,
        grouping=GROUP,
        description=_description(why),
        **kw,
    )
    return rule.to_dict()


def build_block_program(params: dict[str, Any], public_only: bool) -> list[ActionSpec]:
    exe, label = params["exe"], params.get("label", ntpath.basename(params["exe"]))
    where = "Public networks" if public_only else "every network"
    fix = "block_program_public" if public_only else "block_program"
    rule = _block_rule(
        fix,
        f"stop other devices on {where} connecting to {label}",
        application=exe,
        protocol=256,
        profiles=int(Profile.PUBLIC) if public_only else 0x7FFFFFFF,
    )
    return [
        ActionSpec(
            "firewall.add_rule",
            {"rule": rule},
            f"Add firewall rule '{rule['name']}' that blocks incoming connections to {label} "
            f"({exe}) on {where}.",
        )
    ]


def build_block_port(params: dict[str, Any], public_only: bool) -> list[ActionSpec]:
    proto, port = params["protocol"], int(params["port"])
    label = params.get("label", f"port {port}")
    where = "Public networks" if public_only else "every network"
    fix = "block_port_public" if public_only else "block_port"
    rule = _block_rule(
        fix,
        f"stop other devices on {where} connecting to {label} ({proto.upper()} {port})",
        protocol=6 if proto == "tcp" else 17,
        local_ports=str(port),
        profiles=int(Profile.PUBLIC) if public_only else 0x7FFFFFFF,
    )
    return [
        ActionSpec(
            "firewall.add_rule",
            {"rule": rule},
            f"Add firewall rule '{rule['name']}' that blocks incoming {proto.upper()} port {port} "
            f"({label}) on {where}.",
        )
    ]


def public_network_warning(ctx: ScanContext, params: dict[str, Any]) -> list[Warning_]:
    out = []
    for iface in ctx.current_public_networks():
        name = iface.network_name or iface.alias
        out.append(
            Warning_(
                text=(
                    f"Your {iface.alias} connection ('{name}') is set to Public, so this also blocks "
                    "devices on that network, including your own phone or other PCs. If this is your "
                    "home network, mark it Private first (this can be undone too)."
                ),
                offer_fix="network.mark_private",
                offer_params={"index": iface.index, "alias": iface.alias, "name": name},
                offer_label=f"Mark '{name}' as a Private (home) network first",
            )
        )
    return out


FIX_BLOCK_PROGRAM = FixDef(
    id="exposure.block_program",
    label="Only this PC",
    description="Adds a firewall rule that blocks other devices from connecting to this program on every network. Programs on this PC can still use it.",
    might_break="Phones, other PCs and VPN devices can no longer connect to this program.",
    build=lambda p: build_block_program(p, public_only=False),
    disruptive=True,
)
FIX_BLOCK_PROGRAM_PUBLIC = FixDef(
    id="exposure.block_program_public",
    label="Home network or VPN only",
    description="Adds a firewall rule that blocks this program on Public networks. Private (home) networks and your VPN keep working. The original allow rule is not touched.",
    might_break="Devices on networks marked Public can no longer connect to this program.",
    build=lambda p: build_block_program(p, public_only=True),
    disruptive=True,
    warnings=public_network_warning,
)
FIX_BLOCK_PORT = FixDef(
    id="exposure.block_port",
    label="Block this port on all networks",
    description="Adds a firewall rule that blocks incoming connections to this port on every network.",
    might_break="Any device that uses this service on this PC (for example file sharing or casting) stops working.",
    build=lambda p: build_block_port(p, public_only=False),
    disruptive=True,
)
FIX_BLOCK_PORT_PUBLIC = FixDef(
    id="exposure.block_port_public",
    label="Block this port on Public networks",
    description="Adds a firewall rule that blocks incoming connections to this port on Public networks only.",
    might_break="Devices on networks marked Public can no longer use this service on this PC.",
    build=lambda p: build_block_port(p, public_only=True),
    disruptive=True,
    warnings=public_network_warning,
)

FIXES = [FIX_BLOCK_PROGRAM, FIX_BLOCK_PROGRAM_PUBLIC, FIX_BLOCK_PORT, FIX_BLOCK_PORT_PUBLIC]


def _allow_add_rule(params: dict[str, Any]) -> bool:
    rule = params.get("rule") or {}
    return (
        str(rule.get("name", "")).startswith("SimplySec:")
        and rule.get("grouping") == GROUP
        and rule.get("action") == "block"
        and rule.get("direction") == "in"
        and rule.get("enabled") is True
        and rule.get("remote_addresses", "*") in ("", "*")
        and not rule.get("local_user_authorized")
        and not rule.get("local_app_package_id")
    )


ALLOWS = [Allow("firewall.add_rule", _allow_add_rule)]


# --------------------------------------------------------------------------- detection


@dataclass
class _Subject:
    ident: Identity
    groups: list[PortGroup] = field(default_factory=list)
    rules: list[FirewallRule] = field(default_factory=list)


def _subject_id(ident: Identity) -> str:
    if ident.subject_kind == "program":
        return f"exposure.program:{ntpath.basename(ident.subject).lower()}"
    return f"exposure.port:{ident.subject}"


def _public_allow_rules(ctx: ScanContext) -> dict[str, list[FirewallRule]]:
    """Enabled inbound allow rules for non-Windows programs that include the Public profile."""
    env = ctx.env
    out: dict[str, list[FirewallRule]] = {}
    for rule in ctx.firewall.rules:
        if rule.direction != "in" or not rule.enabled or rule.action != "allow":
            continue
        if not rule.profile_mask & Profile.PUBLIC or rule.grouping == GROUP:
            continue
        app = normalize_app_path(rule.application, env)
        if not app or app == "system" or ctx.is_windows_binary(app):
            continue
        if requires_authentication(rule):
            continue
        remote, _ = address_set(rule.remote_addresses, 4, {})
        if remote.is_empty() and (rule.remote_addresses or "*").strip() not in ("", "*"):
            # only keywords such as LocalSubnet: not "anyone"
            continue
        out.setdefault(app, []).append(rule)
    return out


def _details(subj: _Subject, ctx: ScanContext) -> list[tuple[str, str]]:
    details: list[tuple[str, str]] = []
    if subj.groups:
        ports = ", ".join(sorted({f"{g.protocol.upper()} {g.port}" for g in subj.groups}))
        details.append(("Ports", ports))
        g0 = subj.groups[0]
        details.append(("Program", g0.exe or g0.process or "System (Windows kernel)"))
        details.append(("Process ID", ", ".join(sorted({str(g.pid) for g in subj.groups}))))
        services = sorted({s for g in subj.groups for s in (g.services or [])})
        if services:
            details.append(("Services", ", ".join(services)))
        sig = ctx.signature(g0.exe)
        if sig is not None and g0.exe:
            details.append(
                ("Signature", f"{sig.status}{' – ' + sig.publisher if sig.publisher else ''}")
            )
        addrs = sorted({a for g in subj.groups for a in g.addresses})
        details.append(("Listening on", ", ".join(addrs)))
        for g in subj.groups:
            for e in g.exposures:
                for ie in e.per_interface:
                    details.append(
                        (
                            f"{g.protocol.upper()} {g.port} via {ie.interface} ({ie.profile.label})",
                            ie.reason,
                        )
                    )
    if subj.rules:
        names = sorted({r.name for r in subj.rules})
        details.append(
            ("Firewall rules allowing it on Public networks", ", ".join(f"'{n}'" for n in names))
        )
    rule_names = sorted(
        {
            n
            for g in subj.groups
            for e in g.exposures
            for ie in e.per_interface
            for n in ie.allow_rules + ie.block_rules
        }
    )
    if rule_names:
        details.append(("Firewall rules involved", ", ".join(f"'{n}'" for n in rule_names)))
    # De-duplicate identical rows while keeping order.
    return list(dict.fromkeys(details))


def exposure_severity_for_group(g: PortGroup, ctx: ScanContext) -> tuple[Severity, str]:
    """Risk of one reachable port group (used by the Open ports table) and its finding id."""
    ident = identify(g, ctx)
    width = exposure_width(g.exposures)
    sig = ctx.signature(g.exe)
    unsigned = ident.third_party and ident.program is None and sig is not None and not sig.signed
    writable = ident.third_party and ident.program is None and is_user_writable(g.exe, ctx.env)
    sev = exposure_severity(
        ident.base,
        width,
        unsigned=unsigned,
        user_writable=writable,
        user_configured=user_configured(ident.program, ctx.env),
    )
    return sev, _subject_id(ident)


def run(ctx: ScanContext) -> list:
    subjects: dict[str, _Subject] = {}
    protected: list[PortGroup] = []
    uncertain: list[PortGroup] = []

    for g in ctx.groups:
        verdicts = {e.verdict for e in g.exposures}
        if Verdict.REACHABLE in verdicts:
            ident = identify(g, ctx)
            sid = _subject_id(ident)
            subjects.setdefault(sid, _Subject(ident)).groups.append(g)
        elif Verdict.UNCERTAIN in verdicts:
            uncertain.append(g)
        elif Verdict.BLOCKED in verdicts:
            protected.append(g)

    # Rules that allow non-Windows programs on Public networks (even when not running now).
    # Known programs get their own finding; unknown ones are grouped into one.
    unknown_rules: dict[str, list[FirewallRule]] = {}
    for app, rules in _public_allow_rules(ctx).items():
        base = ntpath.basename(app)
        sid = f"exposure.program:{base}"
        if sid in subjects:
            subjects[sid].rules.extend(rules)
            continue
        program = ctx.kb.program(base)
        if program is None:
            unknown_rules[app] = rules
            continue
        ident = Identity(
            label=program.description[0].upper() + program.description[1:],
            explain=program.explain,
            base=program.risk,
            program=program,
            port=None,
            third_party=True,
            subject_kind="program",
            subject=rules[0].application,
        )
        subjects[f"exposure.rule:{base}"] = _Subject(ident, rules=list(rules))

    findings = []
    for sid, subj in subjects.items():
        ident = subj.ident
        listening = bool(subj.groups)
        exposures = [e for g in subj.groups for e in g.exposures]
        width = exposure_width(exposures) if listening else WIDTH_PUBLIC_ANY
        exe = subj.groups[0].exe if listening else normalize_app_path(ident.subject, ctx.env)
        sig = ctx.signature(exe)
        unsigned = (
            ident.third_party and ident.program is None and sig is not None and not sig.signed
        )
        writable = ident.third_party and ident.program is None and is_user_writable(exe, ctx.env)
        intent = user_configured(ident.program, ctx.env)

        if listening:
            sev = exposure_severity(
                ident.base, width, unsigned=unsigned, user_writable=writable, user_configured=intent
            )
        elif not ctx.file_exists(exe) or intent or ident.base <= Severity.LOW:
            sev = Severity.INFO
        else:
            sev = Severity.LOW

        if listening and not ident.third_party and sev < Severity.MEDIUM:
            continue  # low-risk Windows listeners: shown in the Open ports table only

        reach_text = WIDTH_LABELS[width]
        if intent:
            title = f"{ident.label} is reachable from other devices – you set this up"
        elif not listening:
            title = f"{ident.label} is allowed through the firewall on Public networks"
        elif unsigned:
            title = f"{ident.label} accepts connections and is not digitally signed"
        elif writable:
            title = f"{ident.label} accepts connections from a folder any program can change"
        else:
            title = f"{ident.label} can be reached by {reach_text}"

        what_parts = [ident.explain]
        if listening:
            reachable_reasons = [
                ie.reason
                for e in exposures
                for ie in e.per_interface
                if ie.verdict == Verdict.REACHABLE
            ]
            if reachable_reasons:
                what_parts.append(reachable_reasons[0])
        else:
            what_parts.append(
                "A firewall rule lets devices on Public networks (cafés, hotels, airports) connect to it "
                "whenever it runs. It is not listening right now."
            )
            if not ctx.file_exists(exe):
                what_parts.append(
                    "The program no longer exists at that location; the rule is a leftover."
                )
        if intent and ident.program is not None:
            what_parts.append(
                f"You set {ident.program.intent_env}={ctx.env.get(ident.program.intent_env.upper(), '')}, "
                "so this looks deliberate. Choose Keep if you need it, or limit who can reach it."
            )
        if unsigned:
            what_parts.append(
                "The program has no valid digital signature, so its publisher can't be confirmed."
            )
        if writable:
            what_parts.append("It runs from a user folder, where other programs could replace it.")

        fixes = []
        reachable_public = width >= WIDTH_PUBLIC_SUBNET
        if ident.subject_kind == "program" and exe:
            params: dict[str, Any] = {
                "exe": exe,
                "label": ident.program.name if ident.program else ntpath.basename(exe),
            }
            if reachable_public or not listening:
                fixes.append(FIX_BLOCK_PROGRAM_PUBLIC.option(params))
            fixes.append(FIX_BLOCK_PROGRAM.option(params))
        else:
            g0 = subj.groups[0]
            params = {"protocol": g0.protocol, "port": g0.port, "label": ident.label}
            if reachable_public:
                fixes.append(FIX_BLOCK_PORT_PUBLIC.option(params))
            fixes.append(FIX_BLOCK_PORT.option(params))
        if isinstance(ident.port, PortInfo):
            for fid in ident.port.fixes:
                if not fid.startswith("exposure.") and fid not in [f.fix_id for f in fixes]:
                    topic = ctx.fix_option(fid)
                    if topic is not None:
                        fixes.insert(0, topic)

        f = finding(
            id=sid,
            check=CHECK,
            area=AREA,
            title=title,
            severity=sev,
            what=" ".join(p for p in what_parts if p),
            details=_details(subj, ctx),
            fixes=[x for x in fixes if x is not None],
            learn_more=ident.port.advice if ident.port is not None else "",
        )
        f.keep_key = f"keep:{sid}"
        f.width = width
        f.user_configured = intent
        accepted = ctx.accepted.get(f.keep_key)
        if accepted is not None and accepted >= width:
            f.status = FindingStatus.ACCEPTED
        findings.append(f)

    if unknown_rules:
        findings.append(_public_rules_finding(unknown_rules, ctx))

    if uncertain:
        details = [
            (
                f"{g.protocol.upper()} {g.port} – {g.process or 'PID ' + str(g.pid)}",
                next((e.reason for e in g.exposures if e.verdict == Verdict.UNCERTAIN), ""),
            )
            for g in uncertain
        ]
        findings.append(
            finding(
                id="exposure.uncertain",
                check=CHECK,
                area=AREA,
                title=f"{len(uncertain)} listening port(s) could not be fully checked",
                severity=Severity.INFO,
                what=(
                    "Some firewall rules depend on details SimplySec could not read or evaluate (for "
                    "example which user runs a program, or ports Windows assigns at runtime). These ports "
                    "are reported as Uncertain, never as protected. Technical details say why for each."
                ),
                details=details,
            )
        )
    if protected:
        details = [
            (
                f"{g.protocol.upper()} {g.port} – {g.process or 'PID ' + str(g.pid)}",
                next((e.reason for e in g.exposures if e.verdict == Verdict.BLOCKED), ""),
            )
            for g in protected
        ]
        f = finding(
            id="exposure.protected",
            check=CHECK,
            area=AREA,
            title=f"{len(protected)} listening port(s) are protected by the firewall",
            severity=Severity.INFO,
            what=(
                "These programs listen for connections, but the firewall stops other devices from "
                "reaching them. Shown for transparency; nothing to do."
            ),
            details=details,
        )
        f.status = FindingStatus.INFO
        findings.append(f)
    return findings


def _public_rules_finding(unknown: dict[str, list[FirewallRule]], ctx: ScanContext):
    present = {app: rules for app, rules in unknown.items() if ctx.file_exists(app)}
    leftovers = sorted(set(unknown) - set(present))
    details: list[tuple[str, str]] = []
    risky = 0
    for app, rules in sorted(present.items()):
        sig = ctx.signature(app)
        notes = []
        if is_user_writable(app, ctx.env):
            notes.append("runs from a user folder")
        if sig is not None and not sig.signed:
            notes.append("not signed")
        elif sig is not None and sig.publisher:
            notes.append(f"signed by {sig.publisher}")
        if len(notes) >= 2 and "not signed" in notes:
            risky += 1
        rule_names = ", ".join(sorted({f"'{r.name}'" for r in rules}))
        details.append(
            (
                rules[0].application,
                f"rules {rule_names}" + (f" – {'; '.join(notes)}" if notes else ""),
            )
        )
    for app in leftovers:
        details.append((app, "program no longer installed (leftover rule)"))
    count = len(present)
    f = finding(
        id="exposure.public_rules",
        check=CHECK,
        area=AREA,
        title=f"{count} other program(s) are allowed through the firewall on Public networks",
        severity=(Severity.MEDIUM if risky else Severity.LOW) if count else Severity.INFO,
        what=(
            "Windows rules let these programs accept connections on Public networks (cafés, hotels, "
            "airports) whenever they run. None of them is listening right now. Usually this comes from "
            "clicking 'Allow' on a firewall prompt or from an installer. "
            + (
                f"{risky} of them run unsigned from a user folder, which deserves a closer look. "
                if risky
                else ""
            )
            + "Limiting them to home networks adds block rules for Public networks; the original rules stay."
        ),
        details=details,
        fixes=[FIX_BLOCK_PROGRAMS_PUBLIC.option({"exes": sorted(present)})] if present else [],
    )
    f.keep_key = "keep:exposure.public_rules"
    f.width = count
    accepted = ctx.accepted.get(f.keep_key)
    if accepted is not None and accepted >= count:
        f.status = FindingStatus.ACCEPTED
    return f


def _build_many_public(params: dict[str, Any]) -> list[ActionSpec]:
    specs: list[ActionSpec] = []
    for exe in params.get("exes", []):
        specs.extend(
            build_block_program({"exe": exe, "label": ntpath.basename(exe)}, public_only=True)
        )
    return specs


FIX_BLOCK_PROGRAMS_PUBLIC = FixDef(
    id="exposure.block_programs_public",
    label="Home network or VPN only (all listed)",
    description="Adds one block rule per program for Public networks. Private (home) networks and your VPN keep working; the original allow rules are not touched.",
    might_break="These programs can no longer accept connections from devices on networks marked Public.",
    build=_build_many_public,
    disruptive=True,
    warnings=public_network_warning,
)
FIXES.append(FIX_BLOCK_PROGRAMS_PUBLIC)

CHECK_DEF = Check(id=CHECK, area=AREA, run=run, fixes=FIXES, allows=ALLOWS)
