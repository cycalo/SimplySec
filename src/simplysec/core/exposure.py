"""Who can reach a listening port? A pure model of Windows Firewall inbound filtering.

For each listener and each network interface it can be reached through, we work out the set
of remote addresses that the firewall lets in:

* firewall off for the interface's profile -> reachable by anyone;
* "block all incoming connections" on -> blocked;
* otherwise: (addresses allowed by matching allow rules, or everything when the default
  inbound action is Allow) minus (addresses covered by matching block rules).

Rules are matched on protocol, local port (including the RPC/RPC-EPMap/IPHTTPS/Teredo
keywords), program path, service, interface, local address, profile, and the user /
AppContainer conditions. When a condition cannot be decided (for example the process token
could not be read), the rule is treated as "maybe": we compute the answer with and without
it, and report Uncertain if they differ. We never claim "blocked" on a guess.

No OS access happens here: everything comes in as plain data from ``models``.
"""

from __future__ import annotations

import ntpath
import os
import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field

from .addrset import AddrSet, parse_literal
from .models import (
    Exposure,
    FirewallRule,
    FirewallState,
    InterfaceExposure,
    InterfaceKind,
    Listener,
    NetInterface,
    Profile,
    Scope,
    Verdict,
)
from .sddl import UserCondition, parse_user_condition

Tri = bool | None  # True: matches, False: does not, None: cannot tell

DYNAMIC_RPC_START = 49152


def tri_and(values: Iterable[Tri]) -> Tri:
    result: Tri = True
    for v in values:
        if v is False:
            return False
        if v is None:
            result = None
    return result


# --------------------------------------------------------------------------- paths


def expand_env(path: str, env: Mapping[str, str]) -> str:
    def repl(m: re.Match[str]) -> str:
        return env.get(m.group(1).upper(), m.group(0))

    return re.sub(r"%([^%]+)%", repl, path)


def normalize_app_path(path: str, env: Mapping[str, str] | None = None) -> str:
    """Comparable form of a program path: env vars expanded, case folded, normalised."""
    if env is None:
        env = {k.upper(): v for k, v in os.environ.items()}
    p = path.strip().strip('"')
    if not p:
        return ""
    if p.lower() == "system":
        return "system"
    p = expand_env(p, env).replace("/", "\\")
    if p.startswith("\\??\\"):
        p = p[4:]
    return ntpath.normpath(p).lower()


# --------------------------------------------------------------------------- context


@dataclass
class EvalContext:
    interfaces: list[NetInterface]
    env: Mapping[str, str] = field(
        default_factory=lambda: {k.upper(): v for k, v in os.environ.items()}
    )
    local_subnets: dict[int, AddrSet] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.local_subnets:
            subnets = {4: AddrSet.empty(4), 6: AddrSet.empty(6)}
            for iface in self.interfaces:
                if not iface.up:
                    continue
                for ipi in iface.ip_interfaces():
                    subnets[ipi.version] = subnets[ipi.version].union(
                        AddrSet.from_network(ipi.network)
                    )
            for fam in (4, 6):
                subnets[fam] = subnets[fam].subtract(AddrSet.loopback(fam))
            self.local_subnets = subnets


# --------------------------------------------------------------------------- compiled rules


@dataclass
class _PortSpec:
    any: bool = False
    ranges: list[tuple[int, int]] = field(default_factory=list)
    keywords: list[str] = field(default_factory=list)


def parse_ports(spec: str) -> _PortSpec:
    out = _PortSpec()
    text = (spec or "").strip()
    if text in ("", "*"):
        out.any = True
        return out
    for token in (t.strip() for t in text.split(",")):
        if not token:
            continue
        if token == "*":
            out.any = True
        elif re.fullmatch(r"\d+", token):
            out.ranges.append((int(token), int(token)))
        elif re.fullmatch(r"\d+-\d+", token):
            a, b = token.split("-")
            out.ranges.append((int(a), int(b)))
        else:
            out.keywords.append(token.lower())
    return out


@dataclass
class CompiledRule:
    rule: FirewallRule
    app: str
    ports: _PortSpec
    user: UserCondition | None
    profile_mask: int

    @property
    def name(self) -> str:
        return self.rule.name


def compile_rules(rules: Iterable[FirewallRule], env: Mapping[str, str]) -> list[CompiledRule]:
    compiled = []
    for r in rules:
        if r.direction != "in" or not r.enabled:
            continue
        compiled.append(
            CompiledRule(
                rule=r,
                app=normalize_app_path(r.application, env),
                ports=parse_ports(r.local_ports),
                user=parse_user_condition(r.local_user_authorized)
                if r.local_user_authorized
                else None,
                profile_mask=r.profile_mask,
            )
        )
    return compiled


# --------------------------------------------------------------------------- matching


def _protocol(rule: FirewallRule, lst: Listener) -> Tri:
    if rule.protocol == 256:
        return True
    return (rule.protocol == 6 and lst.protocol == "tcp") or (
        rule.protocol == 17 and lst.protocol == "udp"
    )


def _keyword_port(kw: str, lst: Listener) -> Tri:
    tcp, udp, port = lst.protocol == "tcp", lst.protocol == "udp", lst.port
    if kw == "rpc":
        if not tcp or port == 135:
            return False
        return True if port >= DYNAMIC_RPC_START else None
    if kw == "rpc-epmap":
        return tcp and port == 135
    if kw == "iphttps":
        return tcp and port == 443
    if kw in ("teredo", "ply2disc"):
        return None if udp else False
    if kw == "mdns":
        return udp and port == 5353
    return None  # unknown keyword: cannot tell


def _local_port(cr: CompiledRule, lst: Listener) -> Tri:
    spec = cr.ports
    if spec.any:
        return True
    if any(lo <= lst.port <= hi for lo, hi in spec.ranges):
        return True
    results = [_keyword_port(k, lst) for k in spec.keywords]
    if any(r is True for r in results):
        return True
    return None if any(r is None for r in results) else False


def _application(cr: CompiledRule, lst: Listener, env: Mapping[str, str]) -> Tri:
    if not cr.app:
        return True
    if cr.app == "system":
        return lst.pid == 4
    if lst.pid == 4:
        return False
    if not lst.exe:
        return None
    return normalize_app_path(lst.exe, env) == cr.app


def _service(rule: FirewallRule, lst: Listener) -> Tri:
    svc = (rule.service or "").strip()
    if not svc:
        return True
    if lst.services is None:
        return None
    if svc == "*":
        return bool(lst.services)
    return svc.lower() in {s.lower() for s in lst.services}


def _interface(rule: FirewallRule, iface: NetInterface) -> Tri:
    if rule.interfaces:
        names = {n.lower() for n in rule.interfaces}
        if iface.alias.lower() in names or iface.description.lower() in names:
            pass
        else:
            return False
    types = {t.strip().lower() for t in (rule.interface_types or "All").split(",")}
    if "all" in types or not types - {""}:
        return True
    kind_to_type = {
        InterfaceKind.ETHERNET: "lan",
        InterfaceKind.VIRTUAL: "lan",
        InterfaceKind.WIFI: "wireless",
    }
    wanted = kind_to_type.get(iface.kind)
    if wanted is None:  # VPN / other: Windows' own classification is not visible to us
        return None
    return wanted in types


def _address_context(iface: NetInterface, family: int, ctx: EvalContext) -> dict[str, AddrSet]:
    def from_ips(ips: list[str]) -> AddrSet:
        s = AddrSet.empty(family)
        for ip in ips:
            lit = parse_literal(ip)
            if lit is not None and lit.family == family:
                s = s.union(lit)
        return s

    return {
        "localsubnet": ctx.local_subnets.get(family, AddrSet.empty(family)),
        "dns": from_ips(iface.dns_servers),
        "dhcp": from_ips(iface.dhcp_servers),
        "defaultgateway": from_ips(iface.gateways),
    }


def address_set(spec: str, family: int, keywords: Mapping[str, AddrSet]) -> tuple[AddrSet, bool]:
    """Parse a firewall address list. Returns (resolved set, fully_resolved)."""
    text = (spec or "").strip()
    if text in ("", "*"):
        return AddrSet.everything(family), True
    result = AddrSet.empty(family)
    resolved = True
    for token in (t.strip() for t in text.split(",")):
        if not token:
            continue
        if token == "*":
            return AddrSet.everything(family), True
        lit = parse_literal(token)
        if lit is not None:
            if lit.family == family:
                result = result.union(lit)
            continue
        kw = keywords.get(token.lower())
        if kw is not None:
            result = result.union(kw)
        else:
            resolved = False  # Intranet, Internet, WINS, ...: not modelled
    return result, resolved


def _local_address(rule: FirewallRule, lst: Listener, iface: NetInterface, ctx: EvalContext) -> Tri:
    spec = (rule.local_addresses or "").strip()
    if spec in ("", "*"):
        return True
    fam = lst.family
    allowed, fully = address_set(spec, fam, _address_context(iface, fam, ctx))
    if lst.is_wildcard:
        local_ips = [str(i.ip) for i in iface.ip_interfaces() if i.version == fam]
    else:
        local_ips = [lst.address]
    if any(allowed.contains_ip(ip) for ip in local_ips):
        return True
    return False if fully else None


def _users(cr: CompiledRule, lst: Listener) -> Tri:
    rule = cr.rule
    results: list[Tri] = []
    if cr.user is not None:
        results.append(cr.user.decide(lst.user_sid))
    if rule.local_user_owner:
        results.append(
            None if lst.user_sid is None else lst.user_sid.upper() == rule.local_user_owner.upper()
        )
    if rule.local_app_package_id:
        pkg = rule.local_app_package_id.upper()
        if lst.package_sid is None:
            results.append(None)
        elif not lst.package_sid:
            results.append(False)
        else:
            results.append(pkg == "S-1-15-2-1" or lst.package_sid.upper() == pkg)
    elif rule.local_user_owner and not rule.application:
        # Store-app (AppContainer) capability rules carry an owner, and Windows hides their
        # package from non-admin readers. They only ever apply to that app's sandbox, so
        # they cannot match a normal (non-AppContainer) program.
        if lst.package_sid is None or lst.package_sid:
            results.append(None)
        else:
            results.append(False)
    return tri_and(results)


def rule_matches(cr: CompiledRule, lst: Listener, iface: NetInterface, ctx: EvalContext) -> Tri:
    rule = cr.rule
    if rule.trust_tuples:
        # Applies only to Wi-Fi Direct / proximity / UPnP-mapped traffic, never to ordinary
        # connections from the network.
        return False
    results: list[Tri] = []
    # Cheap, decisive checks first; stop at the first definite "no".
    for fn in (
        lambda: _protocol(rule, lst),
        lambda: _local_port(cr, lst),
        lambda: _application(cr, lst, ctx.env),
        lambda: _service(rule, lst),
        lambda: _interface(rule, iface),
        lambda: _local_address(rule, lst, iface, ctx),
        lambda: _users(cr, lst),
    ):
        r = fn()
        if r is False:
            return False
        results.append(r)
    return tri_and(results)


UNCERTAIN_WHY = {
    "port": "a port that Windows assigns at runtime (keyword {kw})",
    "program": "the program's path, which could not be read",
    "service": "the services this process hosts, which could not be read",
    "interface": "the adapter type, which Windows does not expose for this adapter",
    "address": "an address keyword SimplySec does not model",
    "user": "which user or Store app runs this program, which could not be read",
}
NEEDS_ADMIN_WHY = {"program", "service", "user"}


def why_uncertain(cr: CompiledRule, lst: Listener, iface: NetInterface, ctx: EvalContext) -> str:
    """Which condition of a 'maybe' rule could not be decided."""
    checks = (
        ("port", lambda: _local_port(cr, lst)),
        ("program", lambda: _application(cr, lst, ctx.env)),
        ("service", lambda: _service(cr.rule, lst)),
        ("interface", lambda: _interface(cr.rule, iface)),
        ("address", lambda: _local_address(cr.rule, lst, iface, ctx)),
        ("user", lambda: _users(cr, lst)),
    )
    for code, fn in checks:
        if fn() is None:
            return code
    return "address"


def requires_authentication(rule: FirewallRule) -> bool:
    return bool(rule.secure_flags or rule.remote_user_authorized or rule.remote_machine_authorized)


# --------------------------------------------------------------------------- evaluation


def _quote_names(names: list[str], limit: int = 3) -> str:
    uniq: list[str] = []
    for n in names:
        if n not in uniq:
            uniq.append(n)
    shown = ", ".join(f"'{n}'" for n in uniq[:limit])
    if len(uniq) > limit:
        shown += f" and {len(uniq) - limit} more"
    return shown


def _where(iface: NetInterface) -> str:
    if iface.kind == InterfaceKind.VPN:
        return f"devices on your {iface.alias} network"
    if iface.kind == InterfaceKind.VIRTUAL:
        return f"virtual machines on this PC ({iface.alias})"
    prof = iface.effective_profile.label
    assumed = " (assumed: Windows has no profile for it)" if iface.profile is None else ""
    return f"devices on the {iface.alias} network ({prof}{assumed})"


def classify(eff: AddrSet, family: int, ctx: EvalContext) -> tuple[Verdict, Scope]:
    if eff.is_empty():
        return Verdict.BLOCKED, Scope.NONE
    local = ctx.local_subnets.get(family, AddrSet.empty(family))
    if eff.issubset(local):
        return Verdict.REACHABLE, Scope.LOCAL_SUBNET
    space = AddrSet.everything(family).subtract(AddrSet.loopback(family))
    if space.subtract(local).issubset(eff):
        return Verdict.REACHABLE, Scope.ANYONE
    return Verdict.REACHABLE, Scope.SPECIFIC


def evaluate_on_interface(
    lst: Listener,
    iface: NetInterface,
    fw: FirewallState,
    rules: list[CompiledRule],
    ctx: EvalContext,
) -> InterfaceExposure:
    prof = iface.effective_profile
    base = InterfaceExposure(
        interface=iface.alias,
        interface_kind=iface.kind,
        profile=prof,
        profile_assumed=iface.profile is None,
        verdict=Verdict.UNCERTAIN,
        scope=Scope.NONE,
    )
    state = fw.profiles.get(prof)
    if state is None:
        base.reason = f"The firewall settings for {prof.label} networks could not be read."
        return base
    if not state.enabled:
        base.verdict, base.scope = Verdict.REACHABLE, Scope.ANYONE
        base.remote = ["any address"]
        base.reason = (
            f"Anyone who can reach {_where(iface)} can connect: the firewall is turned off "
            f"for {prof.label} networks."
        )
        return base
    if state.block_all_inbound:
        base.verdict = Verdict.BLOCKED
        base.reason = f"Blocked on {iface.alias}: the firewall blocks all incoming connections on {prof.label} networks."
        return base

    fam = lst.family
    kw = _address_context(iface, fam, ctx)
    empty = AddrSet.empty(fam)
    everything = AddrSet.everything(fam)
    sure_allow, maybe_allow, sure_block, maybe_block = empty, empty, empty, empty
    allow_names: list[str] = []
    block_names: list[str] = []
    maybe_names: list[str] = []
    maybe_why: dict[str, str] = {}
    auth_only: list[str] = []
    edge = False

    for cr in rules:
        if not cr.profile_mask & prof:
            continue
        m = rule_matches(cr, lst, iface, ctx)
        if m is False:
            continue
        rule = cr.rule
        if m is None:
            code = why_uncertain(cr, lst, iface, ctx)
            keywords = ",".join(cr.ports.keywords) or "?"
            maybe_why.setdefault(code, UNCERTAIN_WHY[code].format(kw=keywords))
        remote, fully = address_set(rule.remote_addresses, fam, kw)
        if rule.action == "allow":
            if requires_authentication(rule):
                auth_only.append(rule.name)
                continue
            if m is True:
                sure_allow = sure_allow.union(remote)
                allow_names.append(rule.name)
                if rule.edge_traversal or rule.edge_traversal_options == 1:
                    edge = True
                if not fully:
                    maybe_allow = maybe_allow.union(everything)
                    maybe_names.append(rule.name)
                    maybe_why.setdefault("address", UNCERTAIN_WHY["address"])
            else:
                maybe_allow = maybe_allow.union(remote if fully else everything)
                maybe_names.append(rule.name)
        else:
            partial = (rule.remote_ports or "*").strip() not in ("", "*")
            if m is True and not partial:
                sure_block = sure_block.union(remote)
                block_names.append(rule.name)
                if not fully:
                    maybe_block = maybe_block.union(everything)
                    maybe_names.append(rule.name)
                    maybe_why.setdefault("address", UNCERTAIN_WHY["address"])
            else:
                maybe_block = maybe_block.union(remote if fully else everything)
                maybe_names.append(rule.name)

    space = everything.subtract(AddrSet.loopback(fam))

    def effective(allow: AddrSet, block: AddrSet) -> AddrSet:
        start = space if not state.default_inbound_block else allow.intersect(space)
        return start.subtract(block)

    eff_min = effective(sure_allow, sure_block.union(maybe_block))
    eff_max = effective(sure_allow.union(maybe_allow), sure_block)
    v_min, s_min = classify(eff_min, fam, ctx)
    v_max, s_max = classify(eff_max, fam, ctx)

    base.allow_rules = list(dict.fromkeys(allow_names))
    base.block_rules = list(dict.fromkeys(block_names))
    base.uncertain_rules = list(dict.fromkeys(maybe_names))
    base.edge_traversal = edge
    where = _where(iface)

    if v_min == Verdict.REACHABLE:
        base.verdict, base.scope = Verdict.REACHABLE, s_max
        base.remote = eff_max.describe()
        if not state.default_inbound_block and not allow_names:
            because = f"the firewall's default for {prof.label} networks is to allow connections"
        else:
            because = f"the firewall rule {_quote_names(allow_names)} allows it"
        who = {
            Scope.ANYONE: f"Anyone who can reach {where}",
            Scope.LOCAL_SUBNET: f"Only {where} on the same local subnet",
            Scope.SPECIFIC: f"Some addresses ({', '.join(base.remote)}) via {iface.alias}",
        }[s_max]
        base.reason = f"{who} can connect: {because}."
        if s_min != s_max:
            base.reason += f" Rules {_quote_names(maybe_names)} may narrow this further."
    elif v_max == Verdict.BLOCKED:
        base.verdict = Verdict.BLOCKED
        if block_names:
            base.reason = f"Blocked on {iface.alias}: the firewall rule {_quote_names(block_names)} blocks it."
        elif state.default_inbound_block:
            base.reason = (
                f"Blocked on {iface.alias}: no firewall rule allows it on {prof.label} networks, "
                "and the default is to block."
            )
        else:
            base.reason = f"Blocked on {iface.alias} by the firewall."
        if auth_only:
            base.reason += (
                f" (Rule {_quote_names(auth_only)} only allows IPsec-authenticated computers.)"
            )
    else:
        base.verdict = Verdict.UNCERTAIN
        base.scope = s_max
        base.remote = eff_max.describe()
        why = "; ".join(maybe_why.values()) or "conditions SimplySec could not evaluate"
        hint = (
            " Running SimplySec as administrator usually resolves this."
            if set(maybe_why) & NEEDS_ADMIN_WHY
            else ""
        )
        base.reason = (
            f"Not sure for {iface.alias}: the firewall rule {_quote_names(maybe_names)} depends on {why}. "
            f"SimplySec does not guess, so this is not reported as protected.{hint}"
        )
    return base


def candidate_interfaces(lst: Listener, interfaces: list[NetInterface]) -> list[NetInterface]:
    if lst.is_loopback:
        return []
    fam = lst.family
    if lst.is_wildcard:
        return [
            i
            for i in interfaces
            if i.up
            and i.kind != InterfaceKind.LOOPBACK
            and any(x.version == fam for x in i.ip_interfaces())
        ]
    return [i for i in interfaces if i.has_ip(lst.address) and i.kind != InterfaceKind.LOOPBACK]


def evaluate(
    lst: Listener,
    fw: FirewallState,
    ctx: EvalContext,
    rules: list[CompiledRule] | None = None,
) -> Exposure:
    """Evaluate one listener. ``rules`` can be pre-compiled for speed."""
    if rules is None:
        rules = compile_rules(fw.rules, ctx.env)
    if lst.is_loopback:
        return Exposure(
            listener=lst,
            verdict=Verdict.LOCAL_ONLY,
            reason=f"Only programs on this PC can connect: it listens on {lst.address} (loopback).",
        )
    cands = candidate_interfaces(lst, ctx.interfaces)
    if not cands:
        if lst.is_wildcard:
            return Exposure(
                listener=lst,
                verdict=Verdict.LOCAL_ONLY,
                reason="No active network connection can reach it right now.",
            )
        return Exposure(
            listener=lst,
            verdict=Verdict.UNCERTAIN,
            reason=f"It listens on {lst.address}, which SimplySec could not match to a network adapter.",
        )
    per = [evaluate_on_interface(lst, i, fw, rules, ctx) for i in cands]
    if lst.package_sid:
        # Store-app sandbox (AppContainer) isolation adds filters we do not model.
        for ie in per:
            if ie.verdict == Verdict.REACHABLE:
                ie.verdict = Verdict.UNCERTAIN
                ie.reason += " This is a sandboxed Store app; Windows may still isolate it."
    reachable = [p for p in per if p.verdict == Verdict.REACHABLE]
    if reachable:
        scope = max((p.scope for p in reachable), key=lambda s: s.rank)
        return Exposure(lst, Verdict.REACHABLE, scope, per, " ".join(p.reason for p in reachable))
    uncertain = [p for p in per if p.verdict == Verdict.UNCERTAIN]
    if uncertain:
        return Exposure(
            lst, Verdict.UNCERTAIN, Scope.NONE, per, " ".join(p.reason for p in uncertain)
        )
    return Exposure(lst, Verdict.BLOCKED, Scope.NONE, per, " ".join(p.reason for p in per))


def evaluate_all(listeners: list[Listener], fw: FirewallState, ctx: EvalContext) -> list[Exposure]:
    rules = compile_rules(fw.rules, ctx.env)
    return [evaluate(lst, fw, ctx, rules) for lst in listeners]


def profile_reachable(exposure: Exposure, profile: Profile) -> bool:
    return any(
        ie.verdict == Verdict.REACHABLE and ie.profile == profile for ie in exposure.per_interface
    )
