"""Scan, preview, apply, verify and undo.

``analyze`` is pure: it turns collected facts (``RawScan``) into findings, a port table and a
score. ``Engine`` adds the side effects: collecting facts, writing the journal and history,
applying primitives and undoing them.
"""

from __future__ import annotations

import datetime as dt
import getpass
import logging
import os
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .. import __version__
from . import checks as checks_pkg
from . import impact as impact_mod
from . import knowledge, scoring
from .actions import PRIMITIVES, Adapters
from .checks.base import Facts, FixDef, PortGroup, ScanContext, SignatureInfo, Warning_
from .checks.exposure import exposure_severity_for_group
from .exposure import EvalContext, evaluate_all
from .impact import Impact
from .journal import APPLIED, REVERT_FAILED, ChangeRecord, Journal
from .models import (
    ActionSpec,
    Exposure,
    Finding,
    FindingStatus,
    FirewallProfileState,
    FirewallState,
    InterfaceKind,
    Listener,
    NetInterface,
    Scope,
    Severity,
    Verdict,
)
from .util import as_list

log = logging.getLogger(__name__)

Progress = Callable[[str], None]


class NeedsAdmin(PermissionError):
    pass


# --------------------------------------------------------------------------- raw input


@dataclass
class RawScan:
    facts: dict[str, Any]
    listeners: list[Listener]
    firewall: FirewallState
    interfaces: list[NetInterface]
    signatures: dict[str, SignatureInfo] = field(default_factory=dict)
    env: dict[str, str] = field(default_factory=dict)
    is_admin: bool = False
    windows_dir: str = r"C:\Windows"
    errors: list[str] = field(default_factory=list)
    started: str = ""
    duration: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "facts": self.facts,
            "listeners": [x.to_dict() for x in self.listeners],
            "firewall": self.firewall.to_dict(),
            "interfaces": [i.to_dict() for i in self.interfaces],
            "signatures": {
                k: {"status": v.status, "publisher": v.publisher}
                for k, v in self.signatures.items()
            },
            "env": self.env,
            "is_admin": self.is_admin,
            "windows_dir": self.windows_dir,
            "errors": self.errors,
            "started": self.started,
            "duration": self.duration,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> RawScan:
        return cls(
            facts=d.get("facts", {}),
            listeners=[Listener.from_dict(x) for x in d.get("listeners", [])],
            firewall=FirewallState.from_dict(d["firewall"]),
            interfaces=[NetInterface.from_dict(i) for i in d.get("interfaces", [])],
            signatures={
                k: SignatureInfo(v["status"], v.get("publisher", ""))
                for k, v in d.get("signatures", {}).items()
            },
            env=d.get("env", {}),
            is_admin=d.get("is_admin", False),
            windows_dir=d.get("windows_dir", r"C:\Windows"),
            errors=d.get("errors", []),
            started=d.get("started", ""),
            duration=d.get("duration", 0.0),
        )


# --------------------------------------------------------------------------- results


@dataclass
class PortRow:
    protocol: str
    port: int
    pid: int
    process: str
    exe: str
    publisher: str
    services: list[str]
    listening_on: str
    reachable_from: str
    verdict: Verdict
    scope: Scope
    risk: Severity
    reason: str
    rules: list[str]
    finding_id: str | None = None
    connected: list[str] = field(default_factory=list)  # remote IPs connected right now

    def to_dict(self) -> dict[str, Any]:
        d = dict(self.__dict__)
        d["verdict"] = self.verdict.value
        d["scope"] = self.scope.value
        d["risk"] = self.risk.name.lower()
        return d

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> PortRow:
        d = dict(d)
        d["verdict"] = Verdict(d["verdict"])
        d["scope"] = Scope(d["scope"])
        d["risk"] = Severity.parse(d["risk"])
        return cls(**d)


@dataclass
class ScanResult:
    started: str
    duration: float
    computer: str
    is_admin: bool
    version: str
    interfaces: list[NetInterface]
    firewall_profiles: list[FirewallProfileState]
    firewall_managed: bool
    exposures: list[Exposure]
    ports: list[PortRow]
    findings: list[Finding]
    score: int
    grade: str
    errors: list[str] = field(default_factory=list)
    facts: dict[str, Any] = field(default_factory=dict)
    extras: dict[str, Any] = field(default_factory=dict)  # M2: devices, router, wifi

    @property
    def open_findings(self) -> list[Finding]:
        return [
            f
            for f in self.findings
            if f.status == FindingStatus.OPEN and f.severity > Severity.INFO
        ]

    def counts(self) -> dict[str, int]:
        out = {
            s.name.lower(): 0
            for s in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW)
        }
        for f in self.open_findings:
            out[f.severity.name.lower()] += 1
        return out

    def finding(self, finding_id: str) -> Finding | None:
        return next((f for f in self.findings if f.id == finding_id), None)

    def network_status(self) -> list[str]:
        profiles = {p.profile: p for p in self.firewall_profiles}
        lines = []
        for iface in self.interfaces:
            if not iface.up or iface.kind in (InterfaceKind.LOOPBACK,) or not iface.ip_interfaces():
                continue
            if iface.kind == InterfaceKind.VIRTUAL:
                continue
            prof = iface.effective_profile
            st = profiles.get(prof)
            fw = "firewall on" if st and st.enabled else "FIREWALL OFF"
            assumed = " (assumed)" if iface.profile is None else ""
            lines.append(f"{iface.alias}: {prof.label}{assumed} network, {fw}")
        return lines

    def to_dict(self, include_facts: bool = True) -> dict[str, Any]:
        d = {
            "version": self.version,
            "started": self.started,
            "duration": round(self.duration, 2),
            "computer": self.computer,
            "is_admin": self.is_admin,
            "score": self.score,
            "grade": self.grade,
            "counts": self.counts(),
            "network": self.network_status(),
            "interfaces": [i.to_dict() for i in self.interfaces],
            "firewall": {
                "managed_by_policy": self.firewall_managed,
                "profiles": [p.to_dict() for p in self.firewall_profiles],
            },
            "findings": [f.to_dict() for f in self.findings],
            "ports": [p.to_dict() for p in self.ports],
            "exposures": [e.to_dict() for e in self.exposures],
            "errors": self.errors,
            "extras": self.extras,
        }
        if include_facts:
            d["facts"] = self.facts
        return d

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> ScanResult:
        return cls(
            started=d["started"],
            duration=d.get("duration", 0),
            computer=d.get("computer", ""),
            is_admin=d.get("is_admin", False),
            version=d.get("version", ""),
            interfaces=[NetInterface.from_dict(i) for i in d.get("interfaces", [])],
            firewall_profiles=[
                FirewallProfileState.from_dict(p) for p in d.get("firewall", {}).get("profiles", [])
            ],
            firewall_managed=d.get("firewall", {}).get("managed_by_policy", False),
            exposures=[Exposure.from_dict(e) for e in d.get("exposures", [])],
            ports=[PortRow.from_dict(p) for p in d.get("ports", [])],
            findings=[Finding.from_dict(f) for f in d.get("findings", [])],
            score=d.get("score", 0),
            grade=d.get("grade", "?"),
            errors=d.get("errors", []),
            facts=d.get("facts", {}),
            extras=d.get("extras", {}),
        )


# --------------------------------------------------------------------------- analysis


def group_exposures(exposures: list[Exposure]) -> list[PortGroup]:
    groups: dict[tuple[str, int, int], PortGroup] = {}
    for e in exposures:
        lst = e.listener
        key = (lst.protocol, lst.port, lst.pid)
        if key not in groups:
            groups[key] = PortGroup(
                lst.protocol, lst.port, lst.pid, lst.process, lst.exe, lst.services, []
            )
        groups[key].exposures.append(e)
    return sorted(groups.values(), key=lambda g: (g.protocol, g.port, g.pid))


VERDICT_ORDER = [Verdict.REACHABLE, Verdict.UNCERTAIN, Verdict.BLOCKED, Verdict.LOCAL_ONLY]


def _listening_on(g: PortGroup, interfaces: list[NetInterface]) -> str:
    addrs = g.addresses
    if all(e.listener.is_loopback for e in g.exposures):
        return "This PC only (" + ", ".join(sorted(set(addrs))) + ")"
    if any(e.listener.is_wildcard for e in g.exposures):
        return "All networks"
    parts = []
    for a in sorted(set(addrs)):
        iface = next((i for i in interfaces if i.has_ip(a)), None)
        parts.append(f"{iface.alias} ({a})" if iface else a)
    return ", ".join(parts)


def _reachable_from(g: PortGroup) -> tuple[Verdict, Scope, str, str, list[str]]:
    verdicts = {e.verdict for e in g.exposures}
    verdict = next(v for v in VERDICT_ORDER if v in verdicts)
    rules: list[str] = []
    for e in g.exposures:
        for r in e.rules:
            if r not in rules:
                rules.append(r)
    if verdict == Verdict.LOCAL_ONLY:
        return verdict, Scope.NONE, "Only this PC", g.exposures[0].reason, rules
    if verdict == Verdict.BLOCKED:
        reason = next(e.reason for e in g.exposures if e.verdict == Verdict.BLOCKED)
        return verdict, Scope.NONE, "Nobody (blocked by the firewall)", reason, rules
    if verdict == Verdict.UNCERTAIN:
        reason = next(e.reason for e in g.exposures if e.verdict == Verdict.UNCERTAIN)
        return verdict, Scope.NONE, "Uncertain", reason, rules
    parts: list[str] = []
    scope = Scope.NONE
    reasons = []
    for e in g.exposures:
        for ie in e.reachable:
            scope = max(scope, ie.scope, key=lambda s: s.rank)
            if ie.interface_kind == InterfaceKind.VPN:
                text = f"{ie.interface} network"
            elif ie.interface_kind == InterfaceKind.VIRTUAL:
                text = f"VMs ({ie.interface})"
            elif ie.scope == Scope.ANYONE:
                text = f"Anyone on {ie.interface} ({ie.profile.label})"
            elif ie.scope == Scope.LOCAL_SUBNET:
                text = f"Local subnet on {ie.interface} ({ie.profile.label})"
            else:
                text = f"Some addresses on {ie.interface}"
            if text not in parts:
                parts.append(text)
                reasons.append(ie.reason)
    return verdict, scope, "; ".join(parts), " ".join(reasons), rules


def environment_for_paths(env: dict[str, str]) -> dict[str, str]:
    return {k.upper(): v for k, v in env.items()}


def attach_impacts(findings: list[Finding], ctx: ScanContext) -> None:
    """Work out, for every fix offered on an open finding, what it would affect right now."""
    for f in findings:
        if f.status != FindingStatus.OPEN:
            continue
        for opt in f.fixes:
            fix = checks_pkg.FIXES.get(opt.fix_id)
            if fix is None or fix.build is None:
                continue
            try:
                impact = impact_mod.assess(fix.id, opt.params, fix.build(opt.params), ctx)
            except Exception as exc:  # never let impact analysis break a scan
                log.warning("impact of %s failed: %s", opt.fix_id, exc)
                impact = impact_mod.Impact(
                    impact_mod.Level.UNKNOWN, "SimplySec could not work out what this affects."
                )
            opt.impact = impact.to_dict()


def analyze(
    raw: RawScan,
    kb: knowledge.KnowledgeBase | None = None,
    accepted: dict[str, int] | None = None,
    file_exists: Callable[[str], bool] | None = None,
) -> ScanResult:
    return analyze_with_context(raw, kb, accepted, file_exists)[0]


def analyze_with_context(
    raw: RawScan,
    kb: knowledge.KnowledgeBase | None = None,
    accepted: dict[str, int] | None = None,
    file_exists: Callable[[str], bool] | None = None,
) -> tuple[ScanResult, ScanContext]:
    kb = kb or knowledge.get()
    env = environment_for_paths(raw.env)
    evalctx = EvalContext(interfaces=raw.interfaces, env=env)
    exposures = evaluate_all(raw.listeners, raw.firewall, evalctx)
    groups = group_exposures(exposures)
    ctx = ScanContext(
        facts=Facts(raw.facts),
        listeners=raw.listeners,
        exposures=exposures,
        groups=groups,
        interfaces=raw.interfaces,
        firewall=raw.firewall,
        kb=kb,
        signatures=raw.signatures,
        is_admin=raw.is_admin,
        env=env,
        accepted=accepted or {},
        windows_dir=raw.windows_dir,
        file_exists=file_exists or (lambda _p: True),
    )
    findings: list[Finding] = []
    errors = list(raw.errors)
    for check in checks_pkg.CHECKS:
        try:
            findings.extend(check.run(ctx))
        except Exception as exc:  # one broken check must not hide the others
            log.exception("check %s failed", check.id)
            errors.append(f"check {check.id} failed: {exc}")
            findings.append(
                Finding(
                    id=f"{check.id}.error",
                    check=check.id,
                    area=check.area,
                    title=f"The {check.area} check could not run",
                    severity=Severity.INFO,
                    what_it_means=f"Error: {exc}. This area is reported as unknown, not as safe.",
                )
            )
    findings.sort(key=lambda f: (f.status != FindingStatus.OPEN, -int(f.severity), f.area, f.title))
    attach_impacts(findings, ctx)

    by_subject = {}
    for f in findings:
        if f.check == "exposure":
            by_subject[f.id] = f
    rows = []
    for g in groups:
        verdict, scope, reach, reason, rules = _reachable_from(g)
        risk, finding_id = Severity.INFO, None
        if verdict == Verdict.REACHABLE:
            risk, finding_id = exposure_severity_for_group(g, ctx)
            if finding_id not in by_subject:
                finding_id = None
        sig = ctx.signature(g.exe)
        rows.append(
            PortRow(
                protocol=g.protocol,
                port=g.port,
                pid=g.pid,
                process=g.process or ("System" if g.pid == 4 else f"PID {g.pid}"),
                exe=g.exe,
                publisher=sig.publisher
                if sig
                else ("Microsoft (Windows kernel)" if g.pid == 4 else ""),
                services=list(g.services or []),
                listening_on=_listening_on(g, raw.interfaces),
                reachable_from=reach,
                verdict=verdict,
                scope=scope,
                risk=risk,
                reason=reason,
                rules=rules,
                finding_id=finding_id,
                connected=sorted(
                    {
                        str(c.get("remote_ip"))
                        for c in as_list((ctx.facts.get("usage") or {}).get("connections"))
                        if c.get("local_port") == g.port
                        and c.get("pid") == g.pid
                        and g.protocol == "tcp"
                    }
                ),
            )
        )
    value = scoring.score(findings)
    system = Facts(raw.facts).get("system") or {}
    result = ScanResult(
        started=raw.started or dt.datetime.now().astimezone().isoformat(timespec="seconds"),
        duration=raw.duration,
        computer=system.get("computer") or os.environ.get("COMPUTERNAME", ""),
        is_admin=raw.is_admin,
        version=__version__,
        interfaces=raw.interfaces,
        firewall_profiles=list(raw.firewall.profiles.values()),
        firewall_managed=raw.firewall.managed_by_policy,
        exposures=exposures,
        ports=rows,
        findings=findings,
        score=value,
        grade=scoring.grade(value, findings),
        errors=errors,
        facts=raw.facts,
    )
    return result, ctx


# --------------------------------------------------------------------------- plan / apply / undo


@dataclass
class Selection:
    fix_id: str
    params: dict[str, Any] = field(default_factory=dict)
    finding_id: str | None = None


@dataclass
class PlannedFix:
    fix: FixDef
    params: dict[str, Any]
    finding_id: str | None
    specs: list[ActionSpec]
    warnings: list[Warning_]
    impact: Impact | None = None


@dataclass
class Plan:
    items: list[PlannedFix]
    refused: list[str] = field(default_factory=list)

    @property
    def specs(self) -> list[ActionSpec]:
        return [s for item in self.items for s in item.specs]

    @property
    def might_break(self) -> list[str]:
        return [f"{i.fix.label}: {i.fix.might_break}" for i in self.items if i.fix.might_break]

    @property
    def touches_firewall(self) -> bool:
        return any(s.kind.startswith("firewall.") for s in self.specs)


@dataclass
class ChangeOutcome:
    spec: ActionSpec
    change_id: int | None
    status: str  # applied | failed | refused
    verified: bool | None
    error: str = ""
    fix_id: str | None = None
    finding_id: str | None = None


@dataclass
class ApplyResult:
    batch_id: int | None
    backup: str | None
    outcomes: list[ChangeOutcome]
    warnings: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return all(o.status == "applied" and o.verified for o in self.outcomes)


@dataclass
class UndoOutcome:
    change: ChangeRecord
    ok: bool
    error: str = ""


def build_plan(selections: list[Selection], ctx_scan: ScanContext | None = None) -> Plan:
    plan = Plan(items=[])
    for sel in selections:
        fix = checks_pkg.FIXES.get(sel.fix_id)
        if fix is None:
            plan.refused.append(f"unknown fix {sel.fix_id}")
            continue
        if fix.build is None:
            plan.refused.append(f"{fix.label} only opens Windows settings")
            continue
        specs = fix.build(sel.params)
        bad = [s for s in specs if not checks_pkg.spec_allowed(s)]
        if bad:
            plan.refused.append(f"{fix.label}: refused, not on the allow-list ({bad[0].kind})")
            continue
        warnings = fix.warnings(ctx_scan, sel.params) if (fix.warnings and ctx_scan) else []
        impact = impact_mod.assess(fix.id, sel.params, specs, ctx_scan) if ctx_scan else None
        plan.items.append(PlannedFix(fix, sel.params, sel.finding_id, specs, warnings, impact))
    return plan


class Engine:
    def __init__(
        self,
        adapters: Adapters | None = None,
        journal: Journal | None = None,
        history: Any = None,
        collector: Callable[[Progress | None], RawScan] | None = None,
        is_admin: Callable[[], bool] | None = None,
        backups_dir: Path | None = None,
    ) -> None:
        from ..app import elevation, paths

        self._adapters = adapters
        self._journal = journal
        self._history = history
        self._collector = collector
        self._is_admin = is_admin or elevation.is_admin
        self.backups_dir = backups_dir or paths.backups_dir()
        self.last_raw: RawScan | None = None
        self.last_ctx: ScanContext | None = None
        self.last_result: ScanResult | None = None

    # ----------------------------------------------------------------- wiring
    @property
    def adapters(self) -> Adapters:
        if self._adapters is None:
            self._adapters = Adapters.real()
        return self._adapters

    @property
    def journal(self) -> Journal:
        if self._journal is None:
            from ..app import paths

            admin = self._is_admin()
            if admin:
                paths.data_dir().mkdir(parents=True, exist_ok=True)
                try:
                    paths.harden_data_dir()
                except Exception as exc:  # pragma: no cover - needs admin
                    log.error("could not harden %s: %s", paths.data_dir(), exc)
                    raise
            self._journal = Journal(paths.journal_path(), readonly=not admin)
        return self._journal

    @property
    def history(self) -> Any:
        if self._history is None:
            from ..app import paths
            from .history import History

            self._history = History(paths.history_path())
        return self._history

    @property
    def is_admin(self) -> bool:
        return self._is_admin()

    # ----------------------------------------------------------------- scan
    def collect(self, progress: Progress | None = None) -> RawScan:
        if self._collector is not None:
            return self._collector(progress)
        from ..windows.collect import collect

        return collect(progress)

    def scan(
        self, progress: Progress | None = None, save: bool = True, kind: str = "manual"
    ) -> ScanResult:
        raw = self.collect(progress)
        if progress:
            progress("Working out what other devices can reach and checking settings…")
        accepted = {}
        try:
            accepted = self.history.accepted_widths()
        except Exception as exc:
            log.warning("could not read accepted risks: %s", exc)
        result, ctx = analyze_with_context(
            raw, accepted=accepted, file_exists=os.path.exists if self._collector is None else None
        )
        self.last_raw, self.last_result, self.last_ctx = raw, result, ctx
        if progress:
            from .progress import done

            progress(done(f"Analysed: {len(result.open_findings)} things to look at"))
        if save:
            try:
                self.history.save_scan(result, kind=kind)
            except Exception as exc:
                log.warning("could not save scan: %s", exc)
                result.errors.append(f"history not saved: {exc}")
        return result

    # ----------------------------------------------------------------- fixes
    def plan(self, selections: list[Selection]) -> Plan:
        return build_plan(selections, self.last_ctx)

    def recommended(self, result: ScanResult | None = None) -> list[Selection]:
        """'Fix recommended': only non-disruptive fixes on open findings, and never one that
        something is using right now (those must be chosen one at a time)."""
        return self.recommended_split(result)[0]

    def recommended_split(
        self, result: ScanResult | None = None
    ) -> tuple[list[Selection], list[tuple[str, str]]]:
        """(selections, skipped) where skipped lists (finding title, why) for in-use fixes."""
        result = result or self.last_result
        if result is None:
            return [], []
        out, skipped = [], []
        for f in result.open_findings:
            for opt in f.fixes:
                if opt.recommended and not opt.disruptive and not opt.guidance_only:
                    if opt.impact.get("level") == impact_mod.Level.IN_USE.value:
                        skipped.append((f.title, opt.impact.get("headline", "")))
                    else:
                        out.append(Selection(opt.fix_id, opt.params, f.id))
                    break
        return out, skipped

    def apply(
        self, plan: Plan, restore_point: bool = False, progress: Progress | None = None
    ) -> ApplyResult:
        if not self.is_admin:
            raise NeedsAdmin("Applying fixes needs administrator rights.")
        journal = self.journal
        a = self.adapters
        titles = ", ".join(i.fix.label for i in plan.items) or "no changes"
        batch = journal.begin_batch(
            titles[:300], [i.fix.id for i in plan.items], user=getpass.getuser()
        )
        result = ApplyResult(batch_id=batch, backup=None, outcomes=[])
        if plan.touches_firewall:
            if progress:
                progress("Backing up the firewall…")
            try:
                backup = a.firewall.export_policy(self.backups_dir)
                result.backup = str(backup)
                journal.set_backup(batch, str(backup))
            except Exception as exc:
                result.warnings.append(f"Firewall backup failed: {exc}")
                log.error("firewall backup failed: %s", exc)
        if restore_point:
            if progress:
                progress("Creating a System Restore point…")
            try:
                a.system.create_restore_point("SimplySec changes")
            except Exception as exc:
                result.warnings.append(f"Restore point not created: {exc}")
        seq = 0
        for item in plan.items:
            for spec in item.specs:
                seq += 1
                if progress:
                    progress(spec.summary)
                result.outcomes.append(
                    self._apply_one(batch, seq, spec, item.fix.id, item.finding_id)
                )
        return result

    def _apply_one(
        self, batch: int, seq: int, spec: ActionSpec, fix_id: str, finding_id: str | None
    ) -> ChangeOutcome:
        journal, a = self.journal, self.adapters
        prim = PRIMITIVES.get(spec.kind)
        if prim is None or not checks_pkg.spec_allowed(spec):
            return ChangeOutcome(
                spec, None, "refused", None, "not on the allow-list", fix_id, finding_id
            )
        try:
            before = prim.snapshot(a, spec.params)
        except Exception as exc:
            log.error("snapshot failed for %s: %s", spec.kind, exc)
            return ChangeOutcome(
                spec,
                None,
                "failed",
                None,
                f"could not read the current state: {exc}",
                fix_id,
                finding_id,
            )
        cid = journal.add_change(batch, seq, spec, before, fix_id, finding_id)
        try:
            prim.apply(a, spec.params, before)
        except Exception as exc:
            log.error("apply failed for %s: %s", spec.kind, exc)
            journal.mark_failed(cid, str(exc))
            # A partial apply may have changed something: try to restore the before-state.
            try:
                prim.revert(a, spec.params, before)
            except Exception:
                pass
            return ChangeOutcome(spec, cid, "failed", None, str(exc), fix_id, finding_id)
        journal.mark_applied(cid)
        try:
            ok = bool(prim.verify(a, spec.params))
        except Exception as exc:
            log.error("verify failed for %s: %s", spec.kind, exc)
            ok = False
        journal.set_verified(cid, ok)
        log.info("applied %s (verified=%s): %s", spec.kind, ok, spec.summary)
        return ChangeOutcome(spec, cid, "applied", ok, "", fix_id, finding_id)

    @staticmethod
    def resolved(before: ScanResult, after: ScanResult, finding_ids: list[str]) -> dict[str, bool]:
        """Per finding: is it gone (or no longer scored) in a fresh scan?"""
        out = {}
        for fid in finding_ids:
            old, new = before.finding(fid), after.finding(fid)
            out[fid] = (
                new is None or not new.scored or (old is not None and new.severity < old.severity)
            )
        return out

    # ----------------------------------------------------------------- undo
    def undo(
        self,
        change_ids: list[int] | None = None,
        batch_id: int | None = None,
        everything: bool = False,
    ) -> list[UndoOutcome]:
        if not self.is_admin:
            raise NeedsAdmin("Undoing changes needs administrator rights.")
        journal = self.journal
        if everything:
            todo = journal.active_changes()
        elif batch_id is not None:
            todo = [c for c in journal.changes(batch_id) if c.status in (APPLIED, REVERT_FAILED)]
        else:
            todo = [
                c
                for c in (journal.change(i) for i in change_ids or [])
                if c and c.status in (APPLIED, REVERT_FAILED)
            ]
        outcomes = []
        for change in sorted(todo, key=lambda c: c.id, reverse=True):
            outcomes.append(self._undo_one(change))
        return outcomes

    def _undo_one(self, change: ChangeRecord) -> UndoOutcome:
        journal, a = self.journal, self.adapters
        prim = PRIMITIVES.get(change.kind)
        if prim is None or not checks_pkg.is_allowed(change.kind, change.params):
            msg = "refused: this change is not on SimplySec's allow-list (journal may have been altered)"
            journal.mark_revert_failed(change.id, msg)
            return UndoOutcome(change, False, msg)
        before = change.before or {}
        if not prim.before_ok(change.params, before):
            msg = "refused: the stored before-state does not look like something SimplySec saved"
            journal.mark_revert_failed(change.id, msg)
            return UndoOutcome(change, False, msg)
        try:
            prim.revert(a, change.params, before)
            ok = bool(prim.verify_reverted(a, change.params, before))
        except Exception as exc:
            journal.mark_revert_failed(change.id, str(exc))
            return UndoOutcome(change, False, str(exc))
        if ok:
            journal.mark_reverted(change.id)
            log.info("reverted change %s: %s", change.id, change.summary)
            return UndoOutcome(change, True)
        journal.mark_revert_failed(
            change.id, "the original state could not be confirmed after undo"
        )
        return UndoOutcome(change, False, "the original state could not be confirmed after undo")

    def remove_all_rules(self) -> tuple[list[UndoOutcome], list[str]]:
        """Undo every journaled firewall rule, then delete anything left in the SimplySec group."""
        outcomes = []
        for change in sorted(self.journal.active_changes(), key=lambda c: c.id, reverse=True):
            if change.kind == "firewall.add_rule":
                outcomes.append(self._undo_one(change))
        leftovers = []
        for rule in self.adapters.firewall.group_rules():
            self.adapters.firewall.remove_rules_named(rule.name)
            leftovers.append(rule.name)
        return outcomes, leftovers


__all__ = [
    "ApplyResult",
    "Engine",
    "NeedsAdmin",
    "Plan",
    "PortRow",
    "RawScan",
    "ScanResult",
    "Selection",
    "analyze",
    "analyze_with_context",
    "build_plan",
]
