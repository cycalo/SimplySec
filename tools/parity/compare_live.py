"""Live parity check between Python v2 and the C# port on this PC (read-only).

    .venv\\Scripts\\python tools\\parity\\compare_live.py [--runs N] [--out DIR] [--all]

Each run does three comparisons:
  1. raw     - Python collect() vs C# `scan --raw`, section by section (listeners, firewall,
               interfaces, signatures, env, each fact).
  2. analyze - the same RawScan analysed by both: C# `scan --from-raw` vs Python analyze(),
               for Python's raw and for C#'s raw. Strict: any difference fails.
  3. scan    - `scan --json --no-save` from both CLIs.

The two collections run a few seconds apart, so steps 1 and 3 separate real differences from
live drift:
  - a listening socket seen by only one side is drift unless it was open both before and after
    the two collections (then the side that missed it is wrong);
  - UDP 5353 (mDNS) is shared by several programs and its owner changes from scan to scan;
  - current connections (usage fact, "connected", in-use impact) change all the time;
  - findings, ports, counts and score that differ only because of the above.
Ignored: timestamps, durations and version strings.

The gate is N runs in a row without a real difference (default 3). Exit code 0 only then.
"""

from __future__ import annotations

import argparse
import json
import os
import socket
import subprocess
import sys
import tempfile
import time
from collections import Counter
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import psutil

ROOT = Path(__file__).resolve().parents[2]
PY = ROOT / ".venv" / "Scripts" / "python.exe"
DUMP = ROOT / "tools" / "parity" / "dump_raw.py"
CS_EXE = (
    ROOT
    / "src"
    / "SimplySec.Cli"
    / "bin"
    / "Debug"
    / "net10.0-windows10.0.19041.0"
    / "win-x64"
    / "simplysec-cli.exe"
)

VOLATILE_TOP = {"started", "duration", "version"}
IGNORED_FACTS = {"collected"}

Diff = tuple[str, Any, Any]
LKey = tuple[Any, ...]

# --------------------------------------------------------------------------- diff


def _kind(v: Any) -> str:
    if isinstance(v, bool):
        return "bool"
    if isinstance(v, (int, float)):
        return "num"
    if isinstance(v, str):
        return "str"
    if isinstance(v, list):
        return "list"
    if isinstance(v, dict):
        return "dict"
    return "null" if v is None else type(v).__name__


def deep_diff(a: Any, b: Any, path: str = "") -> list[Diff]:
    """Strict structural diff: bool is not a number, int 1 equals float 1.0."""
    ka, kb = _kind(a), _kind(b)
    if ka != kb:
        return [(path or "/", a, b)]
    if ka == "dict":
        out: list[Diff] = []
        for k in sorted(set(a) | set(b), key=str):
            p = f"{path}/{k}"
            if k not in a:
                out.append((p, "<missing>", b[k]))
            elif k not in b:
                out.append((p, a[k], "<missing>"))
            else:
                out.extend(deep_diff(a[k], b[k], p))
        return out
    if ka == "list":
        if len(a) != len(b):
            return [(f"{path} (len {len(a)} vs {len(b)})", a, b)]
        out = []
        for i, (x, y) in enumerate(zip(a, b, strict=True)):
            out.extend(deep_diff(x, y, f"{path}[{i}]"))
        return out
    return [] if a == b else [(path or "/", a, b)]


def _short(v: Any, n: int = 160) -> str:
    s = v if isinstance(v, str) else json.dumps(v, default=str, ensure_ascii=False)
    return s if len(s) <= n else s[: n - 3] + "..."


def _canon(v: Any) -> str:
    return json.dumps(v, sort_keys=True, default=str)


@dataclass
class Pair:
    """An item present on both sides (field diffs) or on one side only."""

    key: Any
    diffs: list[Diff] = field(default_factory=list)
    only: str = ""  # "py" or "cs" when the item exists on one side only
    item: Any = None


def pair_lists(a: list[Any], b: list[Any], key: Callable[[Any], Any], path: str) -> list[Pair]:
    """Compare two lists ignoring order; items are paired by ``key`` for a field-level diff."""
    ca, cb = Counter(_canon(x) for x in a), Counter(_canon(x) for x in b)
    only_a = [json.loads(s) for s, n in (ca - cb).items() for _ in range(n)]
    only_b = [json.loads(s) for s, n in (cb - ca).items() for _ in range(n)]
    out: list[Pair] = []
    by_key_b: dict[Any, list[Any]] = {}
    for y in only_b:
        by_key_b.setdefault(key(y), []).append(y)
    for x in only_a:
        k = key(x)
        if by_key_b.get(k):
            y = by_key_b[k].pop(0)
            out.append(Pair(k, deep_diff(x, y, f"{path}[{k}]")))
        else:
            out.append(Pair(k, only="py", item=x))
    for k, rest in by_key_b.items():
        for y in rest:
            out.append(Pair(k, only="cs", item=y))
    return out


def as_diff(p: Pair, path: str) -> list[Diff]:
    if p.only == "py":
        return [(f"{path}[{p.key}]", p.item, "<missing>")]
    if p.only == "cs":
        return [(f"{path}[{p.key}]", "<missing>", p.item)]
    return p.diffs


@dataclass
class Outcome:
    real: dict[str, list[Diff]] = field(default_factory=dict)
    drift: dict[str, list[Diff]] = field(default_factory=dict)

    def add(self, section: str, diffs: list[Diff], drift: bool) -> None:
        if diffs:
            (self.drift if drift else self.real).setdefault(section, []).extend(diffs)


# --------------------------------------------------------------------------- live sockets


def listener_key(x: dict[str, Any]) -> LKey:
    return (x.get("protocol"), x.get("address"), x.get("port"), x.get("pid"))


def is_mdns(k: LKey) -> bool:
    return k[0] == "udp" and k[2] == 5353


def live_listeners() -> set[LKey]:
    """Listening sockets right now, the way windows/listeners.py selects them."""
    out: set[LKey] = set()
    for c in psutil.net_connections(kind="inet"):
        if c.type == socket.SOCK_STREAM:
            if c.status != psutil.CONN_LISTEN:
                continue
            proto = "tcp"
        else:
            if c.raddr:
                continue
            proto = "udp"
        if c.laddr:
            out.add((proto, c.laddr.ip, c.laddr.port, int(c.pid or 0)))
    return out


# --------------------------------------------------------------------------- step 1: raw


def _normalize_facts(facts: dict[str, Any]) -> dict[str, Any]:
    """Documented P6 deviations of the native facts (both have no effect on the analysis):
    network.ip keeps the IP-interface order, not Get-NetIPConfiguration's (it is only ever
    looked up by interface index); last logons have whole seconds (netapi32), not ticks."""
    facts = json.loads(json.dumps(facts))
    net = facts.get("network", {}).get("value")
    if isinstance(net, dict) and isinstance(net.get("ip"), list):
        net["ip"] = sorted(net["ip"], key=lambda x: x.get("index", 0))
    usage = facts.get("usage", {}).get("value")
    if isinstance(usage, dict):
        for row in usage.get("last_logons") or []:
            if isinstance(row, dict) and isinstance(row.get("last"), str):
                row["last"] = row["last"][:19]
    return facts


def compare_raw(py: dict[str, Any], cs: dict[str, Any], stable: set[LKey]) -> Outcome:
    o = Outcome()
    listener_drift = False
    for p in pair_lists(py.get("listeners", []), cs.get("listeners", []), listener_key, "listeners"):
        if is_mdns(p.key):
            drift = True
        elif p.only:
            drift = p.key not in stable
        else:
            drift = False
        listener_drift |= drift
        o.add("listeners", as_diff(p, "listeners"), drift)

    pf, cf = py.get("firewall", {}), cs.get("firewall", {})
    for section, a, b, key in (
        ("firewall.profiles", pf.get("profiles", []), cf.get("profiles", []), lambda p: p.get("profile")),
        (
            "firewall.rules",
            pf.get("rules", []),
            cf.get("rules", []),
            lambda r: (r.get("name"), r.get("application"), r.get("direction"), r.get("protocol")),
        ),
        ("interfaces", py.get("interfaces", []), cs.get("interfaces", []), lambda i: (i.get("index"), i.get("alias"))),
    ):
        for p in pair_lists(a, b, key, section):
            o.add(section, as_diff(p, section), False)
    o.add(
        "firewall.state",
        deep_diff(
            {k: v for k, v in pf.items() if k not in ("profiles", "rules")},
            {k: v for k, v in cf.items() if k not in ("profiles", "rules")},
            "firewall",
        ),
        False,
    )

    ps, cs_sigs = py.get("signatures", {}), cs.get("signatures", {})
    for path in sorted(set(ps) | set(cs_sigs)):
        if path not in ps or path not in cs_sigs:
            # Which programs get checked follows the listeners, so this drifts with them.
            o.add("signatures", deep_diff(ps.get(path, "<missing>"), cs_sigs.get(path, "<missing>"), f"signatures/{path}"), listener_drift)
        else:
            o.add("signatures", deep_diff(ps[path], cs_sigs[path], f"signatures/{path}"), False)

    o.add("env", deep_diff(py.get("env", {}), cs.get("env", {}), "env"), False)
    keys = ("is_admin", "windows_dir", "errors")
    o.add("top", deep_diff({k: py.get(k) for k in keys}, {k: cs.get(k) for k in keys}, ""), False)

    pfacts, cfacts = _normalize_facts(py.get("facts", {})), _normalize_facts(cs.get("facts", {}))
    for name in sorted(set(pfacts) | set(cfacts)):
        if name in IGNORED_FACTS:
            continue
        for d in deep_diff(pfacts.get(name, "<missing>"), cfacts.get(name, "<missing>"), f"facts/{name}"):
            o.add(f"facts.{name}", [d], name == "usage" and "/connections" in d[0])
    return o


# --------------------------------------------------------------------------- steps 2 and 3


def _port_key(r: dict[str, Any]) -> LKey:
    return (r.get("protocol"), r.get("port"), r.get("pid"))


def _mdns_item(section: str, key: Any) -> bool:
    if section == "ports":  # (protocol, port, pid)
        return key[0] == "udp" and key[1] == 5353
    if section == "exposures":  # (protocol, address, port, pid)
        return is_mdns(key)
    return False


def compare_result(py: dict[str, Any], cs: dict[str, Any], live: bool) -> Outcome:
    """Compare two ScanResult dicts. ``live``: the two came from separate collections."""
    o = Outcome()
    pairs = {
        "findings": pair_lists(py.get("findings", []), cs.get("findings", []), lambda f: f.get("id"), "findings"),
        "ports": pair_lists(py.get("ports", []), cs.get("ports", []), _port_key, "ports"),
        "exposures": pair_lists(
            py.get("exposures", []), cs.get("exposures", []), lambda e: listener_key(e.get("listener", {})), "exposures"
        ),
    }
    # In a live comparison, listeners seen by one side only and connections that came and went
    # explain one-sided findings/ports/exposures, "connected" lists and in-use impacts.
    listener_drift = live and any(
        p.only or _mdns_item(s, p.key) for s in ("exposures", "ports") for p in pairs[s]
    )
    connection_drift = live and any(
        "/connected" in d[0] for p in pairs["ports"] for d in p.diffs
    )
    for section, plist in pairs.items():
        for p in plist:
            if p.only:
                o.add(section, as_diff(p, section), listener_drift)
                continue
            for d in p.diffs:
                path = d[0]
                drift = live and (
                    _mdns_item(section, p.key)
                    or (section == "findings" and listener_drift)
                    or "/connected" in path
                    or ("/impact" in path and connection_drift)
                )
                o.add(section, [d], drift)
    findings_drift = any(p.only for p in pairs["findings"]) or bool(o.drift.get("findings"))
    for k in sorted(set(py) | set(cs)):
        if k in VOLATILE_TOP or k in pairs:
            continue
        drift = live and k in ("score", "grade", "counts") and findings_drift
        o.add(k, deep_diff(py.get(k, "<missing>"), cs.get(k, "<missing>"), k), drift)
    return o


# --------------------------------------------------------------------------- running


def _child_env() -> dict[str, str]:
    # Started from PowerShell 7, Windows PowerShell 5.1 inherits 7's PSModulePath and cannot load
    # its own modules (Python v2 then reports every signature as Unreadable). C# drops the
    # variable itself; do the same for the Python side so both read the same machine.
    return {k: v for k, v in os.environ.items() if k.upper() != "PSMODULEPATH"}


def run(cmd: list[str], out: Path | None = None) -> None:
    t = time.monotonic()
    proc = subprocess.run(cmd, capture_output=True, cwd=ROOT, timeout=600, env=_child_env())
    if proc.returncode != 0:
        sys.stderr.write(proc.stderr.decode("utf-8", "replace"))
        raise SystemExit(f"command failed ({proc.returncode}): {' '.join(cmd)}")
    if out is not None:
        out.write_bytes(proc.stdout)
    print(f"    {Path(cmd[0]).name} {' '.join(Path(c).name for c in cmd[1:3])}: {time.monotonic() - t:.1f}s")


def load(p: Path) -> Any:
    return json.loads(p.read_text(encoding="utf-8-sig"))


def _print(diffs: dict[str, list[Diff]], limit: int | None) -> None:
    for section, items in diffs.items():
        print(f"      [{section}] {len(items)}")
        for path, a, b in items if limit is None else items[:limit]:
            print(f"        {path}\n          py: {_short(a)}\n          cs: {_short(b)}")
        if limit is not None and len(items) > limit:
            print(f"        ... {len(items) - limit} more (use --all)")


def report(title: str, o: Outcome, show_all: bool) -> int:
    real = sum(len(v) for v in o.real.values())
    drift = sum(len(v) for v in o.drift.values())
    note = f", {drift} live drift" if drift else ""
    print(f"  {title}: {'clean' if real == 0 else f'{real} DIFFERENCE(S)'}{note}")
    _print(o.real, None if show_all else 12)
    if drift and show_all:
        print("    drift:")
        _print(o.drift, None)
    elif drift:
        print("    drift: " + ", ".join(f"{k} {len(v)}" for k, v in o.drift.items()))
    return real


def one_run(d: Path, show_all: bool) -> int:
    py_raw, cs_raw = d / "py_raw.json", d / "cs_raw.json"
    print("  collecting")
    before = live_listeners()
    run([str(PY), str(DUMP), "collect", str(py_raw)])
    run([str(CS_EXE), "scan", "--raw"], cs_raw)
    stable = before & live_listeners()
    bad = report("1. raw scan", compare_raw(load(py_raw), load(cs_raw), stable), show_all)

    print("  analysing the same raw scan")
    for label, raw in (("python raw", py_raw), ("c# raw", cs_raw)):
        pa, ca = d / f"py_an_{raw.stem}.json", d / f"cs_an_{raw.stem}.json"
        run([str(PY), str(DUMP), "analyze", str(raw), str(pa)])
        run([str(CS_EXE), "scan", "--from-raw", str(raw)], ca)
        bad += report(f"2. analyze ({label})", compare_result(load(pa), load(ca), live=False), show_all)

    print("  full scans")
    ps, cs = d / "py_scan.json", d / "cs_scan.json"
    run([str(PY), "-m", "simplysec", "scan", "--json", "--no-save"], ps)
    run([str(CS_EXE), "scan", "--json", "--no-save"], cs)
    bad += report("3. scan --json", compare_result(load(ps), load(cs), live=True), show_all)
    return bad


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawTextHelpFormatter)
    ap.add_argument("--runs", type=int, default=3)
    ap.add_argument("--out", type=Path, default=None, help="keep the JSON files here")
    ap.add_argument("--all", action="store_true", help="print every difference, drift included")
    args = ap.parse_args()
    if not CS_EXE.exists():
        raise SystemExit(f"build the CLI first: dotnet build src/SimplySec.Cli ({CS_EXE})")
    base = args.out or Path(tempfile.mkdtemp(prefix="simplysec-parity-"))
    results = []
    for i in range(1, args.runs + 1):
        d = base / f"run{i}"
        d.mkdir(parents=True, exist_ok=True)
        print(f"run {i}/{args.runs} -> {d}")
        results.append(one_run(d, args.all))
    clean = sum(1 for r in results if r == 0)
    print(f"\n{clean}/{len(results)} clean run(s)")
    return 0 if clean == len(results) else 1


if __name__ == "__main__":
    sys.exit(main())
