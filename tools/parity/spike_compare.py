"""P0 spikes: compare the C# native readers with Python v2 on this PC (read-only).

    .venv\\Scripts\\python tools\\parity\\spike_compare.py
"""

from __future__ import annotations

import json
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import psutil

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from simplysec.windows import firewall, listeners  # noqa: E402

EXE = ROOT / "tools" / "spikes" / "bin" / "Debug" / "net10.0-windows10.0.19041.0" / "SimplySec.Spikes.exe"


def run(*args: str) -> object:
    out = subprocess.run([str(EXE), *args], capture_output=True, text=True, check=True, encoding="utf-8")
    sys.stderr.write(out.stderr)
    return json.loads(out.stdout)


def firewall_spike() -> bool:
    t = time.monotonic()
    py = firewall.read_state()
    print(f"python firewall: {time.monotonic() - t:.2f} s")
    cs = run("firewall")
    ok = True
    if len(py.rules) != len(cs["rules"]):
        print(f"  rule count differs: python {len(py.rules)}, C# {len(cs['rules'])}")
        ok = False
    for a, b in zip(py.rules, cs["rules"], strict=False):
        pa = {
            "name": a.name,
            "application": a.application,
            "service": a.service,
            "protocol": a.protocol,
            "local_ports": a.local_ports,
            "remote_addresses": a.remote_addresses,
            "direction": a.direction,
            "enabled": a.enabled,
            "profiles": a.profiles,
            "action": a.action,
            "local_user_owner": a.local_user_owner,
            "edge_traversal_options": a.edge_traversal_options,
        }
        if pa != b:
            print("  rule differs:", pa, b)
            ok = False
            break
    py_profiles = [p.to_dict() for p in py.profiles.values()]
    if py_profiles != cs["profiles"] or py.current_profiles != cs["current_profiles"]:
        print("  profiles differ", py_profiles, cs["profiles"])
        ok = False
    print(f"firewall: {'OK' if ok else 'DIFF'} ({len(cs['rules'])} rules)")
    return ok


def sockets_spike() -> bool:
    py = set()
    seen = set()
    for c in psutil.net_connections(kind="inet"):
        if c.type == socket.SOCK_STREAM:
            if c.status != psutil.CONN_LISTEN:
                continue
            proto = "tcp"
        else:
            if c.raddr:
                continue
            proto = "udp"
        key = (proto, c.laddr.ip, c.laddr.port)
        if key in seen:
            continue
        seen.add(key)
        py.add((proto, c.laddr.ip, c.laddr.port, int(c.pid or 0)))
    cs = {(x["protocol"], x["address"], x["port"], x["pid"]) for x in run("sockets")}
    only_py, only_cs = py - cs, cs - py
    # Short-lived UDP sockets come and go between the two reads.
    print(f"sockets: python {len(py)}, C# {len(cs)}, only python {sorted(only_py)}, only C# {sorted(only_cs)}")
    return not [x for x in only_py | only_cs if x[0] == "tcp"]


def signatures_spike() -> bool:
    paths = sorted({lst.exe for lst in listeners.read_listeners() if lst.exe})
    paths += [r"C:\Windows\System32\svchost.exe", r"C:\Windows\notepad.exe", r"C:\Windows\System32\drivers\etc\hosts"]
    t = time.monotonic()
    py = listeners.signatures(paths)
    print(f"python signatures: {time.monotonic() - t:.2f} s for {len(paths)} files")
    with tempfile.NamedTemporaryFile("w", delete=False, suffix=".txt", encoding="utf-8") as fh:
        fh.write("\n".join(paths))
    cs = run("sigs", fh.name)
    ok = True
    for p in paths:
        a = py.get(p.lower())
        b = cs.get(p.lower())
        pa = (a.status, a.publisher) if a else None
        sig = listeners.Signature(b["status"], b["signer"]) if b else None
        pb = (sig.status, sig.publisher) if sig else None
        if pa != pb:
            print(f"  {p}: python {pa}, C# {pb}")
            ok = False
    print(f"signatures: {'OK' if ok else 'DIFF'}")
    return ok


if __name__ == "__main__":
    results = [firewall_spike(), sockets_spike(), signatures_spike()]
    sys.exit(0 if all(results) else 1)
