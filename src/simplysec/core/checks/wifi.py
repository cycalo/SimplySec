"""Wi-Fi on this PC: weak saved networks that connect automatically, and open networks now."""

from __future__ import annotations

from typing import Any

from ..models import ActionSpec, InterfaceKind, Severity
from ..util import as_list
from .base import Allow, Check, FixDef, ScanContext, finding

AREA = "Wi-Fi"


def _build_manual(params: dict[str, Any]) -> list[ActionSpec]:
    return [
        ActionSpec(
            "wifi.connection_mode",
            {"profile_name": name, "mode": "manual"},
            f"Stop connecting to the Wi-Fi network '{name}' automatically (connection mode: manual).",
        )
        for name in params.get("profiles", [])
    ]


FIX_MANUAL = FixDef(
    id="wifi.manual_connect",
    label="Stop auto-connecting",
    description="Windows will only join these networks when you pick them yourself. The saved networks stay.",
    might_break="You'll have to choose these networks by hand when you want to use them.",
    build=_build_manual,
)
FIX_GUIDE = FixDef(
    id="wifi.open_settings",
    label="Open network settings",
    description="Opens Settings so you can disconnect or use a VPN.",
    might_break="Nothing changes until you change it yourself.",
    guidance="network",
)


def run(ctx: ScanContext) -> list:
    profiles = ctx.facts.get("wifi")
    if profiles is None:
        return []
    out = []
    weak = [p for p in as_list(profiles) if p.get("weak")]
    auto = [p for p in weak if p.get("connection_mode") == "auto"]
    if auto:
        out.append(
            finding(
                id="wifi.weak_autoconnect",
                check="wifi",
                area=AREA,
                title=f"This PC joins {len(auto)} insecure Wi-Fi network(s) automatically",
                severity=Severity.MEDIUM,
                what=(
                    "Anyone can create a Wi-Fi network with the same name as an open or weakly protected one "
                    "you used before. Your PC would join it automatically, letting them watch or redirect "
                    "your traffic."
                ),
                details=[(p["name"], p["weak"]) for p in auto],
                fixes=[FIX_MANUAL.option({"profiles": [p["name"] for p in auto]})],
            )
        )
    connected = {
        i.network_name
        for i in ctx.active_interfaces()
        if i.kind == InterfaceKind.WIFI and i.network_name
    }
    now_open = [p for p in weak if p.get("ssid") in connected or p.get("name") in connected]
    for p in now_open:
        out.append(
            finding(
                id=f"wifi.connected_insecure.{p['name']}",
                check="wifi",
                area=AREA,
                title=f"You are connected to an insecure Wi-Fi network: {p['name']}",
                severity=Severity.HIGH,
                what=(
                    f"This network is {p['weak']}. Others nearby can see unencrypted traffic and may "
                    "pretend to be websites. Avoid signing in to anything important, or use a VPN."
                ),
                fixes=[FIX_GUIDE.option()],
            )
        )
    return out


CHECK_DEF = Check(
    id="wifi",
    area=AREA,
    run=run,
    fixes=[FIX_MANUAL, FIX_GUIDE],
    allows=[
        Allow(
            "wifi.connection_mode",
            lambda p: (
                isinstance(p.get("profile_name"), str) and p.get("mode") in ("manual", "auto")
            ),
        )
    ],
)
