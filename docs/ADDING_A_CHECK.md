# Adding a check

A check is one module in `src/simplysec/core/checks/` that turns facts into findings with
plain-language text and reversible fixes. It replaces v1's `port_security_docs.md`.

## 1. Get the facts

* Windows settings: add an item to `src/simplysec/windows/scripts/facts.ps1` inside `Fact { … }`.
  Return objects or numbers, never localized text. A permission error becomes
  `status = needs_admin` automatically.
* Ports, programs and services: add them to the TOML files in `core/knowledge/`. Describe what
  it means when **this PC listens** on the port, in neutral words.

## 2. Write the module

```python
# core/checks/example.py
from ..models import Severity
from .base import Check, FixDef, ScanContext, fact_unavailable, finding, reg_action, reg_allow

AREA = "System"
KEY = r"HKLM\SOFTWARE\Policies\Example"

FIX = FixDef(
    id="example.turn_off",                  # unique, referenced from findings and TOML
    label="Turn Example off",
    description="Sets Enabled = 0 so …",    # shown in the preview
    might_break="Feature X stops working.",  # "what might stop working"
    build=lambda params: [reg_action(KEY, "Enabled", 0, "REG_DWORD", "Turn off Example (Enabled = 0).")],
    recommended=False,   # True only for safe, non-disruptive fixes ("Fix recommended")
    disruptive=False,    # True if it can break something the user relies on
)


def run(ctx: ScanContext) -> list:
    data = ctx.facts.get("example")
    if data is None:                         # never treat "unknown" as "safe"
        f = fact_unavailable(ctx, "example", "example", AREA, "the Example setting")
        return [f] if f else []
    if data.get("enabled") != 1:
        return []
    return [
        finding(
            id="example.on",                 # stable across scans (history, Keep)
            check="example",
            area=AREA,
            title="Example is on",           # plain words, no jargon
            severity=Severity.MEDIUM,
            what="What this means for the user, in one or two sentences.",
            details=[("Enabled", "1")],      # technical details (registry values, rules, PIDs)
            fixes=[FIX.option()],
        )
    ]


CHECK_DEF = Check(id="example", area=AREA, run=run, fixes=[FIX], allows=[reg_allow((KEY, "Enabled"))])
```

Register it in `core/checks/__init__.py` (`CHECKS`). Add its area to `AREA_ORDER` in
`ui/pages/this_pc.py` if it's new.

## 3. Rules for fixes

* Build fixes only from the primitives in `core/actions.py`. If you need a new kind, add a
  `Primitive` with `snapshot`, `apply`, `verify`, `revert`, `verify_reverted` and `before_ok`.
* Declare an `Allow` for every kind/parameter set your fix produces. Apply and undo refuse
  anything no check allows.
* Never add allow rules or outbound rules, never kill processes, never touch services on the
  never-touch list, never restart the firewall service.
* If Group Policy controls the setting, set `finding.status = FindingStatus.MANAGED` instead of
  offering a fix.
* Guidance-only fixes set `guidance="settings-page-key"` (see `windows/system.py`) and no `build`.

## 4. Test it

Add a case to `tests/unit/test_checks.py` using the real-data fixture and `_with_facts(...)` to
edit the facts. `test_every_offered_fix_builds_allowed_actions` and the knowledge-base tests
check that fixes exist and are allow-listed.
