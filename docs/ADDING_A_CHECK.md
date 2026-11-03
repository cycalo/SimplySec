# Adding a check

A check is one class in `src/SimplySec.Core/Checks/` that turns facts into findings with
plain-language text and reversible fixes. `RemoteAccessCheck.cs` is a short, complete example.

## 1. Get the facts

* **Windows settings:** add an item to `Items` in `src/SimplySec.Windows/NativeFacts.cs` and a
  reader method that returns a `JsonNode`. Use CIM (`Wmi.Query/First`), the registry
  (`PsRegistry.Value`) or a native API. Return numbers and invariant strings, never localized
  text. `Fact()` wraps each reader: an access-denied error becomes `status = needs_admin`, any
  other exception `status = error`.
* **Ports, programs and services:** add them to the TOML files in
  `src/SimplySec.Core/Resources/knowledge/`. Describe what it means when **this PC listens** on
  the port, in neutral words.

## 2. Write the check

```csharp
// src/SimplySec.Core/Checks/ExampleCheck.cs
using SimplySec.Core.Compat;
using SimplySec.Core.Model;
using static SimplySec.Core.Checks.CheckHelpers;

namespace SimplySec.Core.Checks;

public static class ExampleCheck
{
    public const string CheckId = "example";
    public const string Area = "System";
    public const string Key = @"HKLM\SOFTWARE\Policies\Example";

    public static readonly FixDef FixOff = new()
    {
        Id = "example.turn_off",                       // unique; referenced from findings and TOML
        Label = "Turn Example off",
        Description = "Sets Enabled = 0 so …",          // shown in the preview
        MightBreak = "Feature X stops working.",        // "what might stop working"
        Build = _ => [RegAction(Key, "Enabled", 0, "REG_DWORD", "Turn off Example (Enabled = 0).")],
        Recommended = false,   // true only for safe, non-disruptive fixes ("Fix recommended")
        Disruptive = false,    // true if it can break something the user relies on
    };

    public static List<Finding> Run(ScanContext ctx)
    {
        var data = ctx.Facts.Get("example");
        if (data is null)                                // never treat "unknown" as "safe"
        {
            var f0 = FactUnavailable(ctx, "example", CheckId, Area, "the Example setting");
            return f0 is null ? [] : [f0];
        }
        if (!Js.NumEquals(Js.Get(data, "enabled"), 1))
        {
            return [];
        }
        return
        [
            NewFinding("example.on", CheckId, Area,       // the id stays stable across scans (history, Keep)
                "Example is on",                          // plain words, no jargon
                Severity.Medium,
                "What this means for the user, in one or two sentences.",
                [("Enabled", "1")],                       // technical details
                [FixOff.Option()]),
        ];
    }

    public static readonly Check Definition = new()
    {
        Id = CheckId,
        Area = Area,
        Run = Run,
        Fixes = [FixOff],
        Allows = [RegAllow((Key, "Enabled"))],
    };
}
```

Register it in `Checks` in `src/SimplySec.Core/Checks/Registry.cs`. If its area is new, add it
to `AreaOrder` in `src/SimplySec.App/Views/ThisPcPage.cs`.

## 3. Rules for fixes

* Build fixes only from the primitives in `src/SimplySec.Core/Actions/Primitives.cs`. If you
  need a new kind, add a `Primitive` with `Snapshot`, `Apply`, `Verify`, `Revert`,
  `VerifyReverted` and `BeforeOk`, plus the adapter method in `SimplySec.Windows`.
* Declare an `Allow` for every kind and parameter set your fix produces. Apply and undo refuse
  anything no check allows.
* Never add allow rules or outbound rules, never kill processes, never touch services on the
  never-touch list, never restart the firewall service.
* If Group Policy controls the setting, set `Status = FindingStatus.Managed` instead of
  offering a fix.
* Guidance-only fixes set `Guidance = "settings-page-key"` (see `SystemSetters.OpenSettings`) and
  no `Build`.

## 4. Test it

* Add cases to `tests/SimplySec.Core.Tests/ThisPcTests.cs` using the real-data fixture
  (`tests/fixtures/this_pc_raw.json`) with edited facts. `KnowledgeBaseIsValid` and
  `AllowListsRefuseTamperedActions` check that fixes exist and are allow-listed.
* **The golden corpus will notice.** `AnalyzeGoldenTests` compares every scenario's full result
  with `tests/golden/analyze.json.gz`, so a new check (or new wording) makes it fail. That is
  expected; update the goldens on purpose (see `docs/TODO.md`, "golden update mode") and review
  the diff.
* For the native fact, run `dotnet test --project tests/SimplySec.Windows.Tests` (it collects
  the facts on this PC) and, if it needs admin, once from an elevated prompt.
