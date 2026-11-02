using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using SimplySec.Core.Compat;
using SimplySec.Core.Model;

namespace SimplySec.Core.Checks;

/// <summary>All check modules, the fix registry and the action allow-lists.</summary>
public static partial class Registry
{
    public static readonly List<Check> Checks =
    [
        FirewallCheck.Definition,
        ExposureCheck.Definition,
        RemoteAccessCheck.Definition,
        LegacyCheck.Definition,
        SharingCheck.Definition,
        MalwareCheck.Definition,
        UpdatesCheck.Definition,
        AccountsCheck.Definition,
        SystemCheck.Definition,
        WifiCheck.Definition,
        HousekeepingCheck.Definition,
    ];

    public static readonly OrderedDictionary<string, FixDef> Fixes = BuildFixes();

    private static OrderedDictionary<string, FixDef> BuildFixes()
    {
        var fixes = new OrderedDictionary<string, FixDef>(StringComparer.Ordinal);
        foreach (var check in Checks)
        {
            foreach (var fix in check.Fixes)
            {
                if (!fixes.TryAdd(fix.Id, fix))
                {
                    throw new InvalidOperationException($"duplicate fix id {fix.Id}");
                }
            }
        }
        return fixes;
    }

    public const string DailyCheckTask = @"\SimplySec\Daily check";

    [GeneratedRegex(@"^([01]\d|2[0-3]):[0-5]\d$")]
    private static partial Regex TimeOfDay();

    /// <summary>Kinds allowed outside the check modules (the scheduled task is created by Settings).</summary>
    public static readonly List<Allow> ExtraAllows =
    [
        new Allow("task.schedule", p =>
            Js.PyEquals(Js.Get(p, "name"), JsonValue.Create(DailyCheckTask))
            && Js.IsString(Js.Get(p, "time"))
            && TimeOfDay().IsMatch(p["time"]!.GetValue<string>())
            && !p["time"]!.GetValue<string>().Contains('\n')),
    ];

    public static IEnumerable<Allow> Allows() => ExtraAllows.Concat(Checks.SelectMany(c => c.Allows));

    /// <summary>True if some check module declares this exact kind and parameters as allowed.</summary>
    public static bool IsAllowed(string kind, JsonObject parameters)
    {
        foreach (var allow in Allows())
        {
            if (allow.Kind != kind)
            {
                continue;
            }
            try
            {
                if (allow.Predicate(parameters))
                {
                    return true;
                }
            }
            catch (Exception e) when (e is KeyNotFoundException or InvalidOperationException or FormatException or NullReferenceException or InvalidCastException or ArgumentException)
            {
            }
        }
        return false;
    }

    public static bool SpecAllowed(ActionSpec spec) => IsAllowed(spec.Kind, spec.Params);
}
