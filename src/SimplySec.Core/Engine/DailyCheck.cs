using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using System.Xml;
using System.Xml.Linq;
using SimplySec.Core.Checks;
using SimplySec.Core.Compat;
using SimplySec.Core.Lan;
using SimplySec.Core.Model;
using SimplySec.Core.Storage;

namespace SimplySec.Core.Engine;

/// <summary>
/// Background daily check: a read-only scan, saved to history, with a toast only when it matters
/// (risk score +5, new High/Critical finding, new device, antivirus or firewall turned off).
/// </summary>
public static partial class DailyCheck
{
    public const string TaskName = Registry.DailyCheckTask;
    public const string Setting = "daily_check";

    [GeneratedRegex(@"^(firewall\.off\.|malware\.no_antivirus$|malware\.realtime_off$)")]
    private static partial Regex ProtectionOffRegex();

    public static bool ProtectionOff(string id) => ProtectionOffRegex().IsMatch(id) && !id.EndsWith('\n');

    /// <summary>Plain-language reasons to notify (empty: stay quiet).</summary>
    public static List<string> Triggers(JsonNode? prev, JsonNode cur)
    {
        var output = new List<string>();
        var diff = History.Compare(prev, cur);
        if (prev is not null && diff.ScoreChange >= 5)
        {
            output.Add($"Your risk score rose from {Js.PyRepr(Js.Get(prev, "score"))} to {Js.PyRepr(Js.Get(cur, "score"))}.");
        }
        var prevOpen = (Js.Get(prev ?? new JsonObject(), "findings") as JsonArray ?? [])
            .Where(f => Js.PyEquals(Js.Get(f, "status"), JsonValue.Create("open")))
            .Select(f => Js.Str(f!["id"])).ToHashSet(StringComparer.Ordinal);
        foreach (var f in Js.Get(cur, "findings") as JsonArray ?? [])
        {
            var id = Js.Str(f!["id"]);
            if (!Js.PyEquals(Js.Get(f, "status"), JsonValue.Create("open")) || prevOpen.Contains(id))
            {
                continue;
            }
            if (ProtectionOff(id))
            {
                output.Add(Js.Str(f["title"]) + ".");
            }
        }
        if (prev is not null)
        {
            foreach (var f in diff.NewFindings)
            {
                var sev = Js.Str(Js.Get(f, "severity"));
                if (sev is "high" or "critical" && !ProtectionOff(Js.Str(f["id"])))
                {
                    output.Add($"New: {Js.Str(f["title"])}.");
                }
            }
        }
        foreach (var d in diff.NewDevices)
        {
            var label = Js.Truthy(Js.Get(d, "name")) ? Js.PyRepr(d["name"])
                : Js.Truthy(Js.Get(d, "vendor")) ? Js.PyRepr(d["vendor"]) : Js.PyRepr(Js.Get(d, "ip"));
            output.Add($"New device on your network: {label}.");
        }
        return output;
    }

    /// <summary><c>monitor --run</c>: scan, save, compare, notify. Returns an exit code.</summary>
    public static int RunOnce(ScanEngine engine, ILanHost? lan, Action<string, List<string>> notify)
    {
        var previous = engine.History.Latest(1);
        var prev = previous.Count > 0 ? previous[0] : null;
        var result = engine.Scan(save: false, kind: "monitor");
        if (lan is not null && LanScan.OwnedNetworks(engine.History).Count > 0)
        {
            try
            {
                LanScan.ScanNetwork(engine, lan, result);
            }
            catch (Exception exc)
            {
                result.Errors.Add($"home-network scan failed: {exc.Message}");
            }
        }
        engine.History.SaveScan(result, "monitor");
        var reasons = Triggers(prev, result.ToJson(includeFacts: false));
        if (reasons.Count > 0)
        {
            var title = reasons.Count > 1 ? "SimplySec: something changed" : "SimplySec";
            var lines = reasons.Take(2).ToList();
            if (reasons.Count > 2)
            {
                lines.Add($"…and {reasons.Count - 2} more. Open SimplySec for details.");
            }
            notify(title, lines);
        }
        return 0;
    }

    /// <summary>What the scheduled daily-check task runs, and at what time of day.</summary>
    public sealed record TaskAction(string Command, string Arguments, string Time);

    /// <summary>Read the program, arguments and time from the task's XML (<c>schtasks /Query /XML</c>).</summary>
    public static TaskAction? ParseTask(string? xml)
    {
        if (string.IsNullOrWhiteSpace(xml))
        {
            return null;
        }
        XDocument doc;
        try
        {
            doc = XDocument.Parse(xml.Trim().TrimStart((char)0xFEFF));
        }
        catch (XmlException)
        {
            return null;
        }
        XNamespace ns = "http://schemas.microsoft.com/windows/2004/02/mit/task";
        var exec = doc.Descendants(ns + "Exec").FirstOrDefault();
        if (exec is null)
        {
            return null;
        }
        var start = (string?)doc.Descendants(ns + "StartBoundary").FirstOrDefault() ?? "";
        var t = start.IndexOf('T', StringComparison.Ordinal);
        var time = t >= 0 && start.Length >= t + 6 ? start.Substring(t + 1, 5) : "";
        var command = ((string?)exec.Element(ns + "Command") ?? "").Trim().Trim('"');
        return new TaskAction(command, ((string?)exec.Element(ns + "Arguments") ?? "").Trim(), time);
    }

    /// <summary>
    /// True when the task runs something other than this copy of SimplySec: the Python v2 build, or
    /// a folder that was moved or replaced. Such a task stops working once the old folder is gone.
    /// </summary>
    public static bool PointsElsewhere(TaskAction task, string exe, string arguments)
    {
        static string Full(string path)
        {
            try
            {
                return Path.GetFullPath(path.Trim().Trim('"'));
            }
            catch (Exception e) when (e is ArgumentException or NotSupportedException or PathTooLongException)
            {
                return path;
            }
        }
        return !string.Equals(Full(task.Command), Full(exe), StringComparison.OrdinalIgnoreCase)
            || !string.Equals(task.Arguments, arguments.Trim(), StringComparison.Ordinal);
    }

    /// <summary>The daily-check task as Task Scheduler has it now (null: none, or it can't be read).</summary>
    public static TaskAction? CurrentTask(ScanEngine engine) =>
        engine.Adapters.Scheduler is { } sched ? ParseTask(sched.ExportXml(TaskName)) : null;

    public static ActionSpec ScheduleSpec(string time) => new("task.schedule",
        new JsonObject { ["name"] = TaskName, ["time"] = time },
        $"Create the scheduled task '{TaskName}' (daily at {time}, read-only).");

    public static ChangeRecord? ActiveChange(ScanEngine engine) =>
        engine.Journal.ActiveChanges().OrderByDescending(c => c.Id).FirstOrDefault(c => c.Kind == "task.schedule");

    /// <summary>Create (or move) the daily check. Journaled; needs admin.</summary>
    public static ApplyResult Enable(ScanEngine engine, string time)
    {
        var current = ActiveChange(engine);
        if (current is not null)
        {
            engine.Undo(changeIds: [current.Id]);
        }
        var fix = new FixDef { Id = "monitor.enable", Label = "Daily check", Description = "", MightBreak = "" };
        var plan = new Plan();
        plan.Items.Add(new PlannedFix { Fix = fix, Params = new JsonObject { ["time"] = time }, Specs = [ScheduleSpec(time)], Warnings = [] });
        var result = engine.Apply(plan);
        // v2 saved "on" even when the task could not be created, so Settings showed a check that never ran.
        if (result.Ok)
        {
            engine.History.SetSetting(Setting, new JsonObject { ["enabled"] = true, ["time"] = time });
        }
        return result;
    }

    /// <summary>Remove the daily check by undoing its journaled change (or delete a stray task).</summary>
    public static bool Disable(ScanEngine engine)
    {
        var current = ActiveChange(engine);
        var ok = true;
        if (current is not null)
        {
            ok = engine.Undo(changeIds: [current.Id]).All(o => o.Ok);
        }
        else if (engine.Adapters.Scheduler is { } sched && sched.Exists(TaskName))
        {
            sched.Delete(TaskName);
        }
        var settings = engine.History.GetSetting(Setting) as JsonObject ?? [];
        var updated = (JsonObject)settings.DeepClone();
        updated["enabled"] = false;
        engine.History.SetSetting(Setting, updated);
        return ok;
    }
}
