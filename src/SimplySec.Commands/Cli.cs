using System.Diagnostics;
using System.Globalization;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Json.Nodes;
using SimplySec.Core;
using SimplySec.Core.Checks;
using SimplySec.Core.Compat;
using SimplySec.Core.Engine;
using SimplySec.Core.Lan;
using SimplySec.Core.Model;
using SimplySec.Core.Report;
using SimplySec.Core.Storage;
using SimplySec.Windows;

namespace SimplySec.Commands;

/// <summary>Everything the CLI needs from the outside world; tests replace it.</summary>
public sealed class CliHost
{
    public Func<ScanEngine> Engine { get; init; } = () => WindowsHost.CreateEngine();
    public Func<bool> IsAdmin { get; init; } = Elevation.IsAdmin;
    public Func<string?> ReadLine { get; init; } = Console.ReadLine;
    public TextWriter Out { get; init; } = Console.Out;
    public TextWriter Err { get; init; } = Console.Error;
    public Func<ILanHost> Lan { get; init; } = () => new WindowsLanHost();
    public Func<string, List<string>, bool> Notify { get; init; } = Toast.Show;
    public Func<IReadOnlyList<string>, (Elevation.ElevatedStatus, int)> RunElevated { get; init; } = a => Elevation.RunElevatedAndWait(a);
    public Func<string> JournalPath { get; init; } = () => Paths.JournalPath;
}

/// <summary>
/// The command-line interface (port of cli.py): same subcommands, flags, texts and exit codes.
/// </summary>
public sealed class Cli(CliHost host)
{
    public const int ExitOk = 0, ExitFail = 1, ExitUsage = 2, ExitNeedsAdmin = 3, ExitDeclined = 4;
    private const string Check = "✓", Cross = "✗";

    private static readonly Dictionary<string, string> SevMark = new(StringComparer.Ordinal)
    {
        ["critical"] = "!!", ["high"] = "! ", ["medium"] = "~ ", ["low"] = "- ", ["info"] = "  ",
    };

    private readonly Stopwatch _started = Stopwatch.StartNew();
    private string[] _argv = [];

    private void Out(string text = "") => host.Out.WriteLine(text);

    private void Progress(string text) =>
        host.Err.WriteLine(string.Create(CultureInfo.InvariantCulture, $"  [{_started.Elapsed.TotalSeconds,4:0}s] {text}"));

    // ------------------------------------------------------------------ parsing

    private sealed class Args
    {
        public string Command = "";
        public HashSet<string> Flags { get; } = new(StringComparer.Ordinal);
        public Dictionary<string, List<string>> Values { get; } = new(StringComparer.Ordinal);
        public List<string> Positional { get; } = [];

        public bool Has(string f) => Flags.Contains(f);
        public string? Value(string k) => Values.TryGetValue(k, out var v) && v.Count > 0 ? v[^1] : null;
        public List<string> All(string k) => Values.TryGetValue(k, out var v) ? v : [];
    }

    private static readonly Dictionary<string, (string[] Flags, string[] Single, string[] Multi, string[] Optional, int MaxPositional)> Spec = new(StringComparer.Ordinal)
    {
        ["scan"] = (["--json", "--facts", "--no-save", "--network", "--deep", "--yes", "--raw"], ["--from-raw"], [], [], 0),
        ["fix"] = (["--yes", "--restore-point", "--mark-private", "--elevate"], ["--finding", "--fix"], ["--select", "--private-network"], [], 1),
        ["keep"] = (["--undo"], ["--finding"], [], [], 0),
        ["undo"] = (["--all", "--rules", "--yes", "--elevate"], ["--batch"], ["--change"], [], 0),
        ["changes"] = ([], [], [], [], 0),
        ["history"] = ([], ["--limit"], [], [], 0),
        ["monitor"] = (["--run", "--disable", "--elevate", "--test-notification"], [], [], ["--enable"], 0),
        ["report"] = (["--html"], [], [], [], 1),
    };

    private const string Usage = "usage: simplysec [--version] [-v] {scan,fix,keep,undo,changes,history,monitor,report} ...";

    private Args? Parse(string[] argv, out string? error)
    {
        error = null;
        var a = new Args();
        var i = 0;
        while (i < argv.Length && argv[i].StartsWith('-'))
        {
            if (argv[i] is "-v" or "--verbose")
            {
                a.Flags.Add("--verbose");
            }
            else if (argv[i] == "--version")
            {
                a.Command = "--version";
                return a;
            }
            else
            {
                error = $"unrecognized arguments: {argv[i]}";
                return null;
            }
            i++;
        }
        if (i >= argv.Length)
        {
            return a;
        }
        a.Command = argv[i++];
        if (!Spec.TryGetValue(a.Command, out var spec))
        {
            error = $"argument command: invalid choice: '{a.Command}' (choose from {string.Join(", ", Spec.Keys.Select(k => $"'{k}'"))})";
            return null;
        }
        while (i < argv.Length)
        {
            var t = argv[i];
            if (spec.Flags.Contains(t))
            {
                a.Flags.Add(t);
                i++;
            }
            else if (spec.Single.Contains(t) || (spec.Multi.Contains(t) && t is "--select" or "--private-network"))
            {
                if (i + 1 >= argv.Length)
                {
                    error = $"argument {t}: expected one argument";
                    return null;
                }
                if (!a.Values.TryGetValue(t, out var list))
                {
                    list = [];
                    a.Values[t] = list;
                }
                list.Add(argv[i + 1]);
                i += 2;
            }
            else if (spec.Multi.Contains(t))
            {
                var list = new List<string>();
                i++;
                while (i < argv.Length && !argv[i].StartsWith("--", StringComparison.Ordinal))
                {
                    list.Add(argv[i++]);
                }
                if (list.Count == 0)
                {
                    error = $"argument {t}: expected at least one argument";
                    return null;
                }
                a.Values[t] = list;
            }
            else if (spec.Optional.Contains(t))
            {
                if (i + 1 < argv.Length && !argv[i + 1].StartsWith("--", StringComparison.Ordinal))
                {
                    a.Values[t] = [argv[i + 1]];
                    i += 2;
                }
                else
                {
                    a.Values[t] = ["12:00"];
                    i++;
                }
            }
            else if (!t.StartsWith('-') && a.Positional.Count < spec.MaxPositional)
            {
                a.Positional.Add(t);
                i++;
            }
            else
            {
                error = $"unrecognized arguments: {t}";
                return null;
            }
        }
        foreach (var k in new[] { "--batch", "--limit" })
        {
            if (a.Value(k) is { } v && !int.TryParse(v, NumberStyles.Integer, CultureInfo.InvariantCulture, out _))
            {
                error = $"argument {k}: invalid int value: '{v}'";
                return null;
            }
        }
        foreach (var k in new[] { "--change", "--private-network" })
        {
            foreach (var v in a.All(k))
            {
                if (!int.TryParse(v, NumberStyles.Integer, CultureInfo.InvariantCulture, out _))
                {
                    error = $"argument {k}: invalid int value: '{v}'";
                    return null;
                }
            }
        }
        if (a.Command == "keep" && a.Value("--finding") is null)
        {
            error = "the following arguments are required: --finding";
            return null;
        }
        return a;
    }

    public int Run(string[] argv)
    {
        _argv = argv;
        var a = Parse(argv, out var error);
        if (a is null)
        {
            host.Err.WriteLine(Usage);
            host.Err.WriteLine($"simplysec: error: {error}");
            return ExitUsage;
        }
        if (a.Command == "--version")
        {
            Out($"SimplySec {AppInfo.Version}");
            return ExitOk;
        }
        Logging.Setup(a.Has("--verbose"));
        if (a.Command.Length == 0)
        {
            Out(Usage);
            return ExitUsage;
        }
        try
        {
            return a.Command switch
            {
                "scan" => Scan(a),
                "fix" => Fix(a),
                "keep" => Keep(a),
                "undo" => UndoCmd(a),
                "changes" => Changes(),
                "history" => HistoryCmd(a),
                "monitor" => MonitorCmd(a),
                "report" => ReportCmd(a),
                _ => ExitUsage,
            };
        }
        catch (OperationCanceledException)
        {
            return ExitDeclined;
        }
    }

    // ------------------------------------------------------------------ scan

    public static readonly JsonSerializerOptions JsonOut = new()
    {
        WriteIndented = true,
        Encoder = JavaScriptEncoder.Default,
        IndentSize = 2,
    };

    private void PrintScan(ScanResult result)
    {
        Out($"SimplySec {result.Version} - {result.Computer} - {result.Started}");
        Out($"Risk score {result.Score}/100 (lower is better), grade {result.Grade}" + (result.IsAdmin ? "" : "  (read-only: not running as administrator)"));
        foreach (var line in result.NetworkStatus())
        {
            Out($"  {line}");
        }
        var counts = result.Counts();
        Out("Open findings: " + string.Join(", ", counts.Select(kv => $"{Js.PyRepr(kv.Value)} {kv.Key}")));
        Out();
        string? current = null;
        foreach (var f in result.Findings)
        {
            if (f.Area != current)
            {
                current = f.Area;
                Out($"[{current}]");
            }
            var status = f.Status == FindingStatus.Open ? "" : $" ({f.Status.Value()})";
            Out($" {SevMark[f.Severity.Key()]} {f.Severity.Label(),-8} {f.Title}{status}");
            Out($"      id: {f.Id}" + (f.Fixes.Count > 0 ? $"   fixes: {string.Join(", ", f.Fixes.Select(o => o.FixId))}" : ""));
        }
        Out();
        var reachable = result.Ports.Where(p => p.Verdict is Verdict.Reachable or Verdict.Uncertain).ToList();
        Out($"Ports other devices can reach ({reachable.Count} of {result.Ports.Count} listening):");
        foreach (var p in reachable)
        {
            var proc = p.Process.Length > 24 ? p.Process[..24] : p.Process;
            Out(string.Create(CultureInfo.InvariantCulture, $"  {PyStr.Upper(p.Protocol),-4}{p.Port,-6} {proc,-24} {p.Risk.Label(),-8} {p.ReachableFrom}"));
        }
        var devices = result.Extras["devices"] as JsonArray ?? [];
        if (devices.Count > 0)
        {
            Out();
            Out($"Devices on your network ({devices.Count}):");
            foreach (var d in devices)
            {
                var name = Js.Truthy(Js.Get(d, "name")) ? Js.Str(d!["name"]) : Js.Truthy(Js.Get(d, "vendor")) ? $"{Js.Str(d!["vendor"])} device" : "unknown";
                var ports = string.Join(",", (Js.Get(d, "open_ports") as JsonArray ?? []).Select(x => Js.PyRepr(x)));
                Out($"  {Js.Str(Js.Get(d, "ip")),-15} {Js.Str(Js.Get(d, "mac")),-17} {(name.Length > 40 ? name[..40] : name),-40} {ports}");
            }
        }
        if (result.Extras["router"] is JsonObject router && router.Count > 0)
        {
            var state = Js.Truthy(router["found"]) ? "UPnP on" : "UPnP not found";
            var forwards = (router["mappings"] as JsonArray)?.Count ?? 0;
            var ext = Js.Truthy(Js.Get(router, "external_ip")) ? Js.Str(router["external_ip"]) : "?";
            Out($"Router: {state}; external IP {ext}; {forwards} port forward(s)");
        }
        if (result.Errors.Count > 0)
        {
            Out();
            Out("Problems while scanning:");
            foreach (var e in result.Errors)
            {
                Out($"  {e}");
            }
        }
    }

    private bool Confirm(string prompt, bool assumeYes)
    {
        if (assumeYes)
        {
            return true;
        }
        host.Out.Write($"{prompt} [y/N] ");
        var answer = host.ReadLine();
        return answer is not null && PyStr.Lower(PyStr.Strip(answer)) is "y" or "yes";
    }

    private List<ScanTarget> ConfirmNetworks(ScanEngine engine, ScanResult result, bool assumeYes)
    {
        var targets = Discovery.ScanTargets(result.Interfaces);
        if (targets.Count == 0)
        {
            host.Err.WriteLine("No home network to scan (only VPN, virtual or public-address adapters).");
        }
        foreach (var t in targets)
        {
            if (LanScan.IsOwned(engine.History, t))
            {
                continue;
            }
            host.Err.WriteLine($"Is {t.Label} your network? SimplySec will look for devices on it and check which services they offer. Only scan networks you own or manage.");
            if (assumeYes || Confirm("This is my network, scan it", false))
            {
                LanScan.SetOwned(engine.History, t, true);
            }
        }
        return targets.Where(t => LanScan.IsOwned(engine.History, t)).ToList();
    }

    private int Scan(Args a)
    {
        var json = a.Has("--json") || a.Has("--raw");
        Action<string>? progress = json ? null : Progress;
        if (a.Value("--from-raw") is { } rawPath)
        {
            // Developer/parity aid: analyse a saved RawScan instead of collecting one.
            var raw = RawScan.FromJson(JsonNode.Parse(File.ReadAllText(rawPath))!);
            var analysed = Analysis.Analyze(raw);
            host.Out.WriteLine(analysed.ToJson(includeFacts: a.Has("--facts")).ToJsonString(JsonOut));
            return ExitOk;
        }
        var engine = host.Engine();
        if (a.Has("--raw"))
        {
            host.Out.WriteLine(engine.Collect().ToJson().ToJsonString(JsonOut));
            return ExitOk;
        }
        var result = engine.Scan(progress, save: !a.Has("--no-save") && !a.Has("--network"));
        if (a.Has("--network"))
        {
            var targets = ConfirmNetworks(engine, result, a.Has("--yes"));
            if (targets.Count > 0)
            {
                try
                {
                    LanScan.ScanNetwork(engine, host.Lan(), result, targets, progress, a.Has("--deep"));
                }
                catch (Exception exc)
                {
                    result.Errors.Add($"home-network scan failed: {exc.Message}");
                }
            }
            if (!a.Has("--no-save"))
            {
                engine.History.SaveScan(result, "network");
            }
        }
        if (json)
        {
            host.Out.WriteLine(result.ToJson(includeFacts: a.Has("--facts")).ToJsonString(JsonOut));
        }
        else
        {
            PrintScan(result);
        }
        return ExitOk;
    }

    // ------------------------------------------------------------------ fix / keep

    private int RelaunchElevated()
    {
        var argv = _argv.Where(x => x != "--elevate").ToList();
        if (!argv.Contains("--yes"))
        {
            argv.Add("--yes");
        }
        var (status, code) = host.RunElevated(argv);
        return status switch
        {
            Elevation.ElevatedStatus.Declined => ExitDeclined,
            Elevation.ElevatedStatus.TimedOut => ExitFail,
            _ => code,
        };
    }

    private int Fix(Args a)
    {
        if (!host.IsAdmin())
        {
            Out("Applying fixes needs administrator rights. Run this from an elevated prompt,");
            Out("or add --elevate to relaunch with a UAC prompt.");
            return a.Has("--elevate") ? RelaunchElevated() : ExitNeedsAdmin;
        }
        var engine = host.Engine();
        var before = engine.Scan(Progress, save: false);
        var selections = new List<Selection>();
        if (a.Positional.FirstOrDefault() == "recommended")
        {
            var (sels, skipped) = engine.RecommendedSplit(before);
            foreach (var (title, why) in skipped)
            {
                Out($"Left out because it's in use right now: {title} ({why})");
            }
            if (sels.Count == 0)
            {
                Out("Nothing to fix: no open findings have a recommended, non-disruptive fix.");
                return ExitOk;
            }
            selections = sels;
        }
        else
        {
            var pairs = new List<string>(a.All("--select"));
            if (a.Value("--finding") is not null || a.Value("--fix") is not null)
            {
                if (a.Value("--finding") is null || a.Value("--fix") is null)
                {
                    Out("Give both --finding ID and --fix FIX_ID.");
                    return ExitUsage;
                }
                pairs.Add($"{a.Value("--finding")}={a.Value("--fix")}");
            }
            if (pairs.Count == 0)
            {
                Out("Give 'recommended', --finding ID --fix FIX_ID, or --select ID=FIX_ID (see 'simplysec scan').");
                return ExitUsage;
            }
            foreach (var pair in pairs)
            {
                var eq = pair.LastIndexOf('=');
                var findingId = eq >= 0 ? pair[..eq] : "";
                var fixId = eq >= 0 ? pair[(eq + 1)..] : pair;
                var f = before.Finding(findingId);
                if (f is null)
                {
                    Out($"No finding '{findingId}' in a fresh scan (already resolved?).");
                    return ExitFail;
                }
                var opt = f.Fixes.FirstOrDefault(o => o.FixId == fixId);
                if (opt is null)
                {
                    var offers = f.Fixes.Count > 0 ? string.Join(", ", f.Fixes.Select(o => o.FixId)) : "no fixes";
                    Out($"Finding {findingId} offers: {offers}");
                    return ExitUsage;
                }
                selections.Add(new Selection(opt.FixId, opt.Params, f.Id));
            }
            // --mark-private: every offered "mark this network Private first"; --private-network N:
            // only the offer for interface index N (the GUI passes exactly the ticked ones).
            var privateNets = a.All("--private-network").Select(v => long.Parse(v, CultureInfo.InvariantCulture)).ToHashSet();
            if (a.Has("--mark-private") || privateNets.Count > 0)
            {
                var extra = new List<Selection>();
                foreach (var item in engine.Plan(selections).Items)
                {
                    foreach (var w in item.Warnings)
                    {
                        var wanted = a.Has("--mark-private")
                            || (w.OfferFix == "network.mark_private" && privateNets.Contains(Js.Long(w.OfferParams["index"])));
                        if (wanted && w.OfferFix is not null && extra.All(s => !Js.PyEquals(s.Params, w.OfferParams)))
                        {
                            extra.Add(new Selection(w.OfferFix, (JsonObject)w.OfferParams.DeepClone()));
                        }
                    }
                }
                selections = [.. extra, .. selections];
            }
        }
        var plan = engine.Plan(selections);
        foreach (var r in plan.Refused)
        {
            Out($"Refused: {r}");
        }
        if (plan.Items.Count == 0)
        {
            return ExitFail;
        }
        Out("SimplySec will make these changes:");
        foreach (var item in plan.Items)
        {
            Out($"  {item.Fix.Label}");
            foreach (var s in item.Specs)
            {
                Out($"    - {s.Summary}");
            }
            if (item.Impact is not null)
            {
                Out($"    What uses this: {Impact.Label(item.Impact.Level)} - {item.Impact.Headline}");
                foreach (var e in item.Impact.Evidence.Take(8))
                {
                    Out($"      * {e}");
                }
            }
            foreach (var w in item.Warnings)
            {
                Out($"    ! {w.Text}");
                if (w.OfferFix is not null)
                {
                    Out("      (add --mark-private to do that first)");
                }
            }
        }
        Out("What might stop working:");
        foreach (var line in plan.MightBreak)
        {
            Out($"  - {line}");
        }
        Out("Every change is recorded and can be undone with 'simplysec undo'.");
        if (!Confirm("Apply these changes?", a.Has("--yes")))
        {
            Out("Nothing changed.");
            return ExitDeclined;
        }
        ApplyResult result;
        try
        {
            result = engine.Apply(plan, a.Has("--restore-point"), Progress);
        }
        catch (NeedsAdminException exc)
        {
            Out(exc.Message);
            return ExitNeedsAdmin;
        }
        foreach (var w in result.Warnings)
        {
            Out($"Warning: {w}");
        }
        var after = engine.Scan(Progress, save: true);
        var resolved = ScanEngine.Resolved(before, after, plan.Items.Where(i => i.FindingId is not null).Select(i => i.FindingId!));
        Out();
        Out($"Batch {result.BatchId}" + (result.Backup is not null ? $", firewall backup: {result.Backup}" : ""));
        var ok = true;
        foreach (var o in result.Outcomes)
        {
            var good = o.Status == "applied" && o.Verified == true;
            ok &= good;
            Out($"  [{(good ? $"Verified {Check}" : Cross)}] #{(o.ChangeId is null ? "None" : o.ChangeId.Value.ToString(CultureInfo.InvariantCulture))} {o.Spec.Summary}" + (o.Error.Length > 0 ? $"  ({o.Error})" : ""));
        }
        foreach (var (fid, gone) in resolved)
        {
            Out($"  Finding {fid}: {(gone ? "resolved in a fresh scan" : "STILL PRESENT in a fresh scan")}");
            ok &= gone;
        }
        Out($"Risk score {before.Score} -> {after.Score}");
        return ok ? ExitOk : ExitFail;
    }

    private int Keep(Args a)
    {
        var engine = host.Engine();
        var result = engine.Scan(Progress, save: false);
        var f = result.Finding(a.Value("--finding")!);
        if (f is null || string.IsNullOrEmpty(f.KeepKey))
        {
            Out("That finding doesn't offer 'Keep'.");
            return ExitUsage;
        }
        if (a.Has("--undo"))
        {
            engine.History.Unaccept(f.KeepKey);
            Out($"'{f.Title}' will be scored again.");
        }
        else
        {
            engine.History.Accept(f.KeepKey, f.Width, f.Title);
            Out($"Kept: '{f.Title}'. It is shown but not scored, and comes back only if it gets wider.");
        }
        return ExitOk;
    }

    // ------------------------------------------------------------------ undo / changes

    private int Changes()
    {
        var journal = new Journal(host.JournalPath(), readOnly: true);
        var batches = journal.Batches().ToDictionary(b => b.Id);
        var changes = journal.Changes();
        if (changes.Count == 0)
        {
            Out("SimplySec has not changed anything on this PC.");
            return ExitOk;
        }
        long? current = null;
        foreach (var c in changes)
        {
            if (c.BatchId != current)
            {
                current = c.BatchId;
                batches.TryGetValue(c.BatchId, out var b);
                Out($"Batch {c.BatchId} - {b?.Created ?? ""} - {b?.Title ?? ""}");
                if (!string.IsNullOrEmpty(b?.Backup))
                {
                    Out($"  firewall backup: {b.Backup}");
                }
            }
            var v = c.Verified switch { true => "verified", false => "NOT verified", null => "" };
            Out(string.Create(CultureInfo.InvariantCulture, $"  #{c.Id,-4} {c.Status,-13} {v,-12} {c.Summary}"));
            if (!string.IsNullOrEmpty(c.Error))
            {
                Out($"         error: {c.Error}");
            }
        }
        return ExitOk;
    }

    private int UndoCmd(Args a)
    {
        if (!host.IsAdmin())
        {
            Out("Undo needs administrator rights. Run this from an elevated prompt (or add --elevate).");
            return a.Has("--elevate") ? RelaunchElevated() : ExitNeedsAdmin;
        }
        var engine = host.Engine();
        var changes = a.All("--change").Select(x => long.Parse(x, CultureInfo.InvariantCulture)).ToList();
        long? batch = a.Value("--batch") is { } b ? long.Parse(b, CultureInfo.InvariantCulture) : null;
        if (!(a.Has("--all") || batch is not null || changes.Count > 0 || a.Has("--rules")))
        {
            Out("Choose --change N, --batch N, --all or --rules.");
            return ExitUsage;
        }
        var what = a.Has("--all") ? "every change SimplySec made"
            : a.Has("--rules") ? "all SimplySec firewall rules"
            : batch is not null ? $"batch {batch}"
            : $"change(s) {string.Join(", ", changes)}";
        if (!Confirm($"Undo {what}?", a.Has("--yes")))
        {
            return ExitDeclined;
        }
        List<UndoOutcome> outcomes;
        try
        {
            if (a.Has("--rules"))
            {
                var (o, leftovers) = engine.RemoveAllRules();
                foreach (var name in leftovers)
                {
                    Out($"  removed unjournaled SimplySec rule {name}");
                }
                outcomes = o;
            }
            else
            {
                outcomes = engine.Undo(changes.Count > 0 ? changes : null, batch, a.Has("--all"));
            }
        }
        catch (NeedsAdminException exc)
        {
            Out(exc.Message);
            return ExitNeedsAdmin;
        }
        if (outcomes.Count == 0)
        {
            Out("Nothing to undo.");
        }
        var ok = true;
        foreach (var o in outcomes)
        {
            Out($"  [{(o.Ok ? Check : Cross)}] #{o.Change.Id} {o.Change.Summary}" + (o.Error.Length > 0 ? $" ({o.Error})" : ""));
            ok &= o.Ok;
        }
        return ok ? ExitOk : ExitFail;
    }

    // ------------------------------------------------------------------ history / report / monitor

    private int HistoryCmd(Args a)
    {
        var engine = host.Engine();
        var limit = a.Value("--limit") is { } l ? int.Parse(l, CultureInfo.InvariantCulture) : 30;
        var scans = engine.History.Scans(limit);
        if (scans.Count == 0)
        {
            Out("No scans saved yet.");
            return ExitOk;
        }
        foreach (var s in scans)
        {
            var data = engine.History.ScanData(s.Id);
            var prev = engine.History.PreviousTo(s.Id);
            var diff = data is not null ? History.Compare(prev, data) : null;
            var extra = diff is not null && !diff.Empty
                ? string.Create(CultureInfo.InvariantCulture, $"  ({diff.ScoreChange:+0;-0;+0}; {diff.NewFindings.Count} new, {diff.ResolvedFindings.Count} resolved)")
                : "";
            Out(string.Create(CultureInfo.InvariantCulture, $"#{s.Id,-5} {s.Ts}  {s.Kind,-8} {s.Score,3} {s.Grade}{extra}"));
        }
        return ExitOk;
    }

    private int MonitorCmd(Args a)
    {
        if (a.Has("--run"))
        {
            return DailyCheck.RunOnce(host.Engine(), host.Lan(), (t, l) => host.Notify(t, l));
        }
        if (a.Has("--test-notification"))
        {
            // Hidden: show what a daily-check notification looks like.
            var shown = host.Notify("SimplySec: test notification", ["This is how the daily check tells you that something got worse."]);
            Out(shown ? "Notification shown." : "Could not show a notification (see the log).");
            return shown ? ExitOk : ExitFail;
        }
        var enable = a.Value("--enable");
        if (enable is not null || a.Has("--disable"))
        {
            if (!host.IsAdmin())
            {
                if (a.Has("--elevate"))
                {
                    return RelaunchElevated();
                }
                Out("Turning the daily check on or off needs administrator rights (add --elevate).");
                return ExitNeedsAdmin;
            }
            var engine = host.Engine();
            if (enable is not null)
            {
                var ok = DailyCheck.Enable(engine, enable).Ok;
                Out(ok ? "Daily check scheduled at " + enable : "Could not schedule the daily check; see 'simplysec changes'.");
                return ok ? ExitOk : ExitFail;
            }
            var removed = DailyCheck.Disable(engine);
            Out(removed ? "Daily check removed." : "Could not remove the daily check; see 'simplysec changes'.");
            return removed ? ExitOk : ExitFail;
        }
        Out("Use --run, --enable [HH:MM] or --disable.");
        return ExitUsage;
    }

    private int ReportCmd(Args a)
    {
        var engine = host.Engine();
        var result = engine.Scan(Progress, save: true);
        var path = a.Positional.FirstOrDefault() ?? Path.Combine(Directory.GetCurrentDirectory(), $"SimplySec-report-{(result.Started.Length >= 10 ? result.Started[..10] : result.Started)}.html");
        WriteReport(path, result, engine, host.JournalPath());
        Out($"Report written to {path}");
        return ExitOk;
    }

    public static void WriteReport(string path, ScanResult result, ScanEngine engine, string journalPath)
    {
        List<JsonObject> changes = [];
        List<JsonObject> accepted = [];
        List<(string, int)> trend = [];
        try
        {
            changes = new Journal(journalPath, readOnly: true).Changes().Select(c => c.ToJson()).ToList();
        }
        catch (Exception)
        {
        }
        try
        {
            accepted = engine.History.Accepted();
            trend = engine.History.Scans(30).AsEnumerable().Reverse().Select(s => (s.Ts.Length >= 10 ? s.Ts[..10] : s.Ts, s.Score)).ToList();
        }
        catch (Exception)
        {
        }
        var full = Path.GetFullPath(path);
        Directory.CreateDirectory(Path.GetDirectoryName(full)!);
        File.WriteAllText(full, HtmlReport.Render(result, changes, accepted, trend), new System.Text.UTF8Encoding(false));
    }
}
