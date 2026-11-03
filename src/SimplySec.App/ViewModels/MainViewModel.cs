using System.Globalization;
using System.Text.Json.Nodes;
using CommunityToolkit.Mvvm.ComponentModel;
using Serilog;
using SimplySec.App.Infrastructure;
using SimplySec.Core.Checks;
using SimplySec.Core.Engine;
using SimplySec.Core.Lan;
using SimplySec.Core.Model;
using SimplySec.Core.Storage;

namespace SimplySec.App.ViewModels;

/// <summary>
/// Glue between the pages and the engine: scans, the fix flow, Keep and undo (port of
/// ui/controller.py).
///
/// As administrator, fixes and undo run in-process on a background thread. Otherwise the
/// confirmed selection is handed to one elevated <c>fix</c>/<c>undo</c> call (Windows shows a
/// UAC prompt); the elevated process re-derives the plan from a fresh scan and re-checks every
/// action against the allow-lists. Results are then read from the journal.
/// </summary>
public sealed partial class MainViewModel : ObservableObject
{
    private readonly IAppServices _services;
    private readonly BackgroundRunner _runner;

    public MainViewModel(IAppServices services, IDialogs dialogs, BackgroundRunner runner)
    {
        _services = services;
        Dialogs = dialogs;
        _runner = runner;
        Engine = services.CreateEngine();
    }

    public IDialogs Dialogs { get; }
    public IAppServices Services => _services;
    public ScanEngine Engine { get; }

    /// <summary>busy, text: a task started (true) or ended (false).</summary>
    public event Action<bool, string>? BusyChanged;
    public event Action<string>? Progress;
    public event Action<ScanResult>? ScanFinished;
    public event Action? ChangesUpdated;
    public event Action<string>? Error;

    [ObservableProperty]
    private bool _isBusy;

    /// <summary>Steps for the progress panel (0: unknown).</summary>
    public int TaskSteps { get; private set; }

    public ScanResult? Result { get; set; }

    /// <summary>The scan before <see cref="Result"/> (as saved in history), for "what changed".</summary>
    public JsonObject? Previous { get; set; }

    public bool IsAdmin => _services.IsAdmin;

    public Journal Journal() => new(_services.JournalPath, readOnly: !IsAdmin);

    private void SetBusy(bool busy, string text = "", int steps = 0)
    {
        IsBusy = busy;
        TaskSteps = steps;
        BusyChanged?.Invoke(busy, text);
    }

    private void Fail(string text) => Error?.Invoke(text);

    /// <summary>Show a result that came from somewhere else (e.g. --load-raw).</summary>
    public void Publish(ScanResult result)
    {
        Result = result;
        ScanFinished?.Invoke(result);
    }

    public Comparison? Comparison() =>
        Result is null ? null : History.Compare(Previous, Result.ToJson(includeFacts: false));

    // ------------------------------------------------------------------ scan

    public void StartScan(Action? then = null)
    {
        if (IsBusy)
        {
            return;
        }
        SetBusy(true, "Scanning this PC…", Core.Engine.Progress.ScanSteps);
        _runner.Run(
            progress =>
            {
                JsonObject? prev = null;
                try
                {
                    var latest = Engine.History.Latest(1);
                    prev = latest.Count > 0 ? latest[0] : null;
                }
                catch (Exception exc)
                {
                    Log.Warning("history unavailable: {Error}", exc.Message);
                }
                return (Engine.Scan(progress), prev);
            },
            onResult: value =>
            {
                (Result, Previous) = value;
                ScanFinished?.Invoke(Result);
                then?.Invoke();
            },
            onError: e => Fail($"The scan failed: {e}"),
            onProgress: t => Progress?.Invoke(t),
            onFinished: () => SetBusy(false));
    }

    /// <summary>Scan confirmed home networks and merge the devices into the current result.</summary>
    public void ScanNetwork(List<ScanTarget> targets, bool deep = false)
    {
        if (IsBusy || Result is null)
        {
            return;
        }
        SetBusy(true, "Scanning your network…", Core.Engine.Progress.NetworkStepsPerTarget * targets.Count);
        var current = Result;
        _runner.Run(
            progress =>
            {
                LanScan.ScanNetwork(Engine, _services.Lan(), current, targets, progress, deep);
                try
                {
                    Engine.History.SaveScan(current, kind: "network");
                }
                catch (Exception exc)
                {
                    Log.Warning("could not save network scan: {Error}", exc.Message);
                }
                return current;
            },
            onResult: Publish,
            onError: e => Fail($"The network scan failed: {e}"),
            onProgress: t => Progress?.Invoke(t),
            onFinished: () => SetBusy(false));
    }

    public void SetDailyCheck(bool enable, string time)
    {
        if (IsBusy)
        {
            return;
        }
        SetBusy(true, "Updating the daily check…");
        _runner.Run(
            _ =>
            {
                if (IsAdmin)
                {
                    if (enable)
                    {
                        return DailyCheck.Enable(Engine, time).Ok ? $"Daily check scheduled at {time}." : "Could not schedule the daily check.";
                    }
                    return DailyCheck.Disable(Engine) ? "Daily check removed." : "Could not remove the daily check.";
                }
                string[] argv = enable ? ["monitor", "--enable", time] : ["monitor", "--disable"];
                var (outcome, code) = _services.RunElevated(argv);
                if (outcome == ElevatedOutcome.Declined)
                {
                    return "Administrator permission was not given, so nothing changed.";
                }
                if (outcome == ElevatedOutcome.TimedOut)
                {
                    return "The administrator helper did not finish in time. Check the Changes page.";
                }
                if (code == 0)
                {
                    var settings = Engine.History.GetSetting(DailyCheck.Setting, new JsonObject()) as JsonObject ?? [];
                    var updated = (JsonObject)settings.DeepClone();
                    updated["enabled"] = enable;
                    updated["time"] = time;
                    Engine.History.SetSetting(DailyCheck.Setting, updated);
                }
                return code == 0 ? "Done." : $"Finished with problems (code {code}).";
            },
            onResult: message =>
            {
                ChangesUpdated?.Invoke();
                if (Result is not null)
                {
                    ScanFinished?.Invoke(Result);
                }
                Dialogs.Info("Daily check", message);
            },
            onError: e => Fail($"Could not change the daily check: {e}"),
            onProgress: t => Progress?.Invoke(t),
            onFinished: () => SetBusy(false));
    }

    // ------------------------------------------------------------------ keep

    public void Keep(Finding finding)
    {
        if (finding.KeepKey is null)
        {
            return;
        }
        Engine.History.Accept(finding.KeepKey, finding.Width, finding.Title);
        StartScan();
    }

    public void Unkeep(string key)
    {
        Engine.History.Unaccept(key);
        StartScan();
    }

    // ------------------------------------------------------------------ fixes

    public void RequestFix(Finding? finding, FixOption option)
    {
        if (option.GuidanceOnly)
        {
            OpenGuidance(option);
            return;
        }
        RequestFixes([new Selection(option.FixId, option.Params, finding?.Id)]);
    }

    public bool HasRecommended => Result is not null && Engine.Recommended(Result).Count > 0;

    public void RequestRecommended()
    {
        var (sels, skipped) = Engine.RecommendedSplit(Result);
        var notes = skipped.Select(s => $"Left out because it's in use right now: {s.Title} ({s.Why})").ToList();
        if (sels.Count == 0)
        {
            Dialogs.Info("Nothing to fix",
                "There are no recommended, non-disruptive fixes that are safe to apply together."
                + (notes.Count > 0 ? "\n\n" + string.Join("\n", notes) : ""));
            return;
        }
        RequestFixes(sels, notes);
    }

    private void OpenGuidance(FixOption option)
    {
        if (Registry.Fixes.TryGetValue(option.FixId, out var fix) && fix.Guidance is { } target)
        {
            try
            {
                _services.OpenSettings(target);
            }
            catch (Exception exc)
            {
                Fail($"Could not open Settings: {exc.Message}");
            }
        }
    }

    public void RequestFixes(List<Selection> selections, List<string>? notes = null)
    {
        if (IsBusy)
        {
            return;
        }
        var plan = Engine.Plan(selections);
        plan.Refused.AddRange(notes ?? []);
        if (plan.Items.Count == 0)
        {
            Dialogs.Warn("Can't apply", plan.Refused.Count > 0 ? string.Join("\n", plan.Refused) : "Nothing to apply.");
            return;
        }
        var findings = (Result?.Findings ?? []).GroupBy(f => f.Id, StringComparer.Ordinal).ToDictionary(g => g.Key, g => g.Last(), StringComparer.Ordinal);
        var choice = Dialogs.Preview(plan, IsAdmin, findings);
        if (!choice.Accepted || choice.Included.Count == 0)
        {
            return;
        }
        var kept = choice.Included.Select(i => (plan.Items[i].Fix.Id, plan.Items[i].FindingId)).ToHashSet();
        selections = selections.Where(s => kept.Contains((s.FixId, s.FindingId))).ToList();
        var extra = choice.Extra.Where(w => w.OfferFix is not null)
            .Select(w => new Selection(w.OfferFix!, (JsonObject)w.OfferParams.DeepClone())).ToList();
        if (extra.Count > 0)
        {
            selections = [.. extra, .. selections];
        }
        plan = Engine.Plan(selections);
        var before = Result;
        if (IsAdmin)
        {
            ApplyInProcess(plan, choice.RestorePoint, before);
        }
        else
        {
            ApplyElevated(selections, plan, choice.RestorePoint, choice.Extra, before);
        }
    }

    private void ApplyInProcess(Plan plan, bool restorePoint, ScanResult? before)
    {
        SetBusy(true, "Applying changes…");
        _runner.Run(
            progress =>
            {
                var res = Engine.Apply(plan, restorePoint, progress);
                var after = Engine.Scan(progress);
                return (res, after);
            },
            onResult: value =>
            {
                var (res, after) = value;
                var lines = res.Outcomes.Select(o => new ResultLine(o.Spec.Summary, o.Status, o.Verified, o.Error)).ToList();
                ShowResults(lines, plan, before, after, res.Warnings);
            },
            onError: e => Fail($"Applying failed: {e}"),
            onProgress: t => Progress?.Invoke(t),
            onFinished: () => SetBusy(false));
    }

    /// <summary>The elevated helper's command line for these selections.</summary>
    public static List<string> FixArgs(List<Selection> selections, bool restorePoint, IEnumerable<FixWarning> privateOffers)
    {
        var argv = new List<string> { "fix" };
        foreach (var sel in selections)
        {
            if (sel.FindingId is not null && !sel.FixId.StartsWith("network.", StringComparison.Ordinal))
            {
                argv.AddRange(["--select", $"{sel.FindingId}={sel.FixId}"]);
            }
        }
        // Only the networks the user ticked (v2 passed --mark-private, which applied every offer).
        foreach (var w in privateOffers)
        {
            if (w.OfferFix == "network.mark_private" && w.OfferParams["index"] is { } index)
            {
                argv.AddRange(["--private-network", index.ToJsonString()]);
            }
        }
        if (restorePoint)
        {
            argv.Add("--restore-point");
        }
        argv.Add("--yes");
        return argv;
    }

    private void ApplyElevated(List<Selection> selections, Plan plan, bool restorePoint, List<FixWarning> offers, ScanResult? before)
    {
        SetBusy(true, "Waiting for administrator permission…");
        var lastBatch = new Journal(_services.JournalPath, readOnly: true).Batches().Select(b => b.Id).DefaultIfEmpty(0).Max();
        var argv = FixArgs(selections, restorePoint, offers);
        _runner.Run(
            progress =>
            {
                var (outcome, code) = _services.RunElevated(argv);
                progress("Checking the result…");
                var changes = new Journal(_services.JournalPath, readOnly: true).Changes().Where(c => c.BatchId > lastBatch).ToList();
                var after = Engine.Scan(progress);
                return (outcome, code, changes, after);
            },
            onResult: value =>
            {
                var (outcome, code, changes, after) = value;
                if (outcome == ElevatedOutcome.Declined)
                {
                    Dialogs.Info("Nothing changed", "Administrator permission was not given, so nothing was changed.");
                    Publish(after);
                    return;
                }
                var lines = changes.Select(c => new ResultLine(c.Summary, c.Status, c.Verified, c.Error ?? "")).ToList();
                var warnings = new List<string>();
                // Exit code 1 also means "a finding is still present in the fresh scan", which the
                // result dialog already shows; only mention the code when a change itself failed.
                var allGood = lines.Count > 0 && lines.All(l => l.Status == "applied" && l.Verified == true);
                if (outcome == ElevatedOutcome.TimedOut)
                {
                    warnings.Add("The administrator helper did not finish in time.");
                }
                else if (code != 0 && !(code == 1 && allGood))
                {
                    warnings.Add($"The elevated helper finished with code {code}. Details are in {_services.LogDir}.");
                }
                if (lines.Count == 0)
                {
                    warnings.Add("No changes were recorded.");
                }
                ShowResults(lines, plan, before, after, warnings);
            },
            onError: e => Fail($"Applying failed: {e}"),
            onProgress: t => Progress?.Invoke(t),
            onFinished: () => SetBusy(false));
    }

    private void ShowResults(List<ResultLine> lines, Plan plan, ScanResult? before, ScanResult after, List<string> warnings)
    {
        var ids = plan.Items.Where(i => i.FindingId is not null).Select(i => i.FindingId!).ToList();
        var resolved = before is not null ? ScanEngine.Resolved(before, after, ids) : [];
        var titles = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var f in before?.Findings ?? [])
        {
            titles[f.Id] = f.Title;
        }
        Previous = before is not null ? before.ToJson(includeFacts: false) : Previous;
        Result = after;
        ScanFinished?.Invoke(after);
        ChangesUpdated?.Invoke();
        Dialogs.Results(new ResultSummary(lines, resolved, titles, before?.Score, after.Score, warnings));
    }

    // ------------------------------------------------------------------ undo

    public void Undo(List<long>? changeIds = null, long? batchId = null, bool everything = false, bool rules = false)
    {
        if (IsBusy)
        {
            return;
        }
        var what = everything ? "every change SimplySec made"
            : rules ? "all SimplySec firewall rules"
            : batchId is not null ? $"batch {batchId}"
            : $"{changeIds?.Count ?? 0} change(s)";
        if (!Dialogs.Ask("Undo", $"Undo {what}? The previous settings will be restored."))
        {
            return;
        }
        SetBusy(true, "Undoing…");
        _runner.Run(
            progress =>
            {
                var messages = new List<string>();
                if (IsAdmin)
                {
                    List<UndoOutcome> outcomes;
                    if (rules)
                    {
                        (outcomes, var leftovers) = Engine.RemoveAllRules();
                        messages.AddRange(leftovers.Select(n => $"Removed unrecorded SimplySec rule {n}"));
                    }
                    else
                    {
                        outcomes = Engine.Undo(changeIds, batchId, everything);
                    }
                    foreach (var o in outcomes)
                    {
                        messages.Add($"{(o.Ok ? "Restored" : "FAILED")}: {o.Change.Summary}" + (o.Error.Length > 0 ? $" ({o.Error})" : ""));
                    }
                }
                else
                {
                    var argv = new List<string> { "undo", "--yes" };
                    if (everything)
                    {
                        argv.Add("--all");
                    }
                    else if (rules)
                    {
                        argv.Add("--rules");
                    }
                    else if (batchId is not null)
                    {
                        argv.AddRange(["--batch", batchId.Value.ToString(CultureInfo.InvariantCulture)]);
                    }
                    else
                    {
                        argv.Add("--change");
                        argv.AddRange((changeIds ?? []).Select(c => c.ToString(CultureInfo.InvariantCulture)));
                    }
                    var (outcome, code) = _services.RunElevated(argv);
                    messages.Add(outcome switch
                    {
                        ElevatedOutcome.Declined => "Administrator permission was not given, so nothing was undone.",
                        ElevatedOutcome.TimedOut => "The administrator helper did not finish in time; see the Changes page.",
                        _ when code == 0 => "Undo finished.",
                        _ => $"Undo finished with problems (code {code}); see the Changes page.",
                    });
                }
                progress("Checking the result…");
                return (messages, Engine.Scan(progress));
            },
            onResult: value =>
            {
                var (messages, after) = value;
                Publish(after);
                ChangesUpdated?.Invoke();
                Dialogs.Info("Undo", messages.Count > 0 ? string.Join("\n", messages) : "Nothing to undo.");
            },
            onError: e => Fail(e.Contains("administrator", StringComparison.OrdinalIgnoreCase) ? e : $"Undo failed: {e}"),
            onProgress: t => Progress?.Invoke(t),
            onFinished: () => SetBusy(false));
    }
}
