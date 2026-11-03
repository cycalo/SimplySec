using System.Text.Json.Nodes;
using SimplySec.Core.Actions;
using SimplySec.Core.Checks;
using SimplySec.Core.Compat;
using SimplySec.Core.Model;
using SimplySec.Core.Storage;

namespace SimplySec.Core.Engine;

public sealed class NeedsAdminException(string message) : UnauthorizedAccessException(message);

public sealed record ChangeOutcome(
    ActionSpec Spec, long? ChangeId, string Status, bool? Verified, string Error = "", string? FixId = null, string? FindingId = null);

public sealed class ApplyResult
{
    public long? BatchId { get; init; }
    public string? Backup { get; set; }
    public List<ChangeOutcome> Outcomes { get; } = [];
    public List<string> Warnings { get; } = [];
    public bool Ok => Outcomes.All(o => o.Status == "applied" && o.Verified == true);
}

public sealed record UndoOutcome(ChangeRecord Change, bool Ok, string Error = "");

/// <summary>A progress callback: plain strings; "✓ " marks a finished step.</summary>
public static class Progress
{
    public const string Done = "✓ ";
    public const int ScanSteps = 7;
    public const int NetworkStepsPerTarget = 4;

    public static string MarkDone(string text) => Done + text;

    public static bool IsDone(string text) => text.StartsWith(Done, StringComparison.Ordinal);
}

/// <summary>Everything the engine needs from the host; SimplySec.Windows provides the real ones.</summary>
public sealed class EngineOptions
{
    public Func<Adapters>? Adapters { get; init; }
    public Func<bool, Journal>? Journal { get; init; }
    public Func<History>? History { get; init; }
    public Func<Action<string>?, RawScan>? Collector { get; init; }
    public Func<bool> IsAdmin { get; init; } = () => false;
    public string BackupsDir { get; init; } = "";
    /// <summary>Called before an elevated process opens the journal (hardens the data folder ACL).</summary>
    public Action? PrepareDataDir { get; init; }
    /// <summary>File existence for "leftover rule" findings; null means "exists".</summary>
    public Func<string, bool>? FileExists { get; init; }
    public string UserName { get; init; } = Environment.UserName;
}

/// <summary>Scan, preview, apply, verify and undo.</summary>
public sealed class ScanEngine(EngineOptions options)
{
    private Adapters? _adapters;
    private Journal? _journal;
    private History? _history;

    public RawScan? LastRaw { get; private set; }
    public ScanContext? LastContext { get; private set; }
    public ScanResult? LastResult { get; private set; }
    public string BackupsDir => options.BackupsDir;

    public Adapters Adapters => _adapters ??= (options.Adapters ?? throw new InvalidOperationException("no adapters"))();

    public Journal Journal
    {
        get
        {
            if (_journal is null)
            {
                var admin = IsAdmin;
                if (admin)
                {
                    options.PrepareDataDir?.Invoke();
                }
                _journal = (options.Journal ?? throw new InvalidOperationException("no journal"))(!admin);
            }
            return _journal;
        }
    }

    public History History => _history ??= (options.History ?? throw new InvalidOperationException("no history"))();

    public bool IsAdmin => options.IsAdmin();

    public void SetLast(RawScan raw, ScanResult result, ScanContext ctx)
    {
        LastRaw = raw;
        LastResult = result;
        LastContext = ctx;
    }

    // ------------------------------------------------------------------ scan

    public RawScan Collect(Action<string>? progress = null) =>
        (options.Collector ?? throw new InvalidOperationException("no collector"))(progress);

    public ScanResult Scan(Action<string>? progress = null, bool save = true, string kind = "manual")
    {
        var raw = Collect(progress);
        progress?.Invoke("Working out what other devices can reach and checking settings…");
        var accepted = new Dictionary<string, int>(StringComparer.Ordinal);
        try
        {
            accepted = History.AcceptedWidths();
        }
        catch (Exception)
        {
        }
        var (result, ctx) = Analysis.AnalyzeWithContext(raw, accepted: accepted, fileExists: options.FileExists);
        SetLast(raw, result, ctx);
        progress?.Invoke(Progress.MarkDone($"Analysed: {result.OpenFindings.Count} things to look at"));
        if (save)
        {
            try
            {
                History.SaveScan(result, kind);
            }
            catch (Exception exc)
            {
                result.Errors.Add($"history not saved: {exc.Message}");
            }
        }
        return result;
    }

    // ------------------------------------------------------------------ fixes

    public Plan Plan(List<Selection> selections) => Analysis.BuildPlan(selections, LastContext);

    public List<Selection> Recommended(ScanResult? result = null) => RecommendedSplit(result).Selections;

    public (List<Selection> Selections, List<(string Title, string Why)> Skipped) RecommendedSplit(ScanResult? result = null) =>
        Analysis.RecommendedSplit(result ?? LastResult);

    public ApplyResult Apply(Plan plan, bool restorePoint = false, Action<string>? progress = null)
    {
        if (!IsAdmin)
        {
            throw new NeedsAdminException("Applying fixes needs administrator rights.");
        }
        var journal = Journal;
        var a = Adapters;
        var titles = plan.Items.Count > 0 ? string.Join(", ", plan.Items.Select(i => i.Fix.Label)) : "no changes";
        var batch = journal.BeginBatch(CheckHelpers.Truncate(titles, 300), plan.Items.Select(i => i.Fix.Id).ToList(), options.UserName);
        var result = new ApplyResult { BatchId = batch };
        if (plan.TouchesFirewall)
        {
            progress?.Invoke("Backing up the firewall…");
            try
            {
                var backup = a.Firewall.ExportPolicy(options.BackupsDir);
                result.Backup = backup;
                journal.SetBackup(batch, backup);
            }
            catch (Exception exc)
            {
                result.Warnings.Add($"Firewall backup failed: {exc.Message}");
            }
        }
        if (restorePoint)
        {
            progress?.Invoke("Creating a System Restore point…");
            try
            {
                a.System.CreateRestorePoint("SimplySec changes");
            }
            catch (Exception exc)
            {
                result.Warnings.Add($"Restore point not created: {exc.Message}");
            }
        }
        var seq = 0;
        foreach (var item in plan.Items)
        {
            foreach (var spec in item.Specs)
            {
                seq += 1;
                progress?.Invoke(spec.Summary);
                result.Outcomes.Add(ApplyOne(batch, seq, spec, item.Fix.Id, item.FindingId));
            }
        }
        return result;
    }

    private ChangeOutcome ApplyOne(long batch, int seq, ActionSpec spec, string fixId, string? findingId)
    {
        var journal = Journal;
        var a = Adapters;
        if (!Primitives.All.TryGetValue(spec.Kind, out var prim) || !Registry.SpecAllowed(spec))
        {
            return new ChangeOutcome(spec, null, "refused", null, "not on the allow-list", fixId, findingId);
        }
        JsonObject before;
        try
        {
            before = prim.Snapshot(a, spec.Params);
        }
        catch (Exception exc)
        {
            return new ChangeOutcome(spec, null, "failed", null, $"could not read the current state: {exc.Message}", fixId, findingId);
        }
        var cid = journal.AddChange(batch, seq, spec, before, fixId, findingId);
        try
        {
            prim.Apply(a, spec.Params, before);
        }
        catch (Exception exc)
        {
            journal.MarkFailed(cid, exc.Message);
            // A partial apply may have changed something: try to restore the before-state.
            try
            {
                prim.Revert(a, spec.Params, before);
            }
            catch (Exception)
            {
            }
            return new ChangeOutcome(spec, cid, "failed", null, exc.Message, fixId, findingId);
        }
        journal.MarkApplied(cid);
        bool ok;
        try
        {
            ok = prim.Verify(a, spec.Params);
        }
        catch (Exception)
        {
            ok = false;
        }
        journal.SetVerified(cid, ok);
        return new ChangeOutcome(spec, cid, "applied", ok, "", fixId, findingId);
    }

    /// <summary>Per finding: is it gone (or no longer scored, or less severe) in a fresh scan?</summary>
    public static Dictionary<string, bool> Resolved(ScanResult before, ScanResult after, IEnumerable<string> findingIds)
    {
        var output = new Dictionary<string, bool>(StringComparer.Ordinal);
        foreach (var fid in findingIds)
        {
            var old = before.Finding(fid);
            var nw = after.Finding(fid);
            output[fid] = nw is null || !nw.Scored || (old is not null && nw.Severity < old.Severity);
        }
        return output;
    }

    // ------------------------------------------------------------------ undo

    public List<UndoOutcome> Undo(List<long>? changeIds = null, long? batchId = null, bool everything = false)
    {
        if (!IsAdmin)
        {
            throw new NeedsAdminException("Undoing changes needs administrator rights.");
        }
        var journal = Journal;
        List<ChangeRecord> todo;
        if (everything)
        {
            todo = journal.ActiveChanges();
        }
        else if (batchId is not null)
        {
            todo = journal.Changes(batchId).Where(c => c.Status is Journal.Applied or Journal.RevertFailed).ToList();
        }
        else
        {
            todo = (changeIds ?? []).Select(journal.Change).Where(c => c is not null && c.Status is Journal.Applied or Journal.RevertFailed).Select(c => c!).ToList();
        }
        return todo.OrderByDescending(c => c.Id).Select(UndoOne).ToList();
    }

    private UndoOutcome UndoOne(ChangeRecord change)
    {
        var journal = Journal;
        var a = Adapters;
        if (!Primitives.All.TryGetValue(change.Kind, out var prim) || !Registry.IsAllowed(change.Kind, change.Params))
        {
            const string msg = "refused: this change is not on SimplySec's allow-list (journal may have been altered)";
            journal.MarkRevertFailed(change.Id, msg);
            return new UndoOutcome(change, false, msg);
        }
        var before = change.Before ?? [];
        if (!prim.BeforeOk(change.Params, before))
        {
            const string msg = "refused: the stored before-state does not look like something SimplySec saved";
            journal.MarkRevertFailed(change.Id, msg);
            return new UndoOutcome(change, false, msg);
        }
        bool ok;
        try
        {
            prim.Revert(a, change.Params, before);
            ok = prim.VerifyReverted(a, change.Params, before);
        }
        catch (Exception exc)
        {
            journal.MarkRevertFailed(change.Id, exc.Message);
            return new UndoOutcome(change, false, exc.Message);
        }
        if (ok)
        {
            journal.MarkReverted(change.Id);
            return new UndoOutcome(change, true);
        }
        const string notConfirmed = "the original state could not be confirmed after undo";
        journal.MarkRevertFailed(change.Id, notConfirmed);
        return new UndoOutcome(change, false, notConfirmed);
    }

    /// <summary>Undo every journaled firewall rule, then delete anything left in the SimplySec group.</summary>
    public (List<UndoOutcome> Outcomes, List<string> Leftovers) RemoveAllRules()
    {
        var outcomes = Journal.ActiveChanges().OrderByDescending(c => c.Id)
            .Where(c => c.Kind == "firewall.add_rule").Select(UndoOne).ToList();
        var leftovers = new List<string>();
        foreach (var rule in Adapters.Firewall.GroupRules())
        {
            Adapters.Firewall.RemoveRulesNamed(rule.Name);
            leftovers.Add(rule.Name);
        }
        return (outcomes, leftovers);
    }
}
