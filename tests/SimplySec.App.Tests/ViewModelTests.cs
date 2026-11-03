using System.Text.Json.Nodes;
using SimplySec.App.Infrastructure;
using SimplySec.App.ViewModels;
using SimplySec.Core.Actions;
using SimplySec.Core.Checks;
using SimplySec.Core.Compat;
using SimplySec.Core.Engine;
using SimplySec.Core.Storage;
using SimplySec.Core.Tests.Support;

namespace SimplySec.App.Tests;

/// <summary>The main view model on fakes (port of ui/controller.py's behaviour and test_gui_smoke).</summary>
public sealed class ViewModelTests : IDisposable
{
    private const string RaPath = @"HKLM\SYSTEM\CurrentControlSet\Control\Remote Assistance";
    private readonly TempDir _tmp = new();
    private readonly PumpContext _ui = new();
    private readonly FakeDialogs _dialogs = new();

    public void Dispose() => _tmp.Dispose();

    private static RawScan Raw() => RawScan.FromJson(Golden.Fixture("this_pc_raw.json"));

    private ScanEngine Engine(Adapters adapters, bool admin) => new(new EngineOptions
    {
        Adapters = () => adapters,
        Journal = ro => new Journal(_tmp.File("data/simplysec.db"), ro),
        History = () => new History(_tmp.File("user/history.db")),
        Collector = _ => Raw(),
        IsAdmin = () => admin,
        BackupsDir = _tmp.File("backups"),
    });

    private (MainViewModel Vm, FakeServices Services, Adapters Adapters) Make(bool admin)
    {
        var (_, adapters) = TestEngines.Make(_tmp, admin, Raw());
        ((FakeRegistry)adapters.Registry).Values[(RaPath, "fAllowToGetHelp")] = ("REG_DWORD", 1);
        var services = new FakeServices(_tmp, Engine(adapters, admin), admin);
        var vm = new MainViewModel(services, _dialogs, new BackgroundRunner(_ui));
        return (vm, services, adapters);
    }

    private void Scan(MainViewModel vm)
    {
        ScanResult? got = null;
        vm.ScanFinished += r => got = r;
        vm.StartScan();
        _ui.PumpUntil(() => got is not null && !vm.IsBusy);
    }

    [Fact]
    public void ScanPublishesResultAndClearsBusy()
    {
        var (vm, _, _) = Make(admin: false);
        var events = new List<string>();
        vm.BusyChanged += (busy, text) => events.Add(busy ? $"busy {text}" : "idle");
        vm.ScanFinished += _ => events.Add("result");
        vm.StartScan();
        vm.StartScan(); // ignored while busy
        _ui.PumpUntil(() => events.Contains("result"));
        Assert.Equal(["busy Scanning this PC…", "idle", "result"], events);
        Assert.NotNull(vm.Result);
        Assert.Equal(Progress.ScanSteps, 7);
    }

    [Fact]
    public void FailedScanStillClearsBusy()
    {
        var (_, adapters) = TestEngines.Make(_tmp, false, Raw());
        var broken = new ScanEngine(new EngineOptions
        {
            Adapters = () => adapters,
            Journal = ro => new Journal(_tmp.File("data/simplysec.db"), ro),
            History = () => new History(_tmp.File("user/history.db")),
            Collector = _ => throw new InvalidOperationException("collector broke"),
        });
        var vm = new MainViewModel(new FakeServices(_tmp, broken, false), _dialogs, new BackgroundRunner(_ui));
        string? error = null;
        vm.Error += e => error = e;
        vm.StartScan();
        _ui.PumpUntil(() => error is not null);
        Assert.False(vm.IsBusy);
        Assert.Equal("The scan failed: collector broke", error);
    }

    [Fact]
    public void FixInProcessWhenAdmin()
    {
        var (vm, services, adapters) = Make(admin: true);
        Scan(vm);
        var finding = vm.Result!.Finding("rdp.remote_assistance_on")!;
        vm.RequestFix(finding, finding.Fixes.First(f => f.FixId == "rdp.remote_assistance_off"));
        _ui.PumpUntil(() => _dialogs.Summaries.Count == 1 && !vm.IsBusy);
        var summary = _dialogs.Summaries[0];
        var line = Assert.Single(summary.Lines);
        Assert.Equal(("applied", true), (line.Status, line.Verified));
        // The fixture doesn't change, so the fresh scan honestly still reports the finding.
        Assert.False(summary.Resolved["rdp.remote_assistance_on"]);
        Assert.Equal(0, Js.Long(((FakeRegistry)adapters.Registry).Values[(RaPath, "fAllowToGetHelp")].Value));
        Assert.Empty(services.Elevated);
    }

    [Fact]
    public void FixThroughElevatedHelperWhenNotAdmin()
    {
        var (vm, services, adapters) = Make(admin: false);
        services.ElevatedEngine = () => Engine(adapters, admin: true);
        Scan(vm);
        var finding = vm.Result!.Finding("rdp.remote_assistance_on")!;
        vm.RequestFix(finding, finding.Fixes.First(f => f.FixId == "rdp.remote_assistance_off"));
        _ui.PumpUntil(() => _dialogs.Summaries.Count == 1 && !vm.IsBusy);

        Assert.Equal(["fix", "--select", "rdp.remote_assistance_on=rdp.remote_assistance_off", "--yes"], Assert.Single(services.Elevated));
        var summary = _dialogs.Summaries[0];
        Assert.Equal(("applied", true), (Assert.Single(summary.Lines).Status, summary.Lines[0].Verified));
        // The helper exits with 1 only because the finding is still present in the fresh scan:
        // that is shown as "Still present", not as "finished with code 1" (a v2 quirk).
        Assert.DoesNotContain(summary.Warnings, w => w.Contains("code", StringComparison.Ordinal));
        Assert.Equal(0, Js.Long(((FakeRegistry)adapters.Registry).Values[(RaPath, "fAllowToGetHelp")].Value));
    }

    [Fact]
    public void DeclinedUacChangesNothing()
    {
        var (vm, services, _) = Make(admin: false);
        services.Outcome = ElevatedOutcome.Declined;
        Scan(vm);
        var finding = vm.Result!.Finding("rdp.remote_assistance_on")!;
        vm.RequestFix(finding, finding.Fixes[0]);
        _ui.PumpUntil(() => _dialogs.Shown.Any(s => s.StartsWith("info Nothing changed", StringComparison.Ordinal)) && !vm.IsBusy);
        Assert.Empty(_dialogs.Summaries);
    }

    [Fact]
    public void CancelledPreviewDoesNothing()
    {
        var (vm, services, _) = Make(admin: false);
        _dialogs.PreviewAnswer = () => new PreviewChoice(false, false, [], [0]);
        Scan(vm);
        var finding = vm.Result!.Finding("rdp.remote_assistance_on")!;
        vm.RequestFix(finding, finding.Fixes[0]);
        Assert.False(vm.IsBusy);
        Assert.Empty(services.Elevated);
    }

    [Fact]
    public void OnlyTickedNetworksAreMarkedPrivate()
    {
        FixWarning Offer(int index) => new()
        {
            Text = "public",
            OfferFix = "network.mark_private",
            OfferParams = new JsonObject { ["index"] = index, ["alias"] = $"if{index}", ["name"] = "Home" },
            OfferLabel = "Mark",
        };
        var argv = MainViewModel.FixArgs(
            [new Selection("network.mark_private", Offer(7).OfferParams, null), new Selection("exposure.block_program", new JsonObject(), "exposure.program:x.exe")],
            restorePoint: true,
            [Offer(7)]);
        Assert.Equal(["fix", "--select", "exposure.program:x.exe=exposure.block_program", "--private-network", "7", "--restore-point", "--yes"], argv);
    }

    [Fact]
    public void UndoEverythingThroughHelper()
    {
        var (vm, services, _) = Make(admin: false);
        Scan(vm);
        var changed = false;
        vm.ChangesUpdated += () => changed = true;
        vm.Undo(everything: true);
        _ui.PumpUntil(() => changed && !vm.IsBusy);
        Assert.Equal(["undo", "--yes", "--all"], Assert.Single(services.Elevated));
        Assert.Contains(_dialogs.Shown, s => s.StartsWith("ask Undo: Undo every change SimplySec made?", StringComparison.Ordinal));
        Assert.Contains(_dialogs.Shown, s => s == "info Undo: Undo finished.");
    }

    [Fact]
    public void UndoDeclinedAtTheQuestion()
    {
        var (vm, services, _) = Make(admin: false);
        _dialogs.AskAnswer = false;
        vm.Undo(changeIds: [1, 2]);
        Assert.False(vm.IsBusy);
        Assert.Empty(services.Elevated);
        Assert.Contains(_dialogs.Shown, s => s == "ask Undo: Undo 2 change(s)? The previous settings will be restored.");
    }

    [Fact]
    public void KeepRescansWithTheFindingAccepted()
    {
        var (vm, _, _) = Make(admin: false);
        Scan(vm);
        var finding = vm.Result!.Findings.First(f => f.KeepKey is not null && f.Scored);
        var rescanned = false;
        vm.ScanFinished += _ => rescanned = true;
        vm.Keep(finding);
        _ui.PumpUntil(() => rescanned && !vm.IsBusy);
        Assert.Equal(Core.Model.FindingStatus.Accepted, vm.Result!.Finding(finding.Id)!.Status);
    }

    [Fact]
    public void PreviewModelDefaultsAndOffers()
    {
        var (vm, _, _) = Make(admin: false);
        Scan(vm);
        var plan = vm.Engine.Plan([new Selection("exposure.block_program_public", new JsonObject { ["exe"] = @"C:\x\a.exe", ["label"] = "A" })]);
        var model = new PreviewModel(plan, isAdmin: false);
        Assert.True(model.Items[0].Included);
        Assert.NotEmpty(model.Items.SelectMany(i => i.Offers)); // "mark the network Private first"
        Assert.False(model.Choice(accepted: false).Accepted);
        Assert.Equal("Apply 1 change", model.ApplyText);
        Assert.EndsWith("Windows will ask for administrator permission to apply them.", model.Note, StringComparison.Ordinal);
        model.Items[0].Included = false;
        Assert.Equal("Nothing ticked", model.ApplyText);
    }
}
