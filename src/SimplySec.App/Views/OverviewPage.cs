using System.Windows;
using System.Windows.Controls;
using System.Windows.Controls.Primitives;
using SimplySec.App.Controls;
using SimplySec.App.Theme;
using SimplySec.App.ViewModels;
using SimplySec.Core.Compat;
using SimplySec.Core.Engine;
using SimplySec.Core.Model;
using static SimplySec.App.Theme.Ui;

namespace SimplySec.App.Views;

/// <summary>Score ring, Scan &amp; Protect, counts, top fixes, network status, what changed.</summary>
public sealed class OverviewPage : PageView
{
    public ScoreRing Ring { get; } = new();
    private readonly TextBlock _headline = Text("Run a scan to see how this PC is doing.", TextStyle.SectionTitle);
    private readonly TextBlock _sub = Text("The scan is read-only: nothing changes until you choose a fix and confirm it.", TextStyle.Dim);
    private string _idleSub;
    private readonly UniformGrid _counts = new() { Rows = 1, HorizontalAlignment = HorizontalAlignment.Left };
    private readonly Wpf.Ui.Controls.Button _scan;
    private readonly Wpf.Ui.Controls.Button _fix;
    private readonly StackPanel _network = VStack(6);
    private readonly Border _networkCard;
    private readonly StackPanel _top = VStack(10);
    private readonly TextBlock _changesTitle = Text("What changed since the last scan", TextStyle.SectionTitle);
    private readonly StackPanel _changes = VStack(4);
    private readonly Border _changesCard;

    public OverviewPage(MainViewModel vm) : base(vm, "Overview", "What other devices can reach on this PC, and how to make it safer.")
    {
        _idleSub = _sub.Text;
        var right = VStack(8);
        right.Children.Add(_headline);
        right.Children.Add(_sub);
        right.Children.Add(_counts);
        var buttons = HStack(8);
        _scan = Button("Scan & Protect", () => vm.StartScan(), primary: true);
        _scan.MinHeight = 34;
        buttons.Children.Add(_scan);
        _fix = Button("Fix recommended", vm.RequestRecommended);
        _fix.ToolTip = "Applies only safe, non-disruptive fixes (you see a preview first).";
        _fix.IsEnabled = false;
        buttons.Children.Add(_fix);
        right.Children.Add(buttons);
        var row = new DockPanel();
        DockPanel.SetDock(Ring, Dock.Left);
        Ring.Margin = new Thickness(0, 0, 20, 0);
        row.Children.Add(Ring);
        row.Children.Add(right);
        Body.Children.Add(Card(row));

        _networkCard = Card(_network);
        _networkCard.Visibility = Visibility.Collapsed;
        Body.Children.Add(_networkCard);

        Body.Children.Add(Text("Top things to look at", TextStyle.SectionTitle));
        _top.Children.Add(Text("No scan yet.", TextStyle.Dim));
        Body.Children.Add(_top);

        _changesCard = Card(_changes);
        _changesTitle.Visibility = _changesCard.Visibility = Visibility.Collapsed;
        Body.Children.Add(_changesTitle);
        Body.Children.Add(_changesCard);

        vm.BusyChanged += OnBusy;
        vm.ScanFinished += ShowResult;
    }

    private void OnBusy(bool busy, string text)
    {
        _scan.IsEnabled = !busy;
        _fix.IsEnabled = !busy && Vm.HasRecommended;
        // v2 left "Scanning this PC…" here after a failed scan; restore the last real status.
        _sub.Text = busy && text.Length > 0 ? text : _idleSub;
    }

    public void ShowResult(ScanResult result)
    {
        Ring.SetScore(result.Score, result.Grade);
        var opened = result.OpenFindings;
        var counts = result.Counts();
        if (opened.Count == 0)
        {
            _headline.Text = "Nothing needs your attention right now.";
        }
        else if (Js.Long(counts["critical"]) > 0 || Js.Long(counts["high"]) > 0)
        {
            _headline.Text = $"{opened.Count} things to look at, some of them important.";
        }
        else
        {
            _headline.Text = $"{opened.Count} things you could improve.";
        }
        var mode = result.IsAdmin ? "" : " Read-only mode: fixes will ask for administrator permission.";
        var started = result.Started.Replace('T', ' ');
        _idleSub = $"Last scan {started[..Math.Min(16, started.Length)]} on {result.Computer}.{mode}";
        _sub.Text = _idleSub;

        _counts.Children.Clear();
        foreach (var (name, n) in counts)
        {
            var sev = EnumText.ParseSeverity(name);
            var cell = Rich(C(Js.Long(n).ToString(System.Globalization.CultureInfo.InvariantCulture), Palette.SeverityText(sev), bold: true), Br(), R(sev.Label()));
            ((System.Windows.Documents.Run)cell.Inlines.FirstInline).FontSize = 21;
            cell.TextAlignment = TextAlignment.Center;
            cell.MinWidth = 76;
            _counts.Children.Add(cell);
        }
        _fix.IsEnabled = !Vm.IsBusy && Vm.HasRecommended;

        _network.Children.Clear();
        var lines = result.NetworkStatus();
        if (lines.Count > 0)
        {
            _network.Children.Add(Text("Network status", TextStyle.SectionTitle));
            foreach (var line in lines)
            {
                _network.Children.Add(Text(line));
            }
            _networkCard.Visibility = Visibility.Visible;
        }

        _top.Children.Clear();
        var top = opened.Take(5).ToList();
        if (top.Count == 0)
        {
            _top.Children.Add(Text("Nothing needs your attention. Well done.", TextStyle.Dim));
        }
        foreach (var f in top)
        {
            _top.Children.Add(FindingCardFor(f, compact: true));
        }

        _changes.Children.Clear();
        var diff = Vm.Comparison();
        if (diff is null || Vm.Previous is null)
        {
            _changesTitle.Visibility = _changesCard.Visibility = Visibility.Collapsed;
            return;
        }
        _changesTitle.Visibility = _changesCard.Visibility = Visibility.Visible;
        if (diff.Empty)
        {
            _changes.Children.Add(Text("No changes since the previous scan.", TextStyle.Dim));
            return;
        }
        if (diff.ScoreChange != 0)
        {
            _changes.Children.Add(Text($"Risk score {(diff.ScoreChange > 0 ? "up" : "down")} by {Math.Abs(diff.ScoreChange)}."));
        }
        foreach (var f in diff.NewFindings)
        {
            _changes.Children.Add(Text($"New: {Js.Str(f["title"])}"));
        }
        foreach (var f in diff.ResolvedFindings)
        {
            _changes.Children.Add(Text($"Resolved: {Js.Str(f["title"])}"));
        }
        foreach (var item in diff.NewListeners)
        {
            _changes.Children.Add(Text($"Newly reachable: {item}"));
        }
        foreach (var item in diff.GoneListeners)
        {
            _changes.Children.Add(Text($"No longer reachable: {item}"));
        }
        foreach (var d in diff.NewDevices)
        {
            _changes.Children.Add(Text($"New device: {DeviceName(d)}"));
        }
    }

    /// <summary>str(d.get('name') or d.get('ip')).</summary>
    internal static string DeviceName(System.Text.Json.Nodes.JsonObject d) =>
        Js.Truthy(d["name"]) ? Js.Str(d["name"]) : Js.Str(d["ip"]);
}
