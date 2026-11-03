using System.Globalization;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using SimplySec.App.Controls;
using SimplySec.App.Theme;
using SimplySec.App.ViewModels;
using SimplySec.Core.Compat;
using SimplySec.Core.Storage;
using static SimplySec.App.Theme.Ui;

namespace SimplySec.App.Views;

public sealed record ScanRowView(long Id, string Scan, string Type, string Score, string Change);

/// <summary>Score trend, past scans with new and resolved findings, and the HTML report.</summary>
public sealed class HistoryPage : PageView
{
    public TrendChart Chart { get; } = new();
    public DataGrid Table { get; } = new()
    {
        AutoGenerateColumns = false,
        HorizontalScrollBarVisibility = ScrollBarVisibility.Disabled,
        IsReadOnly = true,
        SelectionMode = DataGridSelectionMode.Single,
        HeadersVisibility = DataGridHeadersVisibility.Column,
        CanUserAddRows = false,
        Height = 220,
    };
    private readonly StackPanel _detail = VStack(4);

    public HistoryPage(MainViewModel vm) : base(vm, "History", "How this PC's risk score changed over time, and what each scan found.")
    {
        var chartBox = VStack(8);
        chartBox.Children.Add(Text("Risk score over time (lower is better)", TextStyle.SectionTitle));
        chartBox.Children.Add(Chart);
        Body.Children.Add(Card(chartBox));

        var export = Button("Export HTML report…", Export, primary: true);
        export.HorizontalAlignment = HorizontalAlignment.Left;
        Body.Children.Add(export);

        foreach (var (header, path, star) in new[] { ("Scan", nameof(ScanRowView.Scan), true), ("Type", nameof(ScanRowView.Type), false), ("Risk score", nameof(ScanRowView.Score), false), ("Change", nameof(ScanRowView.Change), false) })
        {
            Table.Columns.Add(new DataGridTextColumn
            {
                Header = header,
                Binding = new Binding(path),
                Width = star ? new DataGridLength(1, DataGridLengthUnitType.Star) : new DataGridLength(120),
            });
        }
        Table.SelectionChanged += (_, _) => Show(Table.SelectedItem as ScanRowView);
        Body.Children.Add(Table);
        Body.Children.Add(Card(_detail));
        vm.ScanFinished += _ => Refresh();
        Refresh();
    }

    public void Refresh()
    {
        var history = Vm.Engine.History;
        List<ScanSummary> scans;
        try
        {
            scans = history.Scans(limit: 200);
        }
        catch (Exception exc)
        {
            _detail.Children.Clear();
            _detail.Children.Add(Text($"Could not read the history: {exc.Message}", TextStyle.Dim));
            return;
        }
        Chart.SetPoints(scans.Take(60).Reverse().Select(s => (s.Ts[..Math.Min(10, s.Ts.Length)], s.Score)).ToList());
        var rows = new List<ScanRowView>();
        for (var i = 0; i < scans.Count; i++)
        {
            var s = scans[i];
            var change = "";
            if (i + 1 < scans.Count)
            {
                var delta = s.Score - scans[i + 1].Score;
                change = delta != 0 ? delta.ToString("+0;-0", CultureInfo.InvariantCulture) : "–";
            }
            var ts = s.Ts[..Math.Min(16, s.Ts.Length)].Replace('T', ' ');
            rows.Add(new ScanRowView(s.Id, ts, s.Kind, $"{s.Score} ({s.Grade})", change));
        }
        Table.ItemsSource = rows;
        if (rows.Count > 0)
        {
            Table.SelectedIndex = 0;
        }
        else
        {
            _detail.Children.Clear();
            _detail.Children.Add(Text("No scans saved yet.", TextStyle.Dim));
        }
    }

    private void Show(ScanRowView? item)
    {
        _detail.Children.Clear();
        if (item is null)
        {
            return;
        }
        var history = Vm.Engine.History;
        var data = history.ScanData(item.Id);
        if (data is null)
        {
            return;
        }
        var previous = history.PreviousTo(item.Id);
        var diff = History.Compare(previous, data);
        _detail.Children.Add(Text($"Scan of {item.Scan}: risk score {Js.Str(data["score"])} ({Js.Str(data["grade"])})", TextStyle.SectionTitle));
        if (diff.Empty)
        {
            _detail.Children.Add(Text(previous is not null ? "Nothing changed compared with the scan before." : "The first saved scan.", TextStyle.Dim));
        }
        foreach (var f in diff.NewFindings)
        {
            _detail.Children.Add(Rich(B("New: "), R($"{Js.Str(f["title"])} ({Js.Str(f["severity"])})")));
        }
        foreach (var f in diff.ResolvedFindings)
        {
            _detail.Children.Add(Rich(B("Resolved: "), R(Js.Str(f["title"]))));
        }
        foreach (var x in diff.NewListeners)
        {
            _detail.Children.Add(Rich(B("Newly reachable: "), R(x)));
        }
        foreach (var x in diff.GoneListeners)
        {
            _detail.Children.Add(Rich(B("No longer reachable: "), R(x)));
        }
        foreach (var d in diff.NewDevices)
        {
            _detail.Children.Add(Rich(B("New device: "), R(OverviewPage.DeviceName(d))));
        }
    }

    private void Export()
    {
        var result = Vm.Result;
        if (result is null)
        {
            Vm.Dialogs.Info("Scan first", "Run a scan first, then export the report.");
            return;
        }
        var docs = Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments);
        var path = Vm.Dialogs.SaveFile("Save report", Path.Combine(docs, $"SimplySec-report-{result.Started[..Math.Min(10, result.Started.Length)]}.html"), "HTML report (*.html)|*.html");
        if (path is null)
        {
            return;
        }
        try
        {
            Vm.Services.WriteReport(path, result, Vm.Engine);
        }
        catch (Exception exc)
        {
            Vm.Dialogs.Warn("Report", $"Could not write the report: {exc.Message}");
            return;
        }
        Vm.Services.OpenPath(path);
    }
}
