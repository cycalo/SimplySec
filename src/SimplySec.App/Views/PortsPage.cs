using System.ComponentModel;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using SimplySec.App.Controls;
using SimplySec.App.Dialogs;
using SimplySec.App.Theme;
using SimplySec.App.ViewModels;
using SimplySec.Core.Engine;
using SimplySec.Core.Model;
using static SimplySec.App.Theme.Ui;

namespace SimplySec.App.Views;

/// <summary>One row of the ports table: display text, sort keys and colours (v2's PortModel roles).</summary>
public sealed class PortRowView(PortRow r)
{
    public PortRow Row { get; } = r;
    public string Port => $"{Row.Protocol.ToUpperInvariant()} {Row.Port}";
    public string Program => Row.Process
        + (Row.Services.Count > 0 ? $" [{string.Join(", ", Row.Services)}]" : "")
        + (Row.Publisher.Length > 0 ? $" ({Row.Publisher})" : "");
    public string ListeningOn => Row.ListeningOn;
    public string ReachableFrom => Row.ReachableFrom;
    public string InUse => Row.Connected.Count switch
    {
        0 => "",
        1 => "1 device connected",
        var n => $"{n} devices connected",
    };
    public string Risk => Row.Verdict == Verdict.Reachable ? Row.Risk.Label() : "–";
    public string Action => Row.FindingId is not null ? "Review…" : "Details…";

    // Sort keys: (port, protocol); risk only counts when reachable; number of connected devices.
    public int PortSort => Row.Port * 2 + (Row.Protocol == "udp" ? 1 : 0);
    public int RiskSort => Row.Verdict == Verdict.Reachable ? (int)Row.Risk : -1;
    public int InUseSort => Row.Connected.Count;

    public Brush? RiskBrush => Row.Verdict == Verdict.Reachable ? Palette.SeverityText(Row.Risk) : null;
    public Brush? ReachBrush => Row.Verdict == Verdict.Uncertain ? Palette.SeverityText(Severity.Medium) : null;
    public string Tooltip => Row.Connected.Count > 0 ? "Connected right now from: " + string.Join(", ", Row.Connected) : Row.Reason;
    public bool Reachable => Row.Verdict is Verdict.Reachable or Verdict.Uncertain;
}

/// <summary>Port, program, listening on, reachable from, in use, risk, action.</summary>
public sealed class PortsPage : PageView
{
    public const int ActionColumn = 6;

    private readonly CheckBox _only = new() { Content = "Reachable only", IsChecked = true };
    private readonly TextBlock _count = Text("", TextStyle.Dim);
    public DataGrid Table { get; } = new()
    {
        AutoGenerateColumns = false,
        HorizontalScrollBarVisibility = ScrollBarVisibility.Disabled,
        IsReadOnly = true,
        SelectionMode = DataGridSelectionMode.Single,
        SelectionUnit = DataGridSelectionUnit.FullRow,
        HeadersVisibility = DataGridHeadersVisibility.Column,
        CanUserAddRows = false,
        Height = 460,
    };
    public List<PortRowView> Rows { get; private set; } = [];
    public ICollectionView? View { get; private set; }

    public PortsPage(MainViewModel vm)
        : base(vm, "Open ports", "Programs that listen for connections, and who can actually reach them through the firewall.")
    {
        var row = new DockPanel();
        DockPanel.SetDock(_only, Dock.Left);
        row.Children.Add(_only);
        _count.Margin = new Thickness(16, 0, 0, 0);
        _count.VerticalAlignment = VerticalAlignment.Center;
        row.Children.Add(_count);
        Body.Children.Add(row);
        _only.Checked += (_, _) => Refilter();
        _only.Unchecked += (_, _) => Refilter();

        Table.Columns.Add(Column("Port", nameof(PortRowView.Port), 95, nameof(PortRowView.PortSort)));
        Table.Columns.Add(Column("Program (publisher)", nameof(PortRowView.Program), 210));
        Table.Columns.Add(Column("Listening on", nameof(PortRowView.ListeningOn), 130));
        Table.Columns.Add(Column("Reachable from", nameof(PortRowView.ReachableFrom), double.NaN, foreground: nameof(PortRowView.ReachBrush)));
        Table.Columns.Add(Column("In use now", nameof(PortRowView.InUse), 110, nameof(PortRowView.InUseSort)));
        Table.Columns.Add(Column("Risk", nameof(PortRowView.Risk), 64, nameof(PortRowView.RiskSort), nameof(PortRowView.RiskBrush)));
        var action = Column("Action", nameof(PortRowView.Action), 80);
        action.ElementStyle.Setters.Add(new Setter(TextBlock.CursorProperty, Cursors.Hand));
        var accent = new Setter { Property = TextBlock.ForegroundProperty, Value = new DynamicResourceExtension(Ui.Accent) };
        action.ElementStyle.Setters.Add(accent);
        Table.Columns.Add(action);
        Table.PreviewMouseLeftButtonUp += OnClick;
        Table.MouseDoubleClick += (_, e) =>
        {
            if (RowAt(e.OriginalSource) is { } r)
            {
                Details(r);
            }
        };
        Body.Children.Add(Table);
        Body.Children.Add(Text("Click 'Review…' to see the finding and its fixes, or double-click a row for the exact firewall rules and reasons.", TextStyle.Dim));
        vm.ScanFinished += ShowResult;
    }

    private static DataGridTextColumn Column(string header, string path, double width, string? sort = null, string? foreground = null)
    {
        var style = new Style(typeof(TextBlock));
        style.Setters.Add(new Setter(TextBlock.TextTrimmingProperty, TextTrimming.CharacterEllipsis));
        style.Setters.Add(new Setter(TextBlock.MarginProperty, new Thickness(4, 2, 4, 2)));
        style.Setters.Add(new Setter(FrameworkElement.ToolTipProperty, new Binding(nameof(PortRowView.Tooltip))));
        if (foreground is not null)
        {
            // Rows without a colour keep the theme's text colour.
            var trigger = new DataTrigger { Binding = new Binding(foreground), Value = null };
            style.Setters.Add(new Setter(TextBlock.ForegroundProperty, new Binding(foreground)));
            trigger.Setters.Add(new Setter(TextBlock.ForegroundProperty, new DynamicResourceExtension(Ui.TextPrimary)));
            style.Triggers.Add(trigger);
        }
        return new DataGridTextColumn
        {
            Header = header,
            Binding = new Binding(path),
            SortMemberPath = sort ?? path,
            Width = double.IsNaN(width) ? new DataGridLength(1, DataGridLengthUnitType.Star) : new DataGridLength(width),
            ElementStyle = style,
        };
    }

    public void ShowResult(ScanResult result)
    {
        Rows = result.Ports.Select(p => new PortRowView(p)).ToList();
        View = CollectionViewSource.GetDefaultView(Rows);
        View.SortDescriptions.Add(new SortDescription(nameof(PortRowView.RiskSort), ListSortDirection.Descending));
        Table.ItemsSource = View;
        if (Table.Columns.FirstOrDefault(c => c.SortMemberPath == nameof(PortRowView.RiskSort)) is { } risk)
        {
            risk.SortDirection = ListSortDirection.Descending;
        }
        Refilter();
    }

    private void Refilter()
    {
        if (View is not null)
        {
            View.Filter = _only.IsChecked == true ? o => ((PortRowView)o).Reachable : null;
        }
        var reach = Rows.Count(r => r.Row.Verdict == Verdict.Reachable);
        var unc = Rows.Count(r => r.Row.Verdict == Verdict.Uncertain);
        _count.Text = $"{Rows.Count} listening, {reach} reachable from other devices, {unc} uncertain";
    }

    /// <summary>Rows shown with the current filter.</summary>
    public int VisibleCount => View?.Cast<object>().Count() ?? 0;

    private static PortRowView? RowAt(object source)
    {
        for (var d = source as DependencyObject; d is not null; d = d is Visual or System.Windows.Media.Media3D.Visual3D ? VisualTreeHelper.GetParent(d) : LogicalTreeHelper.GetParent(d))
        {
            if (d is DataGridRow row)
            {
                return row.Item as PortRowView;
            }
        }
        return null;
    }

    private void OnClick(object sender, MouseButtonEventArgs e)
    {
        DependencyObject? d = e.OriginalSource as DependencyObject;
        while (d is not null and not DataGridCell)
        {
            d = d is Visual ? VisualTreeHelper.GetParent(d) : LogicalTreeHelper.GetParent(d);
        }
        if (d is DataGridCell cell && cell.Column.DisplayIndex == ActionColumn && cell.DataContext is PortRowView r)
        {
            Review(r);
        }
    }

    private void Review(PortRowView r)
    {
        if (r.Row.FindingId is { } id && Vm.Result?.Finding(id) is { Fixes.Count: > 0 } f)
        {
            var card = new FindingCard(f);
            var dlg = new MessageDialog(f.Title, card, 640, Window.GetWindow(this));
            card.FixRequested += (fi, opt) =>
            {
                dlg.Close();
                Vm.RequestFix(fi, opt);
            };
            card.KeepRequested += fi =>
            {
                dlg.Close();
                Vm.Keep(fi);
            };
            dlg.ShowDialog();
            return;
        }
        Details(r);
    }

    private void Details(PortRowView v)
    {
        var r = v.Row;
        var inlines = new List<Inline>
        {
            B($"{r.Protocol.ToUpperInvariant()} {r.Port}"), R($" – {r.Process} (PID {r.Pid})"), Br(),
            R(r.Exe), Br(), Br(),
            B("Listening on: "), R(r.ListeningOn), Br(),
            B("Reachable from: "), R(r.ReachableFrom), Br(),
            B("Connected right now: "), R(r.Connected.Count > 0 ? string.Join(", ", r.Connected) : "nobody"), Br(), Br(),
            R(r.Reason), Br(), Br(),
            B("Firewall rules involved:"),
        };
        foreach (var n in r.Rules.Count > 0 ? r.Rules : ["none"])
        {
            inlines.Add(Br());
            inlines.Add(R($"  •  {n}"));
        }
        new MessageDialog("Port details", Rich([.. inlines]), 600, Window.GetWindow(this)).ShowDialog();
    }
}
