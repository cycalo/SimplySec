using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using SimplySec.App.Theme;
using SimplySec.App.ViewModels;
using SimplySec.Core.Storage;
using static SimplySec.App.Theme.Ui;

namespace SimplySec.App.Views;

/// <summary>A batch header or one change, as a row of the Changes list.</summary>
public sealed record ChangeRowView(bool IsBatch, long Id, string Change, string Status, string Verified, string When, string? Error)
{
    public FontWeight Weight => IsBatch ? FontWeights.SemiBold : FontWeights.Normal;
    public Thickness Indent => IsBatch ? new Thickness(4, 2, 4, 2) : new Thickness(24, 2, 4, 2);
}

/// <summary>
/// Every change SimplySec made, grouped by batch, with Undo, Undo all and the firewall backups
/// (port of pages/changes.py). A flat list with batch rows replaces v2's tree, so several batches
/// and changes can be selected and undone together.
/// </summary>
public sealed class ChangesPage : PageView
{
    private static readonly Dictionary<string, string> StatusText = new(StringComparer.Ordinal)
    {
        ["applied"] = "Active",
        ["reverted"] = "Undone",
        ["failed"] = "Failed",
        ["revert_failed"] = "Undo failed",
        ["pending"] = "Interrupted",
    };

    public DataGrid Table { get; } = new()
    {
        AutoGenerateColumns = false,
        HorizontalScrollBarVisibility = ScrollBarVisibility.Disabled,
        IsReadOnly = true,
        SelectionMode = DataGridSelectionMode.Extended,
        HeadersVisibility = DataGridHeadersVisibility.Column,
        CanUserAddRows = false,
        CanUserSortColumns = false,
        Height = 380,
    };
    private readonly Wpf.Ui.Controls.Button _undo;
    private readonly Wpf.Ui.Controls.Button _undoAll;
    private readonly Wpf.Ui.Controls.Button _rules;
    private readonly TextBlock _note = Text("", TextStyle.Dim);
    private List<ChangeRecord> _changes = [];

    /// <summary>Changes that are still in effect (applied, or an undo that failed).</summary>
    public int Active { get; private set; }

    public ChangesPage(MainViewModel vm)
        : base(vm, "Changes", "Everything SimplySec changed on this PC. Each change keeps its previous value, so it can be undone.")
    {
        var change = new Style(typeof(TextBlock));
        change.Setters.Add(new Setter(TextBlock.FontWeightProperty, new Binding(nameof(ChangeRowView.Weight))));
        change.Setters.Add(new Setter(TextBlock.MarginProperty, new Binding(nameof(ChangeRowView.Indent))));
        change.Setters.Add(new Setter(TextBlock.TextTrimmingProperty, TextTrimming.CharacterEllipsis));
        change.Setters.Add(new Setter(FrameworkElement.ToolTipProperty, new Binding(nameof(ChangeRowView.Change))));
        Table.Columns.Add(new DataGridTextColumn { Header = "Change", Binding = new Binding(nameof(ChangeRowView.Change)), Width = new DataGridLength(1, DataGridLengthUnitType.Star), ElementStyle = change });
        var status = new Style(typeof(TextBlock));
        status.Setters.Add(new Setter(TextBlock.MarginProperty, new Thickness(4, 2, 4, 2)));
        status.Setters.Add(new Setter(FrameworkElement.ToolTipProperty, new Binding(nameof(ChangeRowView.Error))));
        Table.Columns.Add(new DataGridTextColumn { Header = "Status", Binding = new Binding(nameof(ChangeRowView.Status)), Width = 110, ElementStyle = status });
        Table.Columns.Add(new DataGridTextColumn { Header = "Verified", Binding = new Binding(nameof(ChangeRowView.Verified)), Width = 80 });
        Table.Columns.Add(new DataGridTextColumn { Header = "When", Binding = new Binding(nameof(ChangeRowView.When)), Width = 140 });
        Table.SelectionChanged += (_, _) => UpdateButtons();
        Body.Children.Add(Table);

        var row = new DockPanel();
        var left = HStack(8);
        _undo = Button("Undo selected", UndoSelected);
        _undoAll = Button("Undo everything SimplySec changed", () => vm.Undo(everything: true));
        _rules = Button("Remove all SimplySec rules", () => vm.Undo(rules: true));
        left.Children.Add(_undo);
        left.Children.Add(_undoAll);
        left.Children.Add(_rules);
        var backups = Button("Open firewall backups", OpenBackups);
        DockPanel.SetDock(backups, Dock.Right);
        row.Children.Add(backups);
        row.Children.Add(left);
        Body.Children.Add(row);
        Body.Children.Add(_note);

        vm.ChangesUpdated += Refresh;
        vm.BusyChanged += (_, _) => UpdateButtons();
        Refresh();
    }

    public void Refresh()
    {
        var rows = new List<ChangeRowView>();
        try
        {
            var journal = Vm.Journal();
            var batches = journal.Batches().ToDictionary(b => b.Id);
            _changes = journal.Changes();
            long? current = null;
            foreach (var c in _changes)
            {
                if (c.BatchId != current)
                {
                    current = c.BatchId;
                    batches.TryGetValue(c.BatchId, out var b);
                    var created = b?.Created ?? "";
                    rows.Add(new ChangeRowView(true, c.BatchId, $"Batch {c.BatchId}: {b?.Title ?? ""}", "", "", Short(created), null));
                }
                var verified = c.Verified switch { true => "✓", false => "✗", null => "" };
                rows.Add(new ChangeRowView(false, c.Id, c.Summary, StatusText.GetValueOrDefault(c.Status, c.Status), verified,
                    Short(c.RevertedAt ?? c.AppliedAt ?? ""), c.Error));
            }
        }
        catch (Exception exc)
        {
            _changes = [];
            _note.Text = $"Could not read the change journal: {exc.Message}";
        }
        Table.ItemsSource = rows;
        Active = _changes.Count(c => c.Status is Journal.Applied or Journal.RevertFailed);
        if (rows.Count == 0)
        {
            _note.Text = "SimplySec has not changed anything on this PC yet.";
        }
        else
        {
            _note.Text = $"{Active} active change(s). Firewall backups are kept in {Vm.Services.BackupsDir} (newest 10)."
                + (Vm.IsAdmin ? "" : " Undo will ask for administrator permission.");
        }
        UpdateButtons();
    }

    private static string Short(string ts) => ts[..Math.Min(16, ts.Length)].Replace('T', ' ');

    private void UpdateButtons()
    {
        var busy = Vm.IsBusy;
        _rules.IsEnabled = !busy;
        // v2 re-enabled this after every task, even with nothing left to undo.
        _undoAll.IsEnabled = !busy && Active > 0;
        _undo.IsEnabled = !busy && Selected().Count > 0;
    }

    private List<ChangeRowView> Selected() => Table.SelectedItems.OfType<ChangeRowView>().ToList();

    /// <summary>
    /// One batch: undo that batch. Anything else: the selected changes plus the active changes of
    /// every selected batch (v2 ignored a selection of several batches).
    /// </summary>
    public (long? BatchId, List<long> ChangeIds) UndoTarget()
    {
        var sel = Selected();
        var batchIds = sel.Where(r => r.IsBatch).Select(r => r.Id).ToList();
        var changeIds = sel.Where(r => !r.IsBatch).Select(r => r.Id).ToList();
        if (batchIds.Count == 1 && changeIds.Count == 0)
        {
            return (batchIds[0], []);
        }
        var fromBatches = _changes.Where(c => batchIds.Contains(c.BatchId) && c.Status is Journal.Applied or Journal.RevertFailed).Select(c => c.Id);
        return (null, changeIds.Concat(fromBatches).Distinct().Order().ToList());
    }

    private void UndoSelected()
    {
        var (batch, ids) = UndoTarget();
        if (batch is not null)
        {
            Vm.Undo(batchId: batch);
        }
        else if (ids.Count > 0)
        {
            Vm.Undo(changeIds: ids);
        }
        else
        {
            Vm.Dialogs.Info("Undo", "Nothing in the selected batches is still active.");
        }
    }

    private void OpenBackups()
    {
        var folder = Vm.Services.BackupsDir;
        if (Directory.Exists(folder))
        {
            Vm.Services.OpenPath(folder);
        }
        else
        {
            _note.Text = "No firewall backups yet: one is made before the first firewall change.";
        }
    }
}
