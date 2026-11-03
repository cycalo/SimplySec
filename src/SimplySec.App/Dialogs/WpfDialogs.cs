using System.Windows;
using Microsoft.Win32;
using SimplySec.App.Infrastructure;
using SimplySec.App.ViewModels;
using SimplySec.Core.Engine;
using SimplySec.Core.Model;

namespace SimplySec.App.Dialogs;

/// <summary>The real dialogs, owned by the main window.</summary>
public sealed class WpfDialogs : IDialogs
{
    private static Window? Owner => Application.Current?.MainWindow;

    public void Info(string title, string text) => new MessageDialog(title, text, owner: Owner).ShowDialog();

    public void Warn(string title, string text) => new MessageDialog(title, text, owner: Owner).ShowDialog();

    public bool Ask(string title, string text) => new MessageDialog(title, text, question: true, owner: Owner).ShowDialog() == true;

    public PreviewChoice Preview(Plan plan, bool isAdmin, IReadOnlyDictionary<string, Finding> findings)
    {
        var dlg = new PreviewDialog(new PreviewModel(plan, isAdmin, findings), Owner);
        dlg.ShowDialog();
        return dlg.Choice();
    }

    public void Results(ResultSummary summary) => new ResultDialog(summary, Owner).ShowDialog();

    public string? SaveFile(string title, string defaultPath, string filter)
    {
        var dlg = new SaveFileDialog
        {
            Title = title,
            FileName = Path.GetFileName(defaultPath),
            InitialDirectory = Path.GetDirectoryName(defaultPath),
            Filter = filter,
            OverwritePrompt = true,
        };
        var ok = Owner is { } owner ? dlg.ShowDialog(owner) : dlg.ShowDialog();
        return ok == true ? dlg.FileName : null;
    }
}
