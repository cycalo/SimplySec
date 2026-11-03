using System.Windows.Controls;
using SimplySec.App.Controls;
using SimplySec.App.Theme;
using SimplySec.App.ViewModels;
using SimplySec.Core.Model;
using static SimplySec.App.Theme.Ui;

namespace SimplySec.App.Views;

/// <summary>Every finding as a card, most serious first, topic shown on each card.</summary>
public sealed class ThisPcPage : PageView
{
    private static readonly string[] AreaOrder =
    [
        "Firewall", "Exposure", "Remote access", "Legacy protocols", "File sharing", "Malware protection",
        "Updates", "Accounts", "System", "Home network", "Wi-Fi", "Router", "Housekeeping",
    ];

    private readonly CheckBox _showInfo = new() { Content = "Also show informational items and risks you chose to keep" };

    public Dictionary<string, FindingCard> Cards { get; } = new(StringComparer.Ordinal);

    public ThisPcPage(MainViewModel vm)
        : base(vm, "This PC", "Each finding explains what it means. Nothing changes until you choose a fix and confirm it.")
    {
        Header.Children.Add(_showInfo);
        _showInfo.Checked += (_, _) => Refresh();
        _showInfo.Unchecked += (_, _) => Refresh();
        Body.Children.Add(Text("Run a scan from the Overview page.", TextStyle.Dim));
        vm.ScanFinished += _ => Refresh();
    }

    public void Refresh()
    {
        var result = Vm.Result;
        if (result is null)
        {
            return;
        }
        Body.Children.Clear();
        Cards.Clear();
        var showAll = _showInfo.IsChecked == true;
        var findings = result.Findings.Where(f => showAll || f.Scored).ToList();
        if (findings.Count == 0)
        {
            Body.Children.Add(Text("No findings. Nothing needs your attention.", TextStyle.Dim));
            return;
        }
        string[] other = ["lan", "router"]; // advice about other devices, not this PC's settings
        var groups = new (string Title, Func<Finding, bool> Test)[]
        {
            ("Needs attention", f => f.Scored && f.Severity >= Severity.High && !other.Contains(f.Check)),
            ("Worth fixing", f => f.Scored && f.Severity == Severity.Medium && !other.Contains(f.Check)),
            ("Minor", f => f.Scored && f.Severity == Severity.Low && !other.Contains(f.Check)),
            ("Other devices on your network and your router", f => f.Scored && other.Contains(f.Check)),
            ("For information and kept risks", f => !f.Scored),
        };
        foreach (var (title, test) in groups)
        {
            var items = findings.Where(test)
                .OrderBy(f => -(int)f.Severity)
                .ThenBy(f => Array.IndexOf(AreaOrder, f.Area) is var i and >= 0 ? i : 99)
                .ThenBy(f => f.Title, StringComparer.Ordinal)
                .ToList();
            if (items.Count == 0)
            {
                continue;
            }
            Body.Children.Add(Text($"{title} ({items.Count})", TextStyle.SectionTitle));
            foreach (var f in items)
            {
                var c = FindingCardFor(f, showArea: true);
                Cards[f.Id] = c;
                Body.Children.Add(c);
            }
        }
    }
}
