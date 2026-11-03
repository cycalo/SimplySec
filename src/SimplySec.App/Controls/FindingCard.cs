using System.Windows;
using System.Windows.Controls;
using System.Windows.Documents;
using SimplySec.App.Theme;
using SimplySec.Core;
using SimplySec.Core.Model;
using static SimplySec.App.Theme.Ui;

namespace SimplySec.App.Controls;

/// <summary>
/// A finding as a card: plain title, what it means, what uses it, advice and technical details,
/// with Fix / Keep / Show more. <c>compact</c> (Overview) keeps
/// everything but the title, meaning and buttons behind "Show more".
/// </summary>
public sealed class FindingCard : UserControl
{
    public Finding Finding { get; }
    public Border Frame { get; }

    public event Action<Finding, FixOption>? FixRequested;
    public event Action<Finding>? KeepRequested;
    public event Action<Finding>? UnkeepRequested;

    private static readonly Dictionary<FindingStatus, (string Text, string Color)> StatusText = new()
    {
        [FindingStatus.Accepted] = ("Kept", Palette.Grey),
        [FindingStatus.Managed] = ("Managed by your organisation", Palette.Grey),
        [FindingStatus.Info] = ("For information", Palette.Grey),
    };

    public FindingCard(Finding finding, bool compact = false, bool showArea = false, bool showAdvice = false)
    {
        Finding = finding;
        var outer = VStack(6);

        var head = new DockPanel { LastChildFill = true };
        void Right(UIElement e)
        {
            DockPanel.SetDock(e, Dock.Right);
            head.Children.Add(e);
        }
        var chip = Chip(finding.Severity.Label(), Palette.SeverityChip(finding.Severity));
        DockPanel.SetDock(chip, Dock.Left);
        head.Children.Add(chip);
        if (finding.UserConfigured)
        {
            Right(Chip("You set this up", Palette.Brush(Palette.Blue)));
        }
        if (showArea)
        {
            var area = Text(finding.Area, TextStyle.Dim, wrap: false);
            area.Margin = new Thickness(8, 2, 0, 0);
            Right(area);
        }
        if (StatusText.TryGetValue(finding.Status, out var st))
        {
            Right(Chip(st.Text, Palette.Brush(st.Color)));
        }
        head.Children.Add(Text(finding.Title, TextStyle.CardTitle));
        outer.Children.Add(head);

        outer.Children.Add(Rich(B("What this means: "), R(finding.WhatItMeans)));

        // On the full card the impact line is always shown and the rest is behind its own link;
        // on a compact card everything extra sits behind "Show more".
        var impact = ImpactText();
        var learn = finding.LearnMore.Length > 0 ? Rich(B("What to do: "), R(finding.LearnMore)) : null;
        var details = finding.Details.Count > 0 ? DetailsBox() : null;
        foreach (var w in new FrameworkElement?[] { impact, learn, details })
        {
            if (w is not null)
            {
                w.Visibility = Visibility.Collapsed;
                outer.Children.Add(w);
            }
        }
        if (impact is not null && !compact)
        {
            impact.Visibility = Visibility.Visible;
        }
        if (learn is not null && showAdvice)
        {
            learn.Visibility = Visibility.Visible;
        }

        var buttons = HStack(8);
        var actionable = finding.Fixes.ToList();
        if (actionable.Count > 0 && finding.Status is FindingStatus.Open or FindingStatus.Accepted)
        {
            buttons.Children.Add(FixButton(actionable));
        }
        if (finding.KeepKey is not null && finding.Status == FindingStatus.Open)
        {
            var keep = Button("Keep: I need this", () => KeepRequested?.Invoke(Finding));
            keep.ToolTip = "Stop scoring this. It comes back only if it becomes reachable more widely.";
            buttons.Children.Add(keep);
        }
        else if (finding.KeepKey is not null && finding.Status == FindingStatus.Accepted)
        {
            buttons.Children.Add(Button("Score again", () => UnkeepRequested?.Invoke(Finding)));
        }
        var extras = new FrameworkElement?[] { impact, learn, details }.OfType<FrameworkElement>().ToList();
        if (compact && extras.Count > 0)
        {
            var closed = actionable.Count > 0 ? "Show more" : "How to fix";
            var opened = actionable.Count > 0 ? "Show less" : "Hide advice";
            var open = false;
            Wpf.Ui.Controls.Button? more = null;
            more = Link(closed, () =>
            {
                open = !open;
                foreach (var w in extras)
                {
                    w.Visibility = open ? Visibility.Visible : Visibility.Collapsed;
                }
                more!.Content = open ? opened : closed;
            });
            more.ToolTip = "What uses this, advice and technical details";
            buttons.Children.Add(more);
        }
        else if (!compact)
        {
            if (details is not null)
            {
                buttons.Children.Add(Link("Technical details", () => Toggle(details)));
            }
            if (learn is not null && !showAdvice)
            {
                buttons.Children.Add(Link("Learn more", () => Toggle(learn)));
            }
        }
        if (buttons.Children.Count > 0)
        {
            outer.Children.Add(buttons);
        }

        Frame = Card(outer);
        Frame.Padding = new Thickness(16, 12, 16, 12);
        Content = Frame;
    }

    private static void Toggle(UIElement e) =>
        e.Visibility = e.Visibility == Visibility.Visible ? Visibility.Collapsed : Visibility.Visible;

    private TextBlock? ImpactText()
    {
        var primary = Finding.Fixes.FirstOrDefault(o => o.Impact.Count > 0);
        if (primary is null || Finding.Status != FindingStatus.Open)
        {
            return null;
        }
        var imp = Impact.FromJson(primary.Impact);
        var inlines = new List<Inline>
        {
            B("What uses this: "),
            C(Impact.Label(imp.Level), Palette.ImpactText(imp.Level)),
            R($" – {imp.Headline}"),
        };
        foreach (var e in imp.Evidence.Take(3))
        {
            inlines.Add(Br());
            inlines.Add(R($"• {e}"));
        }
        if (imp.Evidence.Count > 3)
        {
            inlines.Add(Br());
            inlines.Add(R($"• …and {imp.Evidence.Count - 3} more (shown before you apply)"));
        }
        return Rich([.. inlines]);
    }

    /// <summary>Technical details: selectable, so paths and ids can be copied.</summary>
    private TextBox DetailsBox()
    {
        var lines = Finding.Details.Select(d => $"{d.Key}:  {d.Value}").Append($"Finding id: {Finding.Id}");
        var box = new TextBox
        {
            Text = string.Join(Environment.NewLine, lines),
            IsReadOnly = true,
            TextWrapping = TextWrapping.Wrap,
            BorderThickness = new Thickness(0),
            Background = System.Windows.Media.Brushes.Transparent,
            Padding = new Thickness(0),
            Style = null,
        };
        box.SetResourceReference(ForegroundProperty, TextSecondary);
        box.SetResourceReference(TextBox.CaretBrushProperty, TextPrimary);
        return box;
    }

    private static string FixText(FixOption opt) => opt.GuidanceOnly ? opt.Label : $"Fix: {opt.Label}";

    private FrameworkElement FixButton(List<FixOption> fixes)
    {
        var first = fixes[0];
        var primary = Finding.Severity >= Severity.Medium;
        var main = Button(FixText(first), () => FixRequested?.Invoke(Finding, first), primary);
        if (fixes.Count == 1)
        {
            return main;
        }
        // More than one way to fix: the main part applies the first, the arrow lists them all.
        var menu = new ContextMenu();
        foreach (var opt in fixes)
        {
            var item = new MenuItem { Header = FixText(opt) };
            item.Click += (_, _) => FixRequested?.Invoke(Finding, opt);
            menu.Items.Add(item);
        }
        var arrow = Button("▾", () => { }, primary);
        arrow.ToolTip = "Other ways to fix this";
        arrow.Padding = new Thickness(8, 4, 8, 4);
        arrow.Margin = new Thickness(2, 0, 0, 0);
        arrow.ContextMenu = menu;
        arrow.Click += (_, _) =>
        {
            menu.PlacementTarget = arrow;
            menu.Placement = System.Windows.Controls.Primitives.PlacementMode.Bottom;
            menu.IsOpen = true;
        };
        var pair = new StackPanel { Orientation = Orientation.Horizontal };
        pair.Children.Add(main);
        pair.Children.Add(arrow);
        return pair;
    }
}
