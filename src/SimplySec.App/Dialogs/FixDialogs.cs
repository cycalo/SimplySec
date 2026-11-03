using System.Windows;
using System.Windows.Controls;
using System.Windows.Documents;
using SimplySec.App.Infrastructure;
using SimplySec.App.Theme;
using SimplySec.App.ViewModels;
using SimplySec.Core;
using SimplySec.Core.Compat;
using static SimplySec.App.Theme.Ui;

namespace SimplySec.App.Dialogs;

/// <summary>
/// Lists each fix with why it's suggested, exactly what changes, what uses it now and what might
/// stop working (port of PreviewDialog). Each fix has its own tick box; fixes in use right now
/// start unticked.
/// </summary>
public sealed class PreviewDialog : DialogWindow
{
    private readonly PreviewModel _model;
    private readonly Wpf.Ui.Controls.Button _apply;
    private bool _accepted;

    public PreviewDialog(PreviewModel model, Window? owner = null) : base("Review changes", 720, owner, maxBodyHeight: 520)
    {
        _model = model;
        Body.Children.Add(Text("Review each change. Untick anything you want to keep as it is.", TextStyle.SectionTitle));
        foreach (var item in model.Items)
        {
            Body.Children.Add(ItemCard(item));
        }
        foreach (var r in model.Plan.Refused)
        {
            Body.Children.Add(Text($"Not included: {r}", TextStyle.Dim));
        }

        var restore = new CheckBox { Content = "Also create a System Restore point first (takes a minute)" };
        restore.Checked += (_, _) => model.RestorePoint = true;
        restore.Unchecked += (_, _) => model.RestorePoint = false;
        Footer.Children.Add(restore);
        Footer.Children.Add(Text(model.Note, TextStyle.Dim));

        _apply = AddButton(model.ApplyText, () =>
        {
            _accepted = true;
            Done(true);
        }, primary: true);
        AddButton("Cancel", () => Done(false));
        UpdateApply();
    }

    public PreviewChoice Choice() => _model.Choice(_accepted);

    private void UpdateApply()
    {
        _apply.Content = _model.ApplyText;
        _apply.IsEnabled = _model.IncludedCount > 0;
    }

    private Border ItemCard(PreviewModel.Item item)
    {
        var cl = VStack(6);
        var box = new CheckBox
        {
            Content = new TextBlock { Text = item.Fix.Fix.Label, FontWeight = FontWeights.SemiBold, FontSize = 15, TextWrapping = TextWrapping.Wrap },
            IsChecked = item.Included,
        };
        box.Checked += (_, _) =>
        {
            item.Included = true;
            UpdateApply();
        };
        box.Unchecked += (_, _) =>
        {
            item.Included = false;
            UpdateApply();
        };
        cl.Children.Add(box);
        if (item.Finding is { } f)
        {
            cl.Children.Add(Rich(B("Why: "), R($"{f.Title}. {f.WhatItMeans}")));
        }
        var changes = new List<Inline> { B("What changes: "), R(item.Fix.Fix.Description) };
        foreach (var s in item.Fix.Specs)
        {
            changes.Add(Br());
            changes.Add(R($"  •  {s.Summary}"));
        }
        cl.Children.Add(Rich([.. changes]));
        if (item.Fix.Impact is { } impact)
        {
            cl.Children.Add(Banner(ImpactBlock(impact)));
        }
        if (item.Fix.Fix.MightBreak.Length > 0)
        {
            cl.Children.Add(Rich(B("Might stop working: "), R(item.Fix.Fix.MightBreak)));
        }
        foreach (var w in item.Fix.Warnings)
        {
            cl.Children.Add(Banner(Rich(B("Heads-up: "), R(w.Text))));
        }
        foreach (var offer in item.Offers)
        {
            var o = new CheckBox { Content = new TextBlock { Text = offer.Label, TextWrapping = TextWrapping.Wrap }, IsChecked = false };
            o.Checked += (_, _) => offer.Ticked = true;
            o.Unchecked += (_, _) => offer.Ticked = false;
            cl.Children.Add(o);
        }
        if (item.InUse)
        {
            cl.Children.Add(Text("Left unticked because something is using it right now. Tick it only if you're sure.", TextStyle.Dim));
        }
        var card = Card(cl, 12);
        return card;
    }

    /// <summary>"What uses this" with up to <paramref name="limit"/> pieces of evidence.</summary>
    public static TextBlock ImpactBlock(Impact impact, int limit = 8)
    {
        var inlines = new List<Inline>
        {
            B("What uses this: "),
            C(Impact.Label(impact.Level), Palette.ImpactText(impact.Level), bold: true),
            Br(),
            R(impact.Headline),
        };
        foreach (var e in impact.Evidence.Take(limit))
        {
            inlines.Add(Br());
            inlines.Add(R($"  •  {e}"));
        }
        if (impact.Evidence.Count > limit)
        {
            inlines.Add(Br());
            inlines.Add(R($"  •  …and {impact.Evidence.Count - limit} more"));
        }
        return Rich([.. inlines]);
    }
}

/// <summary>Each change Verified or not, findings resolved or still present, the new score (port of ResultDialog).</summary>
public sealed class ResultDialog : DialogWindow
{
    public ResultDialog(ResultSummary s, Window? owner = null) : base("Changes applied", 620, owner)
    {
        Body.Children.Add(Text("Each change was checked again after applying it:", TextStyle.SectionTitle));
        foreach (var line in s.Lines)
        {
            string mark;
            bool good;
            if (line.Status == "applied" && line.Verified == true)
            {
                (mark, good) = ("Verified ✓", true);
            }
            else if (line.Status == "applied")
            {
                (mark, good) = ("Not verified ✗", false);
            }
            else
            {
                (mark, good) = ($"{PyStr.Title(line.Status)} ✗", false);
            }
            var color = good ? Palette.GoodText : Palette.BadText;
            var inlines = new List<Inline> { C(mark, color, bold: true), R($"   {line.Summary}") };
            if (line.Error.Length > 0)
            {
                inlines.Add(Br());
                inlines.Add(C(line.Error, color));
            }
            Body.Children.Add(Rich([.. inlines]));
        }
        if (s.Resolved.Count > 0)
        {
            Body.Children.Add(Text("Fresh scan", TextStyle.SectionTitle));
            foreach (var (fid, ok) in s.Resolved)
            {
                Body.Children.Add(Rich(
                    ok ? C("Resolved ✓", Palette.GoodText) : C("Still present ✗", Palette.BadText),
                    R($"   {s.Titles.GetValueOrDefault(fid, fid)}")));
            }
        }
        if (s.ScoreBefore is { } before && s.ScoreAfter is { } after)
        {
            Body.Children.Add(Text($"Risk score: {before} → {after}"));
        }
        foreach (var w in s.Warnings)
        {
            Body.Children.Add(Text($"Note: {w}", TextStyle.Dim));
        }
        Body.Children.Add(Text("You can undo any of this on the Changes page.", TextStyle.Dim));
        AddButton("OK", () => Done(true), primary: true);
    }
}
