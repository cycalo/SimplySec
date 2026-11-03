using System.Windows.Media;
using SimplySec.Core;
using SimplySec.Core.Model;
using Wpf.Ui.Appearance;

namespace SimplySec.App.Theme;

/// <summary>
/// Severity, grade and impact colours (Windows 11 palette). Chips keep white
/// text on the saturated colour in both themes; colours used as text get a lighter dark-mode
/// variant, so nothing hard-coded is unreadable on a dark background.
/// </summary>
public static class Palette
{
    public static bool IsDark => ApplicationThemeManager.GetAppTheme() == ApplicationTheme.Dark;

    private static readonly Dictionary<Severity, (string Light, string Dark)> SeverityColors = new()
    {
        [Severity.Critical] = ("#C42B1C", "#FF99A4"),
        [Severity.High] = ("#D83B01", "#FFB38A"),
        [Severity.Medium] = ("#B76E00", "#F7C35F"),
        [Severity.Low] = ("#0F6CBD", "#60CDFF"),
        [Severity.Info] = ("#6B6B6B", "#A6A6A6"),
    };

    private static readonly Dictionary<string, (string Light, string Dark)> GradeColors = new(StringComparer.Ordinal)
    {
        ["A"] = ("#0F7B0F", "#6CCB5F"),
        ["B"] = ("#4C9A2A", "#9BD67A"),
        ["C"] = ("#B76E00", "#F7C35F"),
        ["D"] = ("#D83B01", "#FFB38A"),
        ["E"] = ("#C42B1C", "#FF99A4"),
        ["F"] = ("#A4262C", "#FF7A85"),
    };

    public const string Good = "#0F7B0F";
    public const string Bad = "#C42B1C";
    public const string Amber = "#B76E00";
    public const string Grey = "#5D5D5D";
    public const string Blue = "#0F6CBD";

    private static readonly Dictionary<string, SolidColorBrush> Cache = new(StringComparer.Ordinal);

    public static SolidColorBrush Brush(string hex)
    {
        lock (Cache)
        {
            if (!Cache.TryGetValue(hex, out var b))
            {
                b = new SolidColorBrush((Color)ColorConverter.ConvertFromString(hex));
                b.Freeze();
                Cache[hex] = b;
            }
            return b;
        }
    }

    /// <summary>Background of a severity chip (white text).</summary>
    public static SolidColorBrush SeverityChip(Severity s) => Brush(SeverityColors[s].Light);

    /// <summary>A severity colour used as text on the page background.</summary>
    public static SolidColorBrush SeverityText(Severity s) => Brush(IsDark ? SeverityColors[s].Dark : SeverityColors[s].Light);

    public static SolidColorBrush GradeText(string grade) =>
        GradeColors.TryGetValue(grade, out var c) ? Brush(IsDark ? c.Dark : c.Light) : SeverityText(Severity.Low);

    /// <summary>Good/bad/amber as text, readable in both themes.</summary>
    public static SolidColorBrush GoodText => Brush(IsDark ? "#6CCB5F" : Good);
    public static SolidColorBrush BadText => Brush(IsDark ? "#FF99A4" : Bad);
    public static SolidColorBrush AmberText => Brush(IsDark ? "#F7C35F" : Amber);

    public static SolidColorBrush ImpactText(ImpactLevel level) => level switch
    {
        ImpactLevel.InUse => BadText,
        ImpactLevel.MayAffect => AmberText,
        ImpactLevel.NoneFound => GoodText,
        _ => SeverityText(Severity.Info),
    };
}
