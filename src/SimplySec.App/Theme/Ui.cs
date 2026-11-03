using System.Windows;
using System.Windows.Controls;
using System.Windows.Documents;
using System.Windows.Media;
using WpfButton = Wpf.Ui.Controls.Button;

namespace SimplySec.App.Theme;

/// <summary>
/// Small builders for the page content (v2 built its pages in code with Qt rich-text labels).
/// Text is always added as Runs, never parsed as markup, so nothing in a finding can inject
/// formatting.
/// </summary>
public static class Ui
{
    public const string TextPrimary = "TextFillColorPrimaryBrush";
    public const string TextSecondary = "TextFillColorSecondaryBrush";
    public const string CardBackground = "CardBackgroundFillColorDefaultBrush";
    public const string CardStroke = "CardStrokeColorDefaultBrush";
    public const string Accent = "AccentTextFillColorPrimaryBrush";
    public const string SubtleFill = "SubtleFillColorSecondaryBrush";
    public const string Divider = "DividerStrokeColorDefaultBrush";

    public enum TextStyle
    {
        Body,
        Dim,
        PageTitle,
        SectionTitle,
        CardTitle,
    }

    public static TextBlock Text(string text = "", TextStyle style = TextStyle.Body, bool wrap = true)
    {
        var t = new TextBlock { Text = text, TextWrapping = wrap ? TextWrapping.Wrap : TextWrapping.NoWrap };
        Apply(t, style);
        return t;
    }

    public static TextBlock Rich(params Inline[] inlines) => Rich(TextStyle.Body, inlines);

    public static TextBlock Rich(TextStyle style, params Inline[] inlines)
    {
        var t = new TextBlock { TextWrapping = TextWrapping.Wrap };
        Apply(t, style);
        t.Inlines.AddRange(inlines);
        return t;
    }

    /// <summary>Body text size (WPF's default of 12 is what text built from Runs would get otherwise).</summary>
    public const double BodySize = 14;

    public static void Apply(TextBlock t, TextStyle style)
    {
        t.FontSize = BodySize;
        switch (style)
        {
            case TextStyle.Dim:
                t.SetResourceReference(TextBlock.ForegroundProperty, TextSecondary);
                break;
            case TextStyle.PageTitle:
                t.FontSize = 28;
                t.FontWeight = FontWeights.SemiBold;
                t.SetResourceReference(TextBlock.ForegroundProperty, TextPrimary);
                break;
            case TextStyle.SectionTitle:
                t.FontSize = 17;
                t.FontWeight = FontWeights.SemiBold;
                t.Margin = new Thickness(0, 6, 0, 0);
                t.SetResourceReference(TextBlock.ForegroundProperty, TextPrimary);
                break;
            case TextStyle.CardTitle:
                t.FontSize = 15;
                t.FontWeight = FontWeights.SemiBold;
                t.SetResourceReference(TextBlock.ForegroundProperty, TextPrimary);
                break;
            default:
                t.SetResourceReference(TextBlock.ForegroundProperty, TextPrimary);
                break;
        }
    }

    public static Run R(string text) => new(text) { FontSize = BodySize };

    public static Run B(string text) => new(text) { FontWeight = FontWeights.SemiBold, FontSize = BodySize };

    public static Run C(string text, Brush brush, bool bold = false) =>
        new(text) { Foreground = brush, FontWeight = bold ? FontWeights.SemiBold : FontWeights.Normal, FontSize = BodySize };

    public static LineBreak Br() => new();

    /// <summary>A rounded card (v2's #Card frame).</summary>
    public static Border Card(UIElement? child = null, double padding = 16) => Framed(child, new Thickness(1), new CornerRadius(8), padding);

    /// <summary>A highlighted note with an accent bar on the left (v2's #Banner).</summary>
    public static Border Banner(UIElement child)
    {
        var b = new Border
        {
            Child = child,
            BorderThickness = new Thickness(4, 1, 1, 1),
            CornerRadius = new CornerRadius(6),
            Padding = new Thickness(12, 8, 12, 8),
        };
        b.SetResourceReference(Border.BackgroundProperty, SubtleFill);
        b.SetResourceReference(Border.BorderBrushProperty, Accent);
        return b;
    }

    private static Border Framed(UIElement? child, Thickness thickness, CornerRadius radius, double padding)
    {
        var b = new Border { Child = child, BorderThickness = thickness, CornerRadius = radius, Padding = new Thickness(padding, padding * 0.75, padding, padding * 0.75) };
        b.SetResourceReference(Border.BackgroundProperty, CardBackground);
        b.SetResourceReference(Border.BorderBrushProperty, CardStroke);
        return b;
    }

    /// <summary>A coloured pill with white text (severity and status labels).</summary>
    public static Border Chip(string text, Brush background) => new()
    {
        Background = background,
        CornerRadius = new CornerRadius(4),
        Padding = new Thickness(6, 1, 6, 1),
        VerticalAlignment = VerticalAlignment.Top,
        Margin = new Thickness(0, 2, 8, 0),
        Child = new TextBlock { Text = text, Foreground = Brushes.White, FontWeight = FontWeights.SemiBold },
    };

    public static WpfButton Button(string text, Action click, bool primary = false)
    {
        var b = new WpfButton { Content = text, Appearance = primary ? Wpf.Ui.Controls.ControlAppearance.Primary : Wpf.Ui.Controls.ControlAppearance.Secondary };
        b.Click += (_, _) => click();
        return b;
    }

    /// <summary>A text-only button in the accent colour (v2's "Link" buttons).</summary>
    public static WpfButton Link(string text, Action click)
    {
        var b = new WpfButton { Content = text, Appearance = Wpf.Ui.Controls.ControlAppearance.Transparent, Padding = new Thickness(4, 2, 4, 2) };
        b.SetResourceReference(Control.ForegroundProperty, Accent);
        b.Click += (_, _) => click();
        return b;
    }

    /// <summary>A vertical stack whose children are separated by <paramref name="spacing"/>.</summary>
    public static StackPanel VStack(double spacing = 12) => new SpacedStack(spacing, Orientation.Vertical);

    public static StackPanel HStack(double spacing = 8) => new SpacedStack(spacing, Orientation.Horizontal);

    /// <summary>Remove everything from a panel (v2's Page.clear).</summary>
    public static void Clear(Panel panel) => panel.Children.Clear();
}

/// <summary>StackPanel with a gap between children (WPF's StackPanel has no Spacing).</summary>
public sealed class SpacedStack : StackPanel
{
    private readonly double _spacing;
    private readonly System.Runtime.CompilerServices.ConditionalWeakTable<FrameworkElement, object> _own = [];

    public SpacedStack(double spacing, Orientation orientation)
    {
        _spacing = spacing;
        Orientation = orientation;
    }

    protected override void OnVisualChildrenChanged(DependencyObject? visualAdded, DependencyObject? visualRemoved)
    {
        base.OnVisualChildrenChanged(visualAdded, visualRemoved);
        for (var i = 0; i < Children.Count; i++)
        {
            if (Children[i] is not FrameworkElement fe)
            {
                continue;
            }
            var m = (Thickness)_own.GetValue(fe, f => f.Margin);
            var gap = i == 0 ? 0 : _spacing;
            fe.Margin = Orientation == Orientation.Vertical
                ? new Thickness(m.Left, m.Top + gap, m.Right, m.Bottom)
                : new Thickness(m.Left + gap, m.Top, m.Right, m.Bottom);
        }
    }
}
