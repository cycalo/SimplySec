using System.Globalization;
using System.Windows;
using System.Windows.Media;
using SimplySec.App.Theme;
using Wpf.Ui.Appearance;

namespace SimplySec.App.Controls;

/// <summary>Base for the drawn controls: theme brushes, text, and a redraw when the theme changes.</summary>
public abstract class DrawnControl : FrameworkElement
{
    protected DrawnControl()
    {
        Loaded += (_, _) => ApplicationThemeManager.Changed += OnTheme;
        Unloaded += (_, _) => ApplicationThemeManager.Changed -= OnTheme;
    }

    private void OnTheme(ApplicationTheme theme, Color accent) => InvalidateVisual();

    protected Brush Res(string key, string fallback) => TryFindResource(key) as Brush ?? Palette.Brush(fallback);

    protected Brush TextBrush => Res(Ui.TextPrimary, "#1B1B1B");
    protected Brush DimBrush => Res(Ui.TextSecondary, "#5D5D5D");
    protected Brush LineBrush => Res(Ui.Divider, "#E5E5E5");
    protected Brush AccentBrush => Res(Ui.Accent, "#0067C0");

    protected FormattedText Format(string text, double size, Brush brush, FontWeight weight) =>
        new(text, CultureInfo.InvariantCulture, FlowDirection.LeftToRight,
            new Typeface(new FontFamily("Segoe UI Variable Text, Segoe UI"), FontStyles.Normal, weight, FontStretches.Normal),
            size, brush, VisualTreeHelper.GetDpi(this).PixelsPerDip);
}

/// <summary>Score ring with the grade in the middle.</summary>
public sealed class ScoreRing : DrawnControl
{
    public int? Score { get; private set; }
    public string Grade { get; private set; } = "?";

    public ScoreRing()
    {
        Width = 170;
        Height = 170;
    }

    public void SetScore(int? score, string grade)
    {
        (Score, Grade) = (score, grade);
        InvalidateVisual();
    }

    protected override void OnRender(DrawingContext dc)
    {
        var side = Math.Min(ActualWidth, ActualHeight) - 16;
        if (side <= 0)
        {
            return;
        }
        var center = new Point(ActualWidth / 2, ActualHeight / 2);
        var radius = side / 2;
        var track = new Pen(LineBrush, 12) { StartLineCap = PenLineCap.Round, EndLineCap = PenLineCap.Round };
        dc.DrawEllipse(null, track, center, radius, radius);
        if (Score is { } score && score > 0)
        {
            var pen = new Pen(Palette.GradeText(Grade), 12) { StartLineCap = PenLineCap.Round, EndLineCap = PenLineCap.Round };
            if (score >= 100)
            {
                dc.DrawEllipse(null, pen, center, radius, radius);
            }
            else
            {
                // Clockwise from 12 o'clock, like v2's drawArc(90°, -span).
                var angle = 2 * Math.PI * score / 100;
                var start = new Point(center.X, center.Y - radius);
                var end = new Point(center.X + radius * Math.Sin(angle), center.Y - radius * Math.Cos(angle));
                var geo = new StreamGeometry();
                using (var ctx = geo.Open())
                {
                    ctx.BeginFigure(start, false, false);
                    ctx.ArcTo(end, new Size(radius, radius), 0, score > 50, SweepDirection.Clockwise, true, false);
                }
                geo.Freeze();
                dc.DrawGeometry(null, pen, geo);
            }
        }
        var big = Format(Score is null ? "–" : Grade, 40, TextBrush, FontWeights.SemiBold);
        dc.DrawText(big, new Point(center.X - big.Width / 2, center.Y - side * 0.32 + (side * 0.45 - big.Height) / 2));
        var small = Format(Score is { } s ? $"risk {s}/100" : "not scanned", 14.5, DimBrush, FontWeights.Normal);
        dc.DrawText(small, new Point(center.X - small.Width / 2, center.Y + side * 0.08 + (side * 0.2 - small.Height) / 2));
    }
}

/// <summary>Risk-score-over-time line chart.</summary>
public sealed class TrendChart : DrawnControl
{
    public List<(string Label, int Score)> Points { get; private set; } = [];

    public TrendChart()
    {
        MinHeight = 180;
        Height = 200;
    }

    public void SetPoints(List<(string Label, int Score)> points)
    {
        Points = points;
        InvalidateVisual();
    }

    protected override void OnRender(DrawingContext dc)
    {
        const double left = 40, top = 12, right = 12, bottom = 26;
        var area = new Rect(left, top, Math.Max(0, ActualWidth - left - right), Math.Max(0, ActualHeight - top - bottom));
        dc.DrawRectangle(Brushes.Transparent, null, new Rect(0, 0, ActualWidth, ActualHeight));
        var grid = new Pen(LineBrush, 1);
        foreach (var score in new[] { 0, 25, 50, 75, 100 })
        {
            var y = area.Bottom - area.Height * score / 100;
            dc.DrawLine(grid, new Point(area.Left, y), new Point(area.Right, y));
            var label = Format(score.ToString(CultureInfo.InvariantCulture), 12, DimBrush, FontWeights.Normal);
            dc.DrawText(label, new Point(left - 6 - label.Width, y - label.Height / 2));
        }
        if (Points.Count == 0)
        {
            var none = Format("No scans yet", 13, DimBrush, FontWeights.Normal);
            dc.DrawText(none, new Point(area.Left + (area.Width - none.Width) / 2, area.Top + (area.Height - none.Height) / 2));
            return;
        }
        var n = Points.Count;
        Point Pt(int i, int score) => new(
            area.Left + (n > 1 ? area.Width * i / (n - 1) : area.Width / 2),
            area.Bottom - area.Height * score / 100);
        var geo = new StreamGeometry();
        using (var ctx = geo.Open())
        {
            ctx.BeginFigure(Pt(0, Points[0].Score), false, false);
            for (var i = 1; i < n; i++)
            {
                ctx.LineTo(Pt(i, Points[i].Score), true, true);
            }
        }
        geo.Freeze();
        dc.DrawGeometry(null, new Pen(AccentBrush, 2.5) { LineJoin = PenLineJoin.Round }, geo);
        for (var i = 0; i < n; i++)
        {
            dc.DrawEllipse(AccentBrush, null, Pt(i, Points[i].Score), 3.5, 3.5);
        }
        foreach (var i in new SortedSet<int> { 0, n - 1 })
        {
            var text = Format(Points[i].Label, 12, DimBrush, FontWeights.Normal);
            var x = Pt(i, 0).X;
            var atEnd = i == n - 1 && n > 1;
            dc.DrawText(text, new Point(atEnd ? x - text.Width : x, area.Bottom + 4 + (18 - text.Height) / 2));
        }
    }
}
