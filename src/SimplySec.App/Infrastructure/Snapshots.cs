using System.Windows;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Threading;
using SimplySec.App.Views;

namespace SimplySec.App.Infrastructure;

/// <summary>
/// Developer aid: render every page of the window to PNG files and exit
/// (<c>SimplySec.exe --load-raw FILE --snapshot DIR</c>), so the UI can be checked without
/// clicking through it.
/// </summary>
public static class Snapshots
{
    public static async Task TakeAsync(MainWindow window, string dir)
    {
        Directory.CreateDirectory(dir);
        var theme = Theme.Palette.IsDark ? "dark" : "light";
        var i = 0;
        foreach (var (name, _) in window.Pages)
        {
            window.Go(name);
            await Settle();
            Save(window, Path.Combine(dir, $"{++i}-{name.Replace(' ', '-').ToLowerInvariant()}-{theme}.png"));
        }

        // The dialogs of the fix flow, with the recommended fixes of this scan.
        var vm = window.Vm;
        if (vm.Result is { } result)
        {
            var (sels, _) = vm.Engine.RecommendedSplit(result);
            var exposure = result.Findings.FirstOrDefault(f => f.Check == "exposure" && f.Fixes.Count > 0);
            if (exposure is not null)
            {
                sels.Add(new Core.Engine.Selection(exposure.Fixes[0].FixId, exposure.Fixes[0].Params, exposure.Id));
            }
            var plan = vm.Engine.Plan(sels);
            var findings = result.Findings.GroupBy(f => f.Id).ToDictionary(g => g.Key, g => g.Last());
            await ShowAndSave(new Dialogs.PreviewDialog(new ViewModels.PreviewModel(plan, vm.IsAdmin, findings), window), Path.Combine(dir, $"8-preview-{theme}.png"));
            var lines = plan.Items.SelectMany(p => p.Specs).Select((s, n) => new ResultLine(s.Summary, n == 1 ? "failed" : "applied", n != 1, n == 1 ? "access denied" : "")).ToList();
            var resolved = plan.Items.Where(p => p.FindingId is not null).Select((p, n) => (p.FindingId!, n % 2 == 0)).ToDictionary(x => x.Item1, x => x.Item2);
            var summary = new ResultSummary(lines, resolved, findings.ToDictionary(kv => kv.Key, kv => kv.Value.Title), result.Score, result.Score - 4, ["Firewall backup failed: example warning."]);
            await ShowAndSave(new Dialogs.ResultDialog(summary, window), Path.Combine(dir, $"9-result-{theme}.png"));
        }
    }

    private static async Task ShowAndSave(Window dialog, string path)
    {
        dialog.Show();
        await Settle();
        Save(dialog, path);
        dialog.Close();
    }

    private static async Task Settle()
    {
        for (var n = 0; n < 4; n++)
        {
            await Dispatcher.Yield(DispatcherPriority.ApplicationIdle);
            await Task.Delay(150);
        }
    }

    public static void Save(FrameworkElement element, string path)
    {
        var dpi = VisualTreeHelper.GetDpi(element);
        var w = (int)Math.Ceiling(element.ActualWidth * dpi.DpiScaleX);
        var h = (int)Math.Ceiling(element.ActualHeight * dpi.DpiScaleY);
        var visual = new DrawingVisual();
        using (var dc = visual.RenderOpen())
        {
            // Mica is drawn by Windows behind the window, so paint the theme background first.
            var bg = element.TryFindResource("ApplicationBackgroundBrush") as Brush ?? Brushes.White;
            dc.DrawRectangle(bg, null, new Rect(0, 0, element.ActualWidth, element.ActualHeight));
            dc.DrawRectangle(new VisualBrush(element), null, new Rect(0, 0, element.ActualWidth, element.ActualHeight));
        }
        var bmp = new RenderTargetBitmap(w, h, dpi.PixelsPerInchX, dpi.PixelsPerInchY, PixelFormats.Pbgra32);
        bmp.Render(visual);
        var png = new PngBitmapEncoder();
        png.Frames.Add(BitmapFrame.Create(bmp));
        using var fs = File.Create(path);
        png.Save(fs);
    }
}
