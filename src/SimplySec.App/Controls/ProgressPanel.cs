using System.Diagnostics;
using System.Globalization;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Threading;
using SimplySec.App.Theme;
using SimplySec.Core.Engine;
using static SimplySec.App.Theme.Ui;

namespace SimplySec.App.Controls;

/// <summary>
/// What SimplySec is doing right now: steps done, current step, elapsed time (port of
/// widgets/progress_panel.py). Shown above every page while a scan, fix or undo runs.
/// </summary>
public sealed class ProgressPanel : UserControl
{
    /// <summary>A step with no news for this long gets a "still working" note.</summary>
    public static readonly TimeSpan Stall = TimeSpan.FromSeconds(150);

    private readonly TextBlock _title = Text("", TextStyle.CardTitle);
    private readonly TextBlock _clock = Text("", TextStyle.Dim, wrap: false);
    private readonly ProgressBar _bar = new() { Height = 6, Minimum = 0 };
    private readonly TextBlock _current = Text();
    private readonly TextBlock _doneList = Text("", TextStyle.Dim);
    private readonly TextBlock _warning = new() { TextWrapping = TextWrapping.Wrap };
    private readonly DispatcherTimer _timer = new() { Interval = TimeSpan.FromSeconds(1) };
    private readonly Stopwatch _started = new();
    private TimeSpan _lastUpdate;
    private int _total;
    private readonly List<string> _done = [];

    public ProgressPanel()
    {
        var top = new DockPanel();
        DockPanel.SetDock(_clock, Dock.Right);
        top.Children.Add(_clock);
        top.Children.Add(_title);
        var stack = VStack(4);
        stack.Children.Add(top);
        stack.Children.Add(_bar);
        stack.Children.Add(_current);
        stack.Children.Add(_doneList);
        stack.Children.Add(_warning);
        var card = Card(stack);
        card.Padding = new Thickness(16, 10, 16, 10);
        Content = card;
        _timer.Tick += (_, _) => Tick();
        Visibility = Visibility.Collapsed;
    }

    public string CurrentText => _current.Text;

    public void Start(string title, int totalSteps = 0)
    {
        _started.Restart();
        _lastUpdate = TimeSpan.Zero;
        _total = totalSteps;
        _done.Clear();
        _title.Text = title;
        _current.Text = "Starting…";
        _doneList.Text = "";
        _warning.Text = "";
        _bar.IsIndeterminate = totalSteps == 0;
        _bar.Maximum = Math.Max(1, totalSteps);
        _bar.Value = 0;
        Tick();
        _timer.Start();
        Visibility = Visibility.Visible;
    }

    public void UpdateText(string text)
    {
        if (Visibility != Visibility.Visible)
        {
            return;
        }
        _lastUpdate = _started.Elapsed;
        _warning.Text = "";
        if (Progress.IsDone(text))
        {
            _done.Add(text[Progress.Done.Length..]);
            if (_total > 0)
            {
                _bar.Value = Math.Min(_done.Count, _total);
            }
            _doneList.Text = string.Join("\n", _done.TakeLast(4).Select(t => $"✓ {t}"));
        }
        else
        {
            _current.Text = text;
        }
    }

    public void Finish()
    {
        _timer.Stop();
        Visibility = Visibility.Collapsed;
    }

    private void Tick()
    {
        var now = _started.Elapsed;
        var steps = _total > 0 ? $"step {Math.Min(_done.Count + 1, _total)} of {_total} · " : "";
        _clock.Text = string.Create(CultureInfo.InvariantCulture, $"{steps}{now.TotalSeconds:0} s elapsed");
        // Only say something when one step has shown no progress for a long time.
        if (now - _lastUpdate > Stall)
        {
            _warning.Foreground = Palette.AmberText;
            _warning.Text = "Still working on this step. It will finish on its own.";
        }
    }
}
